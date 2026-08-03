//! The TPM as seen by a transport.
//!
//! `Tpm` owns the state and serialises command execution. Part 1 clause 12
//! describes the command header, the response header and the order in which a
//! command is validated, and that order is reproduced here.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::logging::Logger;
use crate::server::Device;
use crate::tpm::config;
use crate::tpm::constants::{rc, st};
use crate::tpm::core::state::TpmState;
use crate::tpm::error::TpmRc;
use crate::tpm::marshal::Writer;
use crate::tpm::persist::StateStore;

/// The fixed part of every command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHeader {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

/// Length of a command or response header in octets.
pub const HEADER_SIZE: usize = 10;

/// Parse and check the command header.
///
/// Part 3 clause 5.2 fixes the order: the tag is unmarshalled and validated
/// first, then `commandSize` is checked against the octets actually received,
/// and only then is the command code read. The tag is therefore checked as
/// soon as two octets are available, before any judgement about the size.
pub fn parse_header(buf: &[u8]) -> Result<CommandHeader, TpmRc> {
    if buf.len() < 2 {
        return Err(TpmRc(rc::COMMAND_SIZE));
    }
    let tag = u16::from_be_bytes([buf[0], buf[1]]);
    if tag != st::NO_SESSIONS && tag != st::SESSIONS {
        return Err(TpmRc(rc::TAG));
    }
    if buf.len() < HEADER_SIZE {
        return Err(TpmRc(rc::COMMAND_SIZE));
    }
    let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    if size as usize != buf.len() {
        return Err(TpmRc(rc::COMMAND_SIZE));
    }
    if size > config::MAX_COMMAND_SIZE {
        return Err(TpmRc(rc::COMMAND_SIZE));
    }
    let code = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
    Ok(CommandHeader { tag, size, code })
}

/// Build the ten octet response used for every failure.
///
/// Part 2 clause 6.6 requires a failure to carry TPM_ST_NO_SESSIONS, a size of
/// ten and the response code. The TPM 1.2 compatible TPM_TAG_RSP_COMMAND form
/// is only for a TPM that implements 1.2 compatibility, which this one does
/// not, so an unrecognised tag is reported as TPM_RC_TAG.
pub fn error_response(code: TpmRc) -> Vec<u8> {
    let mut w = Writer::with_capacity(HEADER_SIZE);
    w.u16(st::NO_SESSIONS);
    w.u32(HEADER_SIZE as u32);
    w.u32(code.value());
    w.into_vec()
}

/// Build a success response from an already marshalled body.
pub fn success_response(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(HEADER_SIZE + body.len());
    w.u16(tag);
    w.u32((HEADER_SIZE + body.len()) as u32);
    w.u32(rc::SUCCESS);
    w.bytes(body);
    w.into_vec()
}

/// A software TPM.
pub struct Tpm {
    state: Mutex<TpmState>,
    powered: AtomicBool,
    cancel: AtomicBool,
    /// The platform establishment flag, set by _TPM_Hash_Start.
    ///
    /// It is kept here rather than in the state file because it belongs to the
    /// register interface a platform presents, not to the TPM state the Library
    /// specification defines. Part 1 clause 31 defines the H-CRTM sequence but
    /// not this flag; the document that fixes how long it survives is the PC
    /// Client Platform TPM Profile, which is not among the references. It
    /// therefore lasts as long as the process does and no claim is made that it
    /// survives a restart.
    established: AtomicBool,
    store: StateStore,
    logger: Arc<Logger>,
}

impl Tpm {
    /// Create a TPM whose non-volatile state lives in `state_dir`.
    ///
    /// A state file that is already there is loaded; otherwise the TPM is
    /// manufactured and the new state is written.
    pub fn new(state_dir: impl AsRef<Path>, logger: Arc<Logger>) -> io::Result<Tpm> {
        // The pre-operational self tests of FIPS 140-3 clause 10.3 run before
        // anything else. Manufacturing a TPM generates seeds and writes a state
        // file, and loading one logs a line; clause 10.3 requires the tests to
        // pass before the module puts anything out. A failure here is fatal
        // rather than a TPM in failure mode, because there is no TPM yet to be
        // in that mode and nothing has been written.
        let integrity = crate::tpm::fips::integrity()
            .map_err(|e| io::Error::other(format!("integrity test failed: {}", e.0)))?;
        crate::tpm::fips::known_answer_tests()
            .map_err(|e| io::Error::other(format!("self test failed: {}", e.0)))?;

        let store = StateStore::new(state_dir)?;
        let state = match store.load()? {
            Some(data) => match TpmState::load(&data) {
                Ok(s) => {
                    logger.line("loaded saved state");
                    s
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("state file is not usable: {e}"),
                    ))
                }
            },
            None => {
                let s = TpmState::manufacture()
                    .map_err(|e| io::Error::other(format!("cannot manufacture: {e}")))?;
                logger.line("manufactured a new TPM");
                let bytes = s
                    .save()
                    .map_err(|e| io::Error::other(format!("cannot save state: {e}")))?;
                store.save(&bytes)?;
                s
            }
        };

        let mut state = state;
        // The digest the integrity test produced is what TPM2_GetTestResult
        // reports, so it is kept rather than recomputed.
        state.test_digest = integrity;
        state.self_test_done = true;
        state.test_failure = None;

        Ok(Tpm {
            state: Mutex::new(state),
            powered: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            established: AtomicBool::new(false),
            store,
            logger,
        })
    }

    /// The store backing the non-volatile state.
    pub fn store(&self) -> &StateStore {
        &self.store
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, TpmState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Read the state while no command is running.
    ///
    /// The debug console needs to look at values the command interface does
    /// not report, so it borrows the state the same way a command does.
    pub fn with_state<T>(&self, f: impl FnOnce(&TpmState) -> T) -> T {
        f(&self.locked())
    }

    /// Change the state while no command is running.
    pub fn with_state_mut<T>(&self, f: impl FnOnce(&mut TpmState) -> T) -> T {
        f(&mut self.locked())
    }

    /// Write the non-volatile state out.
    pub fn persist(&self) {
        let state = self.locked();
        match state.save() {
            Ok(bytes) => {
                if let Err(e) = self.store.save(&bytes) {
                    self.logger.line(&format!("cannot write state: {e}"));
                }
            }
            Err(e) => self.logger.line(&format!("cannot marshal state: {e}")),
        }
    }

    /// True when the command changes anything that must reach the state file.
    fn writes_nv(code: u32) -> bool {
        crate::tpm::commands::table::lookup(code)
            .map(|i| i.nv)
            .unwrap_or(false)
    }
}

impl Device for Tpm {
    fn execute(&self, locality: u8, command: &[u8]) -> Vec<u8> {
        if !self.powered.load(Ordering::SeqCst) {
            return error_response(TpmRc(rc::INITIALIZE));
        }
        let code = parse_header(command).map(|h| h.code).ok();
        let response = {
            let mut state = self.locked();
            crate::tpm::commands::execute::run(&mut state, locality, command)
        };
        // A command that touches non-volatile state is followed by a write so
        // the state file matches what the TPM reports.
        if let Some(code) = code {
            if Tpm::writes_nv(code) {
                self.persist();
            }
        }
        response
    }

    fn power_on(&self) {
        self.powered.store(true, Ordering::SeqCst);
        {
            let mut state = self.locked();
            state.started = false;
            state.objects.clear();
            state.sessions.clear();
            state.physical_presence = false;
            state.failure_mode = false;
            state.clock.time = 0;

            // The pre-operational self tests of FIPS 140-3 clause 10.3, which
            // FIPS 140-2 calls the power-up tests, run here. Power has just
            // been applied and no command has been accepted, so nothing has
            // been output yet. A failure leaves the TPM in failure mode, where
            // Part 1 clause 12.3 allows only the few commands that report it.
            match crate::tpm::commands::management::run_self_tests(&mut state) {
                Ok(()) => self.logger.line("self tests passed"),
                Err(_) => {
                    let which = state.test_failure.clone().unwrap_or_default();
                    self.logger
                        .line(&format!("self test failed: {which}, entering failure mode"));
                }
            }
        }
        self.logger.line("_TPM_Init");
    }

    fn power_off(&self) {
        self.persist();
        self.powered.store(false, Ordering::SeqCst);
        {
            let mut state = self.locked();
            state.started = false;
            state.objects.clear();
            state.sessions.clear();
        }
        self.logger.line("power off");
    }

    fn is_powered_on(&self) -> bool {
        self.powered.load(Ordering::SeqCst)
    }

    fn nv_on(&self) {
        self.locked().nv_available = true;
    }

    fn nv_off(&self) {
        self.locked().nv_available = false;
    }

    fn physical_presence(&self, asserted: bool) {
        self.locked().physical_presence = asserted;
    }

    fn cancel(&self, asserted: bool) {
        self.cancel.store(asserted, Ordering::SeqCst);
    }

    /// _TPM_Hash_Start begins an H-CRTM event sequence, Part 1 clause 31, and
    /// records that one has begun.
    fn hash_start(&self) {
        self.established.store(true, Ordering::SeqCst);
        let mut state = self.locked();
        state.hcrtm_buffer = Some(Vec::new());
    }

    fn hash_data(&self, data: &[u8]) {
        let mut state = self.locked();
        if let Some(buf) = state.hcrtm_buffer.as_mut() {
            if buf.len().saturating_add(data.len()) <= crate::tpm::config::MAX_BUFFER_SIZE {
                buf.extend_from_slice(data);
            }
        }
    }

    /// _TPM_Hash_End records the H-CRTM measurement in PCR 17 through 22.
    fn hash_end(&self) {
        let mut state = self.locked();
        let Some(buf) = state.hcrtm_buffer.take() else {
            return;
        };
        // The D-RTM registers are set to zero before the event is recorded.
        for index in 17..=22u16 {
            let _ = state.pcr.reset(index, 4);
        }
        let algorithms = state.pcr.algorithms();
        for a in algorithms {
            let Ok(digest) = crate::tpm::crypto::hash::digest(a, &buf) else {
                continue;
            };
            let _ = state
                .pcr
                .extend(crate::tpm::config::HCRTM_PCR, 4, &[(a, digest)]);
        }
    }

    fn established(&self) -> bool {
        self.established.load(Ordering::SeqCst)
    }

    fn reset_established(&self, _locality: u8) {
        self.established.store(false, Ordering::SeqCst);
    }

    fn act_get_signaled(&self, _act: u32) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_parsed() {
        let cmd = [
            0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let h = parse_header(&cmd).unwrap();
        assert_eq!(h.tag, st::NO_SESSIONS);
        assert_eq!(h.size, 12);
        assert_eq!(h.code, 0x0000_0144);
    }

    #[test]
    fn unrecognised_tag_is_rejected_with_tpm_rc_tag() {
        // TPM_TAG_RQU_COMMAND from TPM 1.2 is not a TPM 2.0 command tag.
        let cmd = [
            0x00u8, 0xc1, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x44,
        ];
        assert_eq!(parse_header(&cmd).unwrap_err(), TpmRc(rc::TAG));
        // TPM_ST_NULL is not a command tag either.
        let cmd = [
            0x80u8, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x44,
        ];
        assert_eq!(parse_header(&cmd).unwrap_err(), TpmRc(rc::TAG));
    }

    #[test]
    fn the_tag_is_checked_before_the_size() {
        // A truncated buffer that already carries a bad tag reports the tag,
        // matching the validation order of Part 3 clause 5.2.
        assert_eq!(parse_header(&[0x00, 0xc1]).unwrap_err(), TpmRc(rc::TAG));
        assert_eq!(
            parse_header(&[0x00, 0xc1, 0x00, 0x00]).unwrap_err(),
            TpmRc(rc::TAG)
        );
        // A good tag with too few octets is a size problem.
        assert_eq!(
            parse_header(&[0x80, 0x01, 0x00, 0x00]).unwrap_err(),
            TpmRc(rc::COMMAND_SIZE)
        );
        // Fewer than two octets cannot carry a tag at all.
        assert_eq!(parse_header(&[0x80]).unwrap_err(), TpmRc(rc::COMMAND_SIZE));
        assert_eq!(parse_header(&[]).unwrap_err(), TpmRc(rc::COMMAND_SIZE));
    }

    #[test]
    fn size_must_match_the_buffer() {
        let cmd = [
            0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x44,
        ];
        assert_eq!(parse_header(&cmd).unwrap_err(), TpmRc(rc::COMMAND_SIZE));
    }

    #[test]
    fn size_above_the_maximum_is_rejected() {
        let mut cmd = vec![0x80u8, 0x01];
        cmd.extend_from_slice(&(config::MAX_COMMAND_SIZE + 1).to_be_bytes());
        cmd.extend_from_slice(&[0x00, 0x00, 0x01, 0x44]);
        cmd.resize((config::MAX_COMMAND_SIZE + 1) as usize, 0);
        assert_eq!(parse_header(&cmd).unwrap_err(), TpmRc(rc::COMMAND_SIZE));
    }

    #[test]
    fn error_response_shape() {
        let r = error_response(TpmRc(rc::INITIALIZE));
        assert_eq!(
            r,
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00]
        );
        // Every failure, including a bad tag, uses TPM_ST_NO_SESSIONS.
        let r = error_response(TpmRc(rc::TAG));
        assert_eq!(&r[0..2], &st::NO_SESSIONS.to_be_bytes());
        assert_eq!(&r[6..10], &rc::TAG.to_be_bytes());
    }

    #[test]
    fn success_response_shape() {
        let r = success_response(st::NO_SESSIONS, &[0xaa, 0xbb]);
        assert_eq!(
            r,
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb]
        );
    }
}
