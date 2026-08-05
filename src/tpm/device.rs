//! The TPM as seen by a transport.
//!
//! `Tpm` owns the state and serialises command execution. Part 1 clause 12
//! describes the command header, the response header and the order in which a
//! command is validated, and that order is reproduced here.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
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
        // Part 3 clause 5.2 item 1 names TPM_RC_BAD_TAG here, and clause 6.1
        // says which of the two answers a TPM gives: "If the tag of the command
        // is not a recognized command tag, the TPM error response will differ
        // depending on TPM 1.2 compatibility. If the TPM supports 1.2
        // compatibility, the TPM shall return a tag of TPM_TAG_RSP_COMMAND and
        // an appropriate TPM 1.2 response code (TPM_BADTAG = 00 00 00 1E). If
        // the TPM does not have compatibility with TPM 1.2, the TPM shall
        // return TPM_ST_NO_SESSION and a response code of TPM_RC_TAG." Part 2
        // clause 6.6.1 says the same. This TPM has no 1.2 compatibility, and
        // firmware that sends a 1.2 command to tell the families apart takes
        // the 1.2 shaped answer to mean a 1.2 TPM is there.
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
/// Part 2 clause 6.6.1 requires a failure to carry TPM_ST_NO_SESSIONS, a size
/// of ten and the response code. The TPM_TAG_RSP_COMMAND form beside it is for
/// a TPM that has TPM 1.2 compatibility, which this one does not, so an
/// unrecognised command tag is answered like any other failure.
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
    /// When the TPM last advanced its own time.
    ///
    /// Part 1 clause 33 advances Clock and Time while the TPM is powered.
    /// Nothing runs inside a software TPM between commands, so the time that
    /// passed is worked out when the next command arrives.
    ///
    /// The reference is monotonic rather than the wall clock, because clause
    /// 33.1 calls Time "a free-running hardware value that is not under
    /// software control" and a wall clock can be moved either way by anything
    /// on the host.
    last_tick: Mutex<Instant>,
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
        // The value the test compares against lives beside the state, which is
        // the only place this module is given to keep anything.
        let expected_at = state_dir.as_ref().join("integrity.hex");
        if let Some(parent) = expected_at.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let integrity = crate::tpm::fips::integrity_test(&expected_at)
            .map_err(|e| io::Error::other(format!("integrity test failed: {}", e.0)))?;
        match &integrity {
            crate::tpm::fips::Integrity::Passed(_) => {
                logger.line("software integrity test passed")
            }
            // FIPS 140-3 clause 10.3.1 has the module decide, which it cannot
            // do without a value to compare against. Saying so is the honest
            // report; recording the code now would only bless whatever this
            // image already is.
            crate::tpm::fips::Integrity::NotPerformed(_) => logger.line(
                "software integrity test not performed: no recorded value beside the state",
            ),
        }
        let integrity = integrity.code().to_vec();
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
        // reports, so it is kept rather than recomputed. A TPM2_SelfTest that
        // runs it again compares against the same file this one did.
        state.integrity_file = Some(expected_at);
        state.test_digest = integrity;
        state.self_test_done = true;
        state.test_failure = None;

        Ok(Tpm {
            state: Mutex::new(state),
            powered: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            last_tick: Mutex::new(Instant::now()),
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

    /// Milliseconds of powered time since this was last asked.
    ///
    /// Part 1 clause 40.2 counts an ACT down "each second that the TPM is
    /// powered", and clause 33 advances Clock and Time on the same terms, so a
    /// TPM with no power is given no time at all.
    fn elapsed(&self) -> u64 {
        if !self.powered.load(Ordering::SeqCst) {
            return 0;
        }
        let now = Instant::now();
        let mut last = match self.last_tick.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let delta = now.saturating_duration_since(*last);
        *last = now;
        u64::try_from(delta.as_millis()).unwrap_or(u64::MAX)
    }

    /// Start counting powered time again from now.
    ///
    /// Applying power begins a new powered period, and the interval before it
    /// belongs to no period at all.
    fn restart_tick(&self) {
        let mut last = match self.last_tick.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *last = Instant::now();
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
        let elapsed = self.elapsed();
        let (response, clock_rolled_over) = {
            let mut state = self.locked();
            // Part 1 clause 31.1: "During an H-CRTM sequence, if any indication
            // other the _TPM_Hash_Data occurs between the _TPM_Hash_Start and
            // _TPM_Hash_End indications (including receipt of a command), then
            // the H-CRTM Event Sequence is abandoned, the H-CRTM Event Sequence
            // context is flushed, and no change to any PCR occurs." Dropping
            // the buffer here is what makes the _TPM_Hash_End that may still
            // arrive measure nothing.
            state.hcrtm_sequence = None;
            // The time that passed since the last command is credited before
            // the command runs, so a command that reports the clock or reads
            // the countdown timer sees the value it should.
            let rolled = state.advance_time(elapsed);
            (
                crate::tpm::commands::execute::run(&mut state, locality, command),
                rolled,
            )
        };
        // A command that touches non-volatile state is followed by a write so
        // the state file matches what the TPM reports. So is a rollover of the
        // clock, which is the moment Part 2 clause 10.10.2 asks for the copy in
        // NV to be brought up to date.
        let writes_nv = code.map(Tpm::writes_nv).unwrap_or(false);
        if writes_nv || clock_rolled_over {
            self.persist();
        }
        response
    }

    fn power_on(&self) {
        // The powered period starts here, so whatever passed while the TPM had
        // no power is not credited to Clock, Time or the countdown timer.
        self.restart_tick();
        self.powered.store(true, Ordering::SeqCst);
        {
            let mut state = self.locked();
            state.started = false;
            // _TPM_Init is where a stored PCR allocation takes effect, before
            // an H-CRTM sequence could measure into a bank.
            if let Err(e) = state.on_init() {
                self.logger.line(&format!("cannot allocate the PCR: {}", e.0));
            }
            state.objects.clear();
            // Only what was in TPM memory goes away with the power. Part 1
            // clause 27.5 keeps a saved session context across a TPM Restart
            // and a TPM Resume, both of which pass through here, and it is the
            // startup type that decides whether this was one of those or a TPM
            // Reset.
            state.sessions.flush_loaded();
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
            // The record of which sessions have saved contexts is written to
            // the state file above and kept here, because Part 1 clause 27.5
            // lets those contexts be reloaded after the power comes back if
            // the startup that follows is a TPM Restart or a TPM Resume.
            state.sessions.flush_loaded();
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
        // "There is only one _TPM_Hash_Start per H-CRTM Event Sequence", and
        // clause 31.1 abandons a sequence on any other indication, so a second
        // one starts over rather than adding to what came before.
        //
        // Part 3 clause 22.9.1 has the context hold "hash state for each bank
        // of PCR", and requires that creating it "will always succeed", so a
        // bank whose algorithm has no hasher is left out rather than refused.
        let sequence = state
            .pcr
            .algorithms()
            .into_iter()
            .filter_map(|a| crate::tpm::crypto::hash::Hasher::new(a).ok())
            .collect();
        state.hcrtm_sequence = Some(sequence);
    }

    fn hash_data(&self, data: &[u8]) {
        let mut state = self.locked();
        // Clause 22.10.1: "If no H-CRTM Event Sequence context exists, this
        // indication is discarded, and no other action is performed."
        if let Some(sequence) = state.hcrtm_sequence.as_mut() {
            for h in sequence.iter_mut() {
                h.update(data);
            }
        }
    }

    /// _TPM_Hash_End records the H-CRTM measurement, Part 3 clause 22.11.
    ///
    /// Where it goes depends on whether the sequence ran before or after
    /// TPM2_Startup, and the clause gives a different register and a different
    /// starting value for each.
    fn hash_end(&self) {
        use crate::tpm::config;
        use crate::tpm::crypto::hash;

        let mut state = self.locked();
        // Clause 22.11.1: the indication "is discarded, and no other action
        // performed if the TPM does not contain an H-CRTM Event Sequence
        // context."
        let Some(sequence) = state.hcrtm_sequence.take() else {
            return;
        };
        // Each bank's hash is completed here, which is the "complete the
        // digest" the clause asks for.
        let digests: Vec<(u16, Vec<u8>)> = sequence
            .into_iter()
            .map(|h| (h.hash_alg(), h.finish()))
            .collect();
        // A _TPM_Hash_End "will increment pcrUpdateCounter unless a
        // platform-specific specification excludes modifications of PCR[DRTM]
        // from causing an increment", once for the indication however many
        // banks it reaches. Before TPM2_Startup the registers are being given
        // their initial state, which Part 3 clause 9.3.2 leaves the counter out
        // of, so the value the indication found is put back either way and the
        // one increment is added below.
        let counter_before = state.pcr.update_counter();

        if state.started {
            // "If the H-CRTM Event Sequence occurs after TPM2_Startup(), the
            // TPM will set all of the PCR designated in the platform-specific
            // specifications as resettable by this event to the value indicated
            // in the platform specific specification and increment
            // restartCount. The TPM will then Extend the Event Sequence
            // digest/digests into the designated D-RTM PCR (PCR[17])."
            //
            // Setting those registers is the sequence doing it, not a command:
            // the platform profile says no TPM2_PCR_Reset can, and the command
            // path refuses for exactly that reason.
            state.pcr.drtm_reset();
            // The specification is not of one mind about where this belongs.
            // Part 2 clause 10.10.1 says restartCount counts TPM2_Shutdown or
            // _TPM_Hash_Start, clause 10.10.4 says TPM Restart or TPM Resume,
            // and the clause quoted above says this indication. It is done here
            // because that is the sentence that speaks about the H-CRTM
            // sequence, and because a sequence abandoned between its start and
            // its end changes no PCR, so counting it would record a restart
            // that did not happen.
            state.clock.restart_count = state.clock.restart_count.wrapping_add(1);
            for (a, digest) in digests {
                let _ = state.pcr.extend(config::DRTM_PCR, 4, &[(a, digest)]);
            }
            state
                .pcr
                .set_update_counter(counter_before.wrapping_add(u32::from(
                    !crate::tpm::core::pcr::no_increment(config::DRTM_PCR),
                )));
        } else {
            // "A platform-specific specification may allow an H-CRTM Event
            // Sequence before TPM2_Startup(). If so, _TPM_Hash_End will
            // complete the digest, initialize PCR[0] with a digest-size value
            // of 4, and then extend the H-CRTM Event Sequence data into
            // PCR[0]."
            for (a, digest) in digests {
                let Ok(size) = hash::digest_size(a) else {
                    continue;
                };
                // Every hash this TPM has produces a digest, so the last octet
                // is there; a hash with none could not carry the value anyway.
                let Some(last) = size.checked_sub(1) else {
                    continue;
                };
                let mut initial = vec![0u8; size];
                initial[last] = 4;
                if state.pcr.set(a, config::HCRTM_PCR, &initial).is_err() {
                    continue;
                }
                let _ = state.pcr.extend(config::HCRTM_PCR, 4, &[(a, digest)]);
                state.hcrtm_before_startup = true;
            }
            state.pcr.set_update_counter(counter_before);
        }
    }

    fn established(&self) -> bool {
        self.established.load(Ordering::SeqCst)
    }

    fn reset_established(&self, _locality: u8) {
        self.established.store(false, Ordering::SeqCst);
    }

    /// The signal of one authenticated countdown timer.
    ///
    /// This TPM has the single instance the platform profile asks for, so any
    /// other number has no timer and cannot be signalling.
    fn act_get_signaled(&self, act: u32) -> bool {
        if act != 0 {
            return false;
        }
        let elapsed = self.elapsed();
        let (signaled, rolled) = {
            let mut state = self.locked();
            let rolled = state.advance_time(elapsed);
            (state.act.signaled(), rolled)
        };
        // A rollover is the moment Part 2 clause 10.10.2 asks for the copy of
        // Clock in NV to be brought up to date, and it is what puts the safe
        // indication back. Reading the signal can be the thing that reaches it,
        // so the write happens here too rather than only after a command.
        if rolled {
            self.persist();
        }
        signaled
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
        // Every failure, including a bad command tag, uses TPM_ST_NO_SESSIONS.
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
