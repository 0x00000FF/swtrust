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
/// The tag is checked first because a bad tag changes the shape of the error
/// response, then the size is checked against the octets actually received.
pub fn parse_header(buf: &[u8]) -> Result<CommandHeader, TpmRc> {
    if buf.len() < HEADER_SIZE {
        return Err(TpmRc(rc::COMMAND_SIZE));
    }
    let tag = u16::from_be_bytes([buf[0], buf[1]]);
    if tag != st::NO_SESSIONS && tag != st::SESSIONS {
        return Err(TpmRc(rc::BAD_TAG));
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
/// ten and the response code, except when the tag itself was not recognised.
pub fn error_response(code: TpmRc) -> Vec<u8> {
    let tag = if code == TpmRc(rc::BAD_TAG) {
        st::RSP_COMMAND
    } else {
        st::NO_SESSIONS
    };
    let mut w = Writer::with_capacity(HEADER_SIZE);
    w.u16(tag);
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

/// Volatile and non-volatile TPM state.
pub struct TpmState {
    /// Set once TPM2_Startup has completed.
    pub started: bool,
    /// Set while physical presence is asserted by the platform.
    pub physical_presence: bool,
    /// Set while NV storage is available.
    pub nv_available: bool,
}

impl Default for TpmState {
    fn default() -> Self {
        TpmState {
            started: false,
            physical_presence: false,
            nv_available: true,
        }
    }
}

/// A software TPM.
pub struct Tpm {
    state: Mutex<TpmState>,
    powered: AtomicBool,
    cancel: AtomicBool,
    store: StateStore,
    logger: Arc<Logger>,
}

impl Tpm {
    /// Create a TPM whose non-volatile state lives in `state_dir`.
    pub fn new(state_dir: impl AsRef<Path>, logger: Arc<Logger>) -> io::Result<Tpm> {
        let store = StateStore::new(state_dir)?;
        Ok(Tpm {
            state: Mutex::new(TpmState::default()),
            powered: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
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
}

impl Device for Tpm {
    fn execute(&self, _locality: u8, command: &[u8]) -> Vec<u8> {
        if !self.powered.load(Ordering::SeqCst) {
            return error_response(TpmRc(rc::INITIALIZE));
        }
        let header = match parse_header(command) {
            Ok(h) => h,
            Err(e) => return error_response(e),
        };
        let _state = self.locked();
        let _ = header;
        error_response(TpmRc(rc::COMMAND_CODE))
    }

    fn power_on(&self) {
        self.powered.store(true, Ordering::SeqCst);
        let mut state = self.locked();
        *state = TpmState::default();
        self.logger.line("_TPM_Init");
    }

    fn power_off(&self) {
        self.powered.store(false, Ordering::SeqCst);
        let mut state = self.locked();
        *state = TpmState::default();
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

    fn hash_start(&self) {}

    fn hash_data(&self, _data: &[u8]) {}

    fn hash_end(&self) {}

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
    fn unrecognised_tag_is_rejected() {
        let cmd = [
            0x00u8, 0xc1, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x44,
        ];
        assert_eq!(parse_header(&cmd).unwrap_err(), TpmRc(rc::BAD_TAG));
    }

    #[test]
    fn size_must_match_the_buffer() {
        let cmd = [
            0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x44,
        ];
        assert_eq!(parse_header(&cmd).unwrap_err(), TpmRc(rc::COMMAND_SIZE));
        assert_eq!(parse_header(&cmd[..4]).unwrap_err(), TpmRc(rc::COMMAND_SIZE));
    }

    #[test]
    fn error_response_shape() {
        let r = error_response(TpmRc(rc::INITIALIZE));
        assert_eq!(
            r,
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00]
        );
        // A bad tag is reported with the TPM 1.2 compatible response tag.
        let r = error_response(TpmRc(rc::BAD_TAG));
        assert_eq!(&r[0..2], &st::RSP_COMMAND.to_be_bytes());
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
