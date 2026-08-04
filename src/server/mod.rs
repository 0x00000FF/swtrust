//! Transports that carry TPM command buffers.
//!
//! Two interfaces are offered and selected on the command line:
//!
//! * `socket` speaks the TPM simulator TCP protocol on a command port and a
//!   platform control port, which is what existing TPM tooling expects.
//! * `pipe` exposes a Windows named pipe that carries bare TPM command and
//!   response buffers.
//! * `qemu` splits the two apart the way a virtual machine monitor expects: a
//!   data channel carrying bare command and response buffers, and a control
//!   channel carrying the platform requests.

pub mod pipe;
pub mod qemu;
pub mod simulator;
pub mod socket;

use std::io;
use std::sync::Arc;

use crate::cli::{Config, Interface};
use crate::logging::Logger;
use crate::tpm::device::Tpm;

/// The platform facing view of a TPM.
///
/// Part 1 describes the signals a platform sends to a TPM outside of the
/// command interface: power, reset, physical presence, locality and the
/// H-CRTM event sequence. The transports translate their wire protocol into
/// these calls.
pub trait Device: Send + Sync {
    /// Run one command buffer at `locality` and produce the response buffer.
    fn execute(&self, locality: u8, command: &[u8]) -> Vec<u8>;

    /// _TPM_Init followed by power being applied.
    fn power_on(&self);
    /// Power removed. The TPM loses all volatile state.
    fn power_off(&self);
    /// True while the TPM has power.
    fn is_powered_on(&self) -> bool;

    /// NV storage made available or taken away.
    fn nv_on(&self);
    fn nv_off(&self);

    /// Assert or deassert physical presence.
    fn physical_presence(&self, asserted: bool);
    /// Assert or deassert the cancel signal.
    fn cancel(&self, asserted: bool);

    /// _TPM_Hash_Start, _TPM_Hash_Data and _TPM_Hash_End.
    fn hash_start(&self);
    fn hash_data(&self, data: &[u8]);
    fn hash_end(&self);

    /// The platform establishment flag.
    ///
    /// The flag records that an H-CRTM event sequence has begun.
    ///
    /// Part 1 clause 31 defines that sequence and the _TPM_Hash_Start
    /// indication that opens it, but it does not define this flag. The flag is
    /// read and cleared through the register interface, which the PC Client
    /// Platform TPM Profile defines, and that document is not among the
    /// references. So what the flag means here is taken from the one thing the
    /// Library does settle, that _TPM_Hash_Start marks the start of an H-CRTM
    /// sequence, and the register semantics are left to the platform.
    fn established(&self) -> bool;

    /// Clear the establishment flag on behalf of `locality`.
    ///
    /// Which localities may clear it is a property of that same register
    /// interface, so the platform is trusted to have made that decision before
    /// asking.
    fn reset_established(&self, locality: u8);

    /// True when the authenticated timer `act` has signaled.
    fn act_get_signaled(&self, act: u32) -> bool;
}

/// Start the daemon described by `config` and serve until the process is
/// stopped or a client asks the TPM to stop.
pub fn run(config: Config) -> io::Result<()> {
    // The profile decides which algorithms exist, so it is fixed before the TPM
    // is built and before any state is read: a manufactured TPM allocates PCR
    // banks from the set the profile allows.
    crate::tpm::profile::set(if config.ptp {
        crate::tpm::profile::Profile::Strict
    } else {
        crate::tpm::profile::Profile::Legacy
    });

    let logger = Arc::new(Logger::new(&config.log_dir, config.verbose)?);
    let tpm = Arc::new(Tpm::new(&config.state_dir, logger.clone())?);

    logger.line(&format!(
        "swtrust {} starting interface={} state={} log-dir={} profile={}",
        env!("CARGO_PKG_VERSION"),
        config.interface,
        config.state_dir.display(),
        config.log_dir.display(),
        if config.ptp { "ptp" } else { "legacy" }
    ));

    // The console reads stdin on its own thread, so the transport keeps the
    // main one and the two share the TPM through its lock.
    if config.console {
        crate::console::spawn(tpm.clone(), logger.clone());
    }

    match config.interface {
        Interface::Socket => socket::serve(&config, tpm, logger),
        Interface::Pipe => pipe::serve(&config, tpm, logger),
        Interface::Qemu => qemu::serve(&config, tpm, logger),
    }
}
