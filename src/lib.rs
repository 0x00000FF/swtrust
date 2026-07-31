//! swtrust, a software TPM 2.0 implementation.
//!
//! The crate is split into the TPM itself (`tpm`), the transports that carry
//! command buffers (`server`), and the supporting pieces for the daemon: the
//! command line, the command log and small utilities.

pub mod cli;
pub mod console;
pub mod logging;
pub mod server;
pub mod tpm;
pub mod util;

pub use server::run;
