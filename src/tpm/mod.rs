//! TPM 2.0 implementation.
//!
//! The layout follows the specification parts: `constants` and `structures`
//! come from Part 2, `crypto` and the state machine from Part 1, and the
//! command implementations from Part 3.

pub mod commands;
pub mod config;
pub mod constants;
pub mod core;
pub mod crypto;
pub mod device;
pub mod error;
pub mod fips;
pub mod marshal;
pub mod persist;
pub mod profile;
pub mod structures;
