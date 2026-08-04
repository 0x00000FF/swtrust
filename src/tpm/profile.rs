//! Which platform profile the TPM presents.
//!
//! The PC Client Platform TPM Profile 1.07 clause 4.3 Table 3 marks
//! TPM_ALG_SHA1 as Not Allowed, and item 5 of that clause says an algorithm
//! marked that way "SHALL NOT be supported". Software that runs on real TPMs
//! has not caught up: BitLocker seals its volume master key in an object whose
//! nameAlg is TPM_ALG_SHA1, and the key a TPM virtual smart card certifies
//! itself with is signed with RSASSA over SHA-1. A TPM that answers
//! TPM_RC_HASH to those cannot protect a drive.
//!
//! So the two readings are both offered rather than one being chosen. The
//! default keeps SHA-1, which is what every shipping PC Client TPM does and
//! what callers expect. `--ptp` takes it away and leaves a TPM that conforms
//! to the profile as written.
//!
//! The choice is fixed once, before the first command is accepted, and never
//! changes afterwards: a TPM whose algorithm set moved underneath a caller
//! would invalidate keys and PCR banks that were already in use.

use std::sync::atomic::{AtomicU8, Ordering};

/// Which reading of the platform profile the TPM follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Everything the TPM 2.0 Library Specification defines, including the
    /// algorithms the platform profile has since deprecated.
    Legacy,
    /// Only what the PC Client Platform TPM Profile 1.07 allows.
    Strict,
}

const LEGACY: u8 = 0;
const STRICT: u8 = 1;

static CURRENT: AtomicU8 = AtomicU8::new(LEGACY);

/// Choose the profile. Call once, before the TPM accepts a command.
pub fn set(profile: Profile) {
    CURRENT.store(
        match profile {
            Profile::Legacy => LEGACY,
            Profile::Strict => STRICT,
        },
        Ordering::SeqCst,
    );
}

/// The profile in force.
pub fn current() -> Profile {
    match CURRENT.load(Ordering::SeqCst) {
        STRICT => Profile::Strict,
        _ => Profile::Legacy,
    }
}

/// True when the profile is followed as written, so SHA-1 is absent.
pub fn is_strict() -> bool {
    current() == Profile::Strict
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_keeps_the_deprecated_algorithms() {
        // A test binary that never calls `set` sees the default, which is what
        // a caller gets when the daemon is started without `--ptp`.
        assert_eq!(current(), Profile::Legacy);
        assert!(!is_strict());
    }
}
