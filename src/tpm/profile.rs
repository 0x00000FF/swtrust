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

const UNSET: u8 = 0;
const LEGACY: u8 = 1;
const STRICT: u8 = 2;

static CURRENT: AtomicU8 = AtomicU8::new(UNSET);

/// Choose the profile. The first call decides; later ones are ignored.
///
/// It cannot be a value that changes while the TPM runs. The algorithm set is
/// what a caller builds keys and PCR banks on, so moving it underneath one
/// would invalidate what it already holds, and nothing in the specification
/// lets a TPM stop implementing an algorithm it has been reporting.
///
/// Returns the profile in force, which is the one asked for unless the choice
/// had already been made.
pub fn set(profile: Profile) -> Profile {
    let wanted = match profile {
        Profile::Legacy => LEGACY,
        Profile::Strict => STRICT,
    };
    match CURRENT.compare_exchange(UNSET, wanted, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => profile,
        Err(existing) => decode(existing),
    }
}

fn decode(value: u8) -> Profile {
    match value {
        STRICT => Profile::Strict,
        _ => Profile::Legacy,
    }
}

/// The profile in force, which is the legacy one until a choice is made.
pub fn current() -> Profile {
    decode(CURRENT.load(Ordering::SeqCst))
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

    #[test]
    fn the_first_choice_is_the_one_that_stands() {
        // The unit tests share a process, so this one settles the value for all
        // of them. It asks for the default, which is what they already see.
        assert_eq!(set(Profile::Legacy), Profile::Legacy);
        // A later call cannot move it, and says so by returning what is really
        // in force rather than what it was asked for.
        assert_eq!(set(Profile::Strict), Profile::Legacy);
        assert_eq!(current(), Profile::Legacy);
    }
}
