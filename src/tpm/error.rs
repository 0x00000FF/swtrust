//! Response codes.
//!
//! Part 2 clause 6.6 defines three response code groups. Format-zero codes and
//! warnings stand alone. Format-one codes carry a qualifier that says whether
//! the problem was in a handle, a parameter or a session, and which one.

use crate::tpm::constants::rc;

/// A TPM response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmRc(pub u32);

/// Result of any operation that can produce a response code.
pub type TpmResult<T> = Result<T, TpmRc>;

impl TpmRc {
    pub const SUCCESS: TpmRc = TpmRc(rc::SUCCESS);

    /// The raw 32-bit value placed in the response.
    pub fn value(self) -> u32 {
        self.0
    }

    /// True when bit 7 (F) is set, which marks a format-one code.
    pub fn is_format_one(self) -> bool {
        self.0 & 0x080 != 0
    }

    /// Attach a handle number, 1 through 7, to a format-one code.
    ///
    /// The number is the position of the handle in the handle area, counting
    /// from one. An index outside 1 through 7 cannot be encoded, so the code
    /// is returned unqualified rather than pointing at the wrong handle.
    pub fn with_handle(self, index: usize) -> TpmRc {
        self.qualify(rc::H, index, 7)
    }

    /// Attach a parameter number, 1 through 15, to a format-one code.
    ///
    /// The number counts parameters in the command, starting at one after the
    /// handle area. An index outside 1 through 15 leaves the code unqualified.
    pub fn with_parameter(self, index: usize) -> TpmRc {
        self.qualify(rc::P, index, 15)
    }

    /// Attach a session number, 1 through 7, to a format-one code.
    ///
    /// An index outside 1 through 7 leaves the code unqualified.
    pub fn with_session(self, index: usize) -> TpmRc {
        self.qualify(rc::S, index, 7)
    }

    fn qualify(self, kind: u32, index: usize, max: usize) -> TpmRc {
        // Only unqualified format-one codes carry a qualifier. Anything else,
        // including warnings and format-zero codes, is returned unchanged.
        if !self.is_base_format_one() {
            return self;
        }
        // The number field is one based and narrow. Reporting the wrong
        // position would be worse than reporting no position, so an index that
        // does not fit produces the plain error.
        if index == 0 || index > max {
            return self;
        }
        let base = self.0 & 0x03F;
        TpmRc(rc::RC_FMT1 | base | kind | ((index as u32) << 8))
    }

    /// Move a format-one code to a different parameter number.
    ///
    /// Part 2 clause 6.6.2 lets a format-one code name the parameter that
    /// carried the value, and the same check reached from two commands names
    /// two different positions. The qualifier already on the code is replaced
    /// rather than added to, which the plain [`TpmRc::with_parameter`] would
    /// not do because it only decorates an unqualified code.
    pub fn at_parameter(self, index: usize) -> TpmRc {
        if !self.is_format_one() {
            return self;
        }
        TpmRc(rc::RC_FMT1 | (self.0 & 0x03F)).with_parameter(index)
    }

    /// True when the code is a format-one code without a qualifier applied.
    fn is_base_format_one(self) -> bool {
        // Format-one codes occupy 0x080 through 0x0BF before qualification.
        (0x080..=0x0BF).contains(&self.0)
    }

    /// True when the code is a warning, meaning the command may be retried.
    ///
    /// Bit 11 (S) is the severity bit of a format-zero code.
    pub fn is_warning(self) -> bool {
        !self.is_format_one() && (self.0 & 0x800) != 0
    }

    /// True for TPM_RC_SUCCESS.
    pub fn is_success(self) -> bool {
        self.0 == rc::SUCCESS
    }
}

impl From<u32> for TpmRc {
    fn from(v: u32) -> Self {
        TpmRc(v)
    }
}

impl std::fmt::Display for TpmRc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl std::error::Error for TpmRc {}

/// Shorthand for constructing a response code from the `rc` constant module.
#[macro_export]
macro_rules! tpm_rc {
    ($name:ident) => {
        $crate::tpm::error::TpmRc($crate::tpm::constants::rc::$name)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_one_qualifiers() {
        // TPM_RC_VALUE for the first parameter is 0x000001C4 in the low 12 bits.
        let e = TpmRc(rc::VALUE).with_parameter(1);
        assert_eq!(e.0, 0x1C4);
        // Second parameter.
        assert_eq!(TpmRc(rc::VALUE).with_parameter(2).0, 0x2C4);
        // First handle.
        assert_eq!(TpmRc(rc::VALUE).with_handle(1).0, 0x184);
        // First session.
        assert_eq!(TpmRc(rc::VALUE).with_session(1).0, 0x984);
    }

    #[test]
    fn qualifier_does_not_apply_to_other_groups() {
        assert_eq!(TpmRc(rc::INITIALIZE).with_parameter(1).0, rc::INITIALIZE);
        assert_eq!(TpmRc(rc::CONTEXT_GAP).with_parameter(1).0, rc::CONTEXT_GAP);
        assert_eq!(TpmRc(rc::SUCCESS).with_handle(1).0, rc::SUCCESS);
    }

    #[test]
    fn classification() {
        assert!(TpmRc(rc::SUCCESS).is_success());
        assert!(TpmRc(rc::CONTEXT_GAP).is_warning());
        assert!(TpmRc(rc::RETRY).is_warning());
        assert!(!TpmRc(rc::FAILURE).is_warning());
        assert!(!TpmRc(rc::VALUE).is_warning());
        assert!(TpmRc(rc::VALUE).is_format_one());
        assert!(!TpmRc(rc::FAILURE).is_format_one());
        // A qualified format-one code keeps the format bit and is never a warning.
        let q = TpmRc(rc::VALUE).with_session(1);
        assert!(q.is_format_one());
        assert!(!q.is_warning());
    }

    #[test]
    fn qualifier_indexes_cover_the_whole_field() {
        // Handles and sessions have a three bit number, parameters have four.
        assert_eq!(TpmRc(rc::VALUE).with_handle(7).0, 0x784);
        assert_eq!(TpmRc(rc::VALUE).with_session(7).0, 0xF84);
        assert_eq!(TpmRc(rc::VALUE).with_parameter(15).0, 0xFC4);
    }

    #[test]
    fn out_of_range_indexes_leave_the_code_unqualified() {
        // An index that does not fit the field would name the wrong position,
        // so the plain format-one code is returned instead.
        assert_eq!(TpmRc(rc::VALUE).with_handle(8).0, rc::VALUE);
        assert_eq!(TpmRc(rc::VALUE).with_session(8).0, rc::VALUE);
        assert_eq!(TpmRc(rc::VALUE).with_parameter(16).0, rc::VALUE);
        assert_eq!(TpmRc(rc::VALUE).with_handle(0).0, rc::VALUE);
        assert_eq!(TpmRc(rc::VALUE).with_parameter(0).0, rc::VALUE);
        assert_eq!(TpmRc(rc::VALUE).with_handle(usize::MAX).0, rc::VALUE);
    }

    #[test]
    fn qualifier_is_not_applied_twice() {
        let once = TpmRc(rc::VALUE).with_parameter(1);
        assert_eq!(once.with_parameter(2), once);
    }

    #[test]
    fn all_format_one_codes_qualify_cleanly() {
        for base in [
            rc::ASYMMETRIC,
            rc::ATTRIBUTES,
            rc::HASH,
            rc::VALUE,
            rc::HIERARCHY,
            rc::KEY_SIZE,
            rc::MGF,
            rc::MODE,
            rc::TYPE,
            rc::HANDLE,
            rc::KDF,
            rc::RANGE,
            rc::AUTH_FAIL,
            rc::NONCE,
            rc::PP,
            rc::SCHEME,
            rc::SIZE,
            rc::SYMMETRIC,
            rc::TAG,
            rc::SELECTOR,
            rc::INSUFFICIENT,
            rc::SIGNATURE,
            rc::KEY,
            rc::POLICY_FAIL,
            rc::INTEGRITY,
            rc::TICKET,
            rc::RESERVED_BITS,
            rc::BAD_AUTH,
            rc::EXPIRED,
            rc::POLICY_CC,
            rc::BINDING,
            rc::CURVE,
            rc::ECC_POINT,
            rc::FW_LIMITED,
            rc::SVN_LIMITED,
            rc::PARMS,
            rc::EXT_MU,
            rc::ONE_SHOT_SIGNATURE,
            rc::SIGN_CONTEXT_KEY,
            rc::CHANNEL,
            rc::CHANNEL_KEY,
        ] {
            let q = TpmRc(base).with_parameter(3);
            assert_eq!(q.0 & 0x03F, base & 0x03F);
            assert_eq!(q.0 & 0x040, rc::P);
            assert_eq!(q.0 & 0xF00, 0x300);
            assert_eq!(q.0 & 0x080, 0x080);
        }
    }
}
