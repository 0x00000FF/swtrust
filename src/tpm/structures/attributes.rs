//! Attribute bit fields from Part 2 clause 8.
//!
//! Each attribute is a newtype over the integer the specification assigns it.
//! Reserved bits are rejected on unmarshalling with TPM_RC_RESERVED_BITS, which
//! Part 2 clause 8.1 requires for every attribute structure.

use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};

macro_rules! attribute {
    (
        $(#[$meta:meta])*
        $name:ident : $int:ty, reserved = $reserved:expr,
        { $( $(#[$fmeta:meta])* $field:ident = $bit:expr ; )* }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        pub struct $name(pub $int);

        impl $name {
            /// Bits that shall be zero.
            pub const RESERVED: $int = $reserved;

            $(
                $(#[$fmeta])*
                pub const $field: $int = 1 << $bit;
            )*

            /// True when every bit in `mask` is set.
            pub fn has(self, mask: $int) -> bool {
                self.0 & mask == mask
            }

            /// True when any bit in `mask` is set.
            pub fn any(self, mask: $int) -> bool {
                self.0 & mask != 0
            }

            /// A copy with `mask` set.
            pub fn with(self, mask: $int) -> Self {
                $name(self.0 | mask)
            }

            /// A copy with `mask` cleared.
            pub fn without(self, mask: $int) -> Self {
                $name(self.0 & !mask)
            }

            /// Set or clear `mask` according to `on`.
            pub fn set(&mut self, mask: $int, on: bool) {
                if on {
                    self.0 |= mask;
                } else {
                    self.0 &= !mask;
                }
            }

            /// Check that no reserved bit is set.
            ///
            /// A few of the attribute types this macro builds have no reserved
            /// bits at all, so the mask is zero and the test can never be true.
            /// That is the right answer for them and not a mistake, which is
            /// what the allow says.
            #[allow(clippy::bad_bit_mask)]
            pub fn check_reserved(self) -> TpmResult<()> {
                if self.0 & Self::RESERVED != 0 {
                    return Err(TpmRc(rc::RESERVED_BITS));
                }
                Ok(())
            }
        }

        impl Marshal for $name {
            fn marshal(&self, w: &mut Writer) {
                Marshal::marshal(&self.0, w);
            }
        }

        impl Unmarshal for $name {
            fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
                let v = $name(<$int as Unmarshal>::unmarshal(r)?);
                v.check_reserved()?;
                Ok(v)
            }
        }
    };
}

attribute! {
    /// TPMA_OBJECT, Part 2 Table 37.
    ObjectAttributes: u32,
    reserved = 0b1111_1111_1111_0000_1111_0000_0000_1001,
    {
        /// The hierarchy of the object may not change.
        FIXED_TPM = 1;
        /// Saved contexts of this object may not be loaded after a Startup(CLEAR).
        ST_CLEAR = 2;
        /// The parent of the object may not change.
        FIXED_PARENT = 4;
        /// The TPM generated all of the sensitive data other than the authValue.
        SENSITIVE_DATA_ORIGIN = 5;
        /// The authValue may be used with HMAC or password authorization.
        USER_WITH_AUTH = 6;
        /// The authValue may not be used for administrative actions.
        ADMIN_WITH_POLICY = 7;
        /// The object is limited to the firmware that created it.
        FIRMWARE_LIMITED = 8;
        /// The object is limited to a minimum firmware security version number.
        SVN_LIMITED = 9;
        /// Authorization failures for this object do not affect the lockout.
        NO_DA = 10;
        /// The object may only be duplicated with encryptedDuplication.
        ENCRYPTED_DUPLICATION = 11;
        /// The object is a restricted key.
        RESTRICTED = 16;
        /// The private portion may be used to decrypt.
        DECRYPT = 17;
        /// The private portion may be used to sign, or the key may encrypt.
        SIGN_ENCRYPT = 18;
        /// The key may be used to sign an X.509 certificate.
        X509_SIGN = 19;
    }
}

attribute! {
    /// TPMA_SESSION, Part 2 Table 38.
    SessionAttributes: u8,
    reserved = 0b0001_1000,
    {
        /// The session is not flushed when the command completes.
        CONTINUE_SESSION = 0;
        /// The command must be the exclusive audit command.
        AUDIT_EXCLUSIVE = 1;
        /// The audit digest is reset before this command.
        AUDIT_RESET = 2;
        /// The first parameter of the command is encrypted.
        DECRYPT = 5;
        /// The first parameter of the response is to be encrypted.
        ENCRYPT = 6;
        /// The session is an audit session.
        AUDIT = 7;
    }
}

attribute! {
    /// TPMA_LOCALITY, Part 2 Table 39.
    ///
    /// Bits 0 through 4 name localities 0 through 4. When any of bits 7:5 is
    /// set the whole octet is an extended locality between 32 and 255, so no
    /// bit is reserved.
    LocalityAttributes: u8,
    reserved = 0,
    {
        ZERO = 0;
        ONE = 1;
        TWO = 2;
        THREE = 3;
        FOUR = 4;
    }
}

attribute! {
    /// TPMA_PERMANENT, Part 2 Table 40.
    ///
    /// Bits 7:3 and 31:11 are reserved.
    PermanentAttributes: u32,
    reserved = 0xFFFF_F8F8,
    {
        /// An owner authorization value has been set.
        OWNER_AUTH_SET = 0;
        /// An endorsement authorization value has been set.
        ENDORSEMENT_AUTH_SET = 1;
        /// A lockout authorization value has been set.
        LOCKOUT_AUTH_SET = 2;
        /// The TPM has not been provisioned since manufacture.
        DISABLE_CLEAR = 8;
        /// The TPM is in lockout and rejects authorization attempts.
        IN_LOCKOUT = 9;
        /// The endorsement primary seed was created by the TPM.
        TPM_GENERATED_EPS = 10;
    }
}

attribute! {
    /// TPMA_STARTUP_CLEAR, Part 2 Table 41.
    ///
    /// Bits 30:5 are reserved.
    StartupClearAttributes: u32,
    reserved = 0x7FFF_FFE0,
    {
        /// The platform hierarchy is enabled.
        PH_ENABLE = 0;
        /// The storage hierarchy is enabled.
        SH_ENABLE = 1;
        /// The endorsement hierarchy is enabled.
        EH_ENABLE = 2;
        /// NV Indices created by the platform are readable and writable.
        PH_ENABLE_NV = 3;
        /// The TPM is in the read-only mode of operation.
        READ_ONLY = 4;
        /// The last shutdown was orderly.
        ORDERLY = 31;
    }
}

attribute! {
    /// TPMA_MEMORY, Part 2 Table 42.
    MemoryAttributes: u32,
    reserved = 0xFFFF_FFF8,
    {
        /// Object contexts share memory with sessions.
        SHARED_RAM = 0;
        /// NV memory is shared between objects and Indices.
        SHARED_NV = 1;
        /// The object copy is removed when the object is loaded.
        OBJECT_COPIED_TO_RAM = 2;
    }
}

attribute! {
    /// TPMA_MODES, Part 2 Table 44.
    ///
    /// Bits 3:2 hold FIPS_140_3_INDICATOR rather than independent flags, so
    /// only bits 31:4 are reserved.
    ModesAttributes: u32,
    reserved = 0xFFFF_FFF0,
    {
        /// The TPM is designed to comply with FIPS 140-2.
        FIPS_140_2 = 0;
        /// The TPM is designed to comply with FIPS 140-3.
        FIPS_140_3 = 1;
    }
}

impl ModesAttributes {
    /// Mask over FIPS_140_3_INDICATOR, bits 3:2.
    pub const FIPS_140_3_INDICATOR_MASK: u32 = 0x0000_000C;
    /// Shift for FIPS_140_3_INDICATOR.
    pub const FIPS_140_3_INDICATOR_SHIFT: u32 = 2;

    /// The FIPS_140_3_INDICATOR field.
    pub fn fips_140_3_indicator(self) -> u8 {
        ((self.0 & Self::FIPS_140_3_INDICATOR_MASK) >> Self::FIPS_140_3_INDICATOR_SHIFT) as u8
    }
}

attribute! {
    /// TPMA_X509_KEY_USAGE, Part 2 Table 45.
    ///
    /// The bit numbering matches the X.509 KeyUsage extension, which numbers
    /// bits from the most significant end.
    X509KeyUsage: u32,
    reserved = 0x007F_FFFF,
    {
        DECIPHER_ONLY = 23;
        ENCIPHER_ONLY = 24;
        CRL_SIGN = 25;
        KEY_CERT_SIGN = 26;
        KEY_AGREEMENT = 27;
        DATA_ENCIPHERMENT = 28;
        KEY_ENCIPHERMENT = 29;
        NON_REPUDIATION = 30;
        DIGITAL_SIGNATURE = 31;
    }
}

attribute! {
    /// TPMA_ACT, Part 2 Table 46.
    ActAttributes: u32,
    reserved = 0xFFFF_FFFC,
    {
        /// The ACT has signaled.
        SIGNALED = 0;
        /// The signaled state is preserved across a TPM Reset.
        PRESERVE_SIGNALED = 1;
    }
}

attribute! {
    /// TPMA_NV, Part 2 Table 249.
    ///
    /// Bits 7:4 hold a TPM_NT rather than independent flags, so they are not
    /// reserved and are read with [`NvAttributes::index_type`]. Bits 9:8 and
    /// 24:20 are reserved.
    NvAttributes: u32,
    reserved = 0x01F0_0300,
    {
        /// Writable with platform authorization.
        PPWRITE = 0;
        /// Writable with owner authorization.
        OWNERWRITE = 1;
        /// Writable with the Index authValue.
        AUTHWRITE = 2;
        /// Writable with the Index policy.
        POLICYWRITE = 3;
        /// The Index may be undefined only with a policy.
        POLICY_DELETE = 10;
        /// Writes are currently locked.
        WRITELOCKED = 11;
        /// A write must cover the whole Index.
        WRITEALL = 12;
        /// The Index may be permanently write locked.
        WRITEDEFINE = 13;
        /// The write lock is cleared by a Startup(CLEAR).
        WRITE_STCLEAR = 14;
        /// The Index is covered by TPM2_NV_GlobalWriteLock.
        GLOBALLOCK = 15;
        /// Readable with platform authorization.
        PPREAD = 16;
        /// Readable with owner authorization.
        OWNERREAD = 17;
        /// Readable with the Index authValue.
        AUTHREAD = 18;
        /// Readable with the Index policy.
        POLICYREAD = 19;
        /// Authorization failures do not affect the lockout.
        NO_DA = 25;
        /// The Index is kept in RAM and written to NV on an orderly shutdown.
        ORDERLY = 26;
        /// The read lock is cleared by a Startup(CLEAR).
        CLEAR_STCLEAR = 27;
        /// Reads are currently locked.
        READLOCKED = 28;
        /// The Index has been written at least once.
        WRITTEN = 29;
        /// The Index was defined with platform authorization.
        PLATFORMCREATE = 30;
        /// The Index may be read locked.
        READ_STCLEAR = 31;
    }
}

impl NvAttributes {
    /// Mask covering the TPM_NT field, bits 7 through 4.
    pub const TYPE_MASK: u32 = 0x0000_00F0;
    /// Shift for the TPM_NT field.
    pub const TYPE_SHIFT: u32 = 4;

    /// The TPM_NT held in bits 7:4.
    pub fn index_type(self) -> u8 {
        ((self.0 & Self::TYPE_MASK) >> Self::TYPE_SHIFT) as u8
    }

    /// A copy with the TPM_NT field replaced.
    pub fn with_index_type(self, nt: u8) -> Self {
        NvAttributes((self.0 & !Self::TYPE_MASK) | (((nt as u32) << Self::TYPE_SHIFT) & Self::TYPE_MASK))
    }
}

/// TPM_NT values, Part 2 Table 247.
pub mod nt {
    /// Ordinary read and write data.
    pub const ORDINARY: u8 = 0x0;
    /// A monotonic counter.
    pub const COUNTER: u8 = 0x1;
    /// A bit field that is only ever set.
    pub const BITS: u8 = 0x2;
    /// A PCR-like Index that is extended.
    pub const EXTEND: u8 = 0x4;
    /// A PIN counter that fails when the count is reached.
    pub const PIN_FAIL: u8 = 0x8;
    /// A PIN counter that passes while the count is below the limit.
    pub const PIN_PASS: u8 = 0x9;
}

attribute! {
    /// TPMA_CC, Part 2 Table 43.
    ///
    /// Bits 15:0 hold the command index and bits 27:25 hold cHandles, so
    /// neither range is reserved. Bits 21:16 and 31:30 are reserved.
    CommandAttributes: u32,
    reserved = 0xC03F_0000,
    {
        /// The command may write to NV.
        NV = 22;
        /// The command may flush many objects or Indices.
        EXTENSIVE = 23;
        /// The command may flush the handle it was given.
        FLUSHED = 24;
        /// The response has a handle area.
        R_HANDLE = 28;
        /// The command is vendor specific.
        V = 29;
    }
}

impl CommandAttributes {
    /// Mask over the command index, bits 15:0.
    pub const COMMAND_INDEX_MASK: u32 = 0x0000_FFFF;
    /// Mask over cHandles, bits 27:25.
    pub const CHANDLES_MASK: u32 = 0x0E00_0000;
    /// Shift for cHandles.
    pub const CHANDLES_SHIFT: u32 = 25;

    /// Build the attributes for a command.
    pub fn build(command_index: u16, handles: u8, flags: u32) -> CommandAttributes {
        CommandAttributes(
            (command_index as u32)
                | (((handles as u32) << Self::CHANDLES_SHIFT) & Self::CHANDLES_MASK)
                | flags,
        )
    }

    /// The command index in bits 15:0.
    pub fn command_index(self) -> u16 {
        (self.0 & Self::COMMAND_INDEX_MASK) as u16
    }

    /// The number of handles in the handle area.
    pub fn handles(self) -> u8 {
        ((self.0 & Self::CHANDLES_MASK) >> Self::CHANDLES_SHIFT) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_attribute_bit_positions() {
        assert_eq!(ObjectAttributes::FIXED_TPM, 0x0000_0002);
        assert_eq!(ObjectAttributes::ST_CLEAR, 0x0000_0004);
        assert_eq!(ObjectAttributes::FIXED_PARENT, 0x0000_0010);
        assert_eq!(ObjectAttributes::SENSITIVE_DATA_ORIGIN, 0x0000_0020);
        assert_eq!(ObjectAttributes::USER_WITH_AUTH, 0x0000_0040);
        assert_eq!(ObjectAttributes::ADMIN_WITH_POLICY, 0x0000_0080);
        assert_eq!(ObjectAttributes::FIRMWARE_LIMITED, 0x0000_0100);
        assert_eq!(ObjectAttributes::SVN_LIMITED, 0x0000_0200);
        assert_eq!(ObjectAttributes::NO_DA, 0x0000_0400);
        assert_eq!(ObjectAttributes::ENCRYPTED_DUPLICATION, 0x0000_0800);
        assert_eq!(ObjectAttributes::RESTRICTED, 0x0001_0000);
        assert_eq!(ObjectAttributes::DECRYPT, 0x0002_0000);
        assert_eq!(ObjectAttributes::SIGN_ENCRYPT, 0x0004_0000);
        assert_eq!(ObjectAttributes::X509_SIGN, 0x0008_0000);
    }

    #[test]
    fn object_reserved_bits_are_rejected() {
        // Bits 0, 3, 15:12 and 31:20 are reserved.
        for bit in [0u32, 3, 12, 13, 14, 15, 20, 31] {
            let raw = (1u32 << bit).to_be_bytes();
            let e = ObjectAttributes::from_bytes(&raw).unwrap_err();
            assert_eq!(e, TpmRc(rc::RESERVED_BITS), "bit {bit}");
        }
        // A typical storage key template unmarshals cleanly.
        let ok = ObjectAttributes::FIXED_TPM
            | ObjectAttributes::FIXED_PARENT
            | ObjectAttributes::SENSITIVE_DATA_ORIGIN
            | ObjectAttributes::USER_WITH_AUTH
            | ObjectAttributes::RESTRICTED
            | ObjectAttributes::DECRYPT;
        assert_eq!(
            ObjectAttributes::from_bytes(&ok.to_be_bytes()).unwrap(),
            ObjectAttributes(ok)
        );
    }

    #[test]
    fn session_attribute_bit_positions() {
        assert_eq!(SessionAttributes::CONTINUE_SESSION, 0x01);
        assert_eq!(SessionAttributes::AUDIT_EXCLUSIVE, 0x02);
        assert_eq!(SessionAttributes::AUDIT_RESET, 0x04);
        assert_eq!(SessionAttributes::DECRYPT, 0x20);
        assert_eq!(SessionAttributes::ENCRYPT, 0x40);
        assert_eq!(SessionAttributes::AUDIT, 0x80);
        // Bits 4:3 are reserved.
        assert!(SessionAttributes::from_bytes(&[0x08]).is_err());
        assert!(SessionAttributes::from_bytes(&[0x10]).is_err());
        assert!(SessionAttributes::from_bytes(&[0xE7]).is_ok());
    }

    #[test]
    fn nv_attribute_bit_positions_and_type_field() {
        assert_eq!(NvAttributes::PPWRITE, 1 << 0);
        assert_eq!(NvAttributes::POLICYWRITE, 1 << 3);
        assert_eq!(NvAttributes::POLICY_DELETE, 1 << 10);
        assert_eq!(NvAttributes::WRITTEN, 1 << 29);
        assert_eq!(NvAttributes::READ_STCLEAR, 1 << 31);

        let a = NvAttributes(0).with_index_type(nt::COUNTER);
        assert_eq!(a.0, 0x0000_0010);
        assert_eq!(a.index_type(), nt::COUNTER);
        let a = NvAttributes(0).with_index_type(nt::PIN_PASS);
        assert_eq!(a.0, 0x0000_0090);
        assert_eq!(a.index_type(), nt::PIN_PASS);
        // The type field never bleeds into neighbouring bits.
        let a = NvAttributes(0xFFFF_FFFF & !NvAttributes::RESERVED).with_index_type(nt::ORDINARY);
        assert_eq!(a.index_type(), nt::ORDINARY);
        assert!(a.has(NvAttributes::PPWRITE));
    }

    #[test]
    fn nv_reserved_bits_are_rejected() {
        for bit in [8u32, 9, 20, 21, 22, 23, 24] {
            let raw = (1u32 << bit).to_be_bytes();
            assert_eq!(
                NvAttributes::from_bytes(&raw).unwrap_err(),
                TpmRc(rc::RESERVED_BITS),
                "bit {bit}"
            );
        }
        // The TPM_NT field is not reserved.
        assert!(NvAttributes::from_bytes(&0x0000_00F0u32.to_be_bytes()).is_ok());
    }

    #[test]
    fn startup_clear_and_permanent_bits() {
        assert_eq!(StartupClearAttributes::PH_ENABLE, 1);
        assert_eq!(StartupClearAttributes::SH_ENABLE, 2);
        assert_eq!(StartupClearAttributes::EH_ENABLE, 4);
        assert_eq!(StartupClearAttributes::PH_ENABLE_NV, 8);
        assert_eq!(StartupClearAttributes::READ_ONLY, 0x10);
        assert_eq!(StartupClearAttributes::ORDERLY, 0x8000_0000);
        // Bits 30:5 are reserved.
        assert!(StartupClearAttributes::from_bytes(&0x20u32.to_be_bytes()).is_err());
        assert!(StartupClearAttributes::from_bytes(&0x4000_0000u32.to_be_bytes()).is_err());
        assert!(StartupClearAttributes::from_bytes(&0x8000_001Fu32.to_be_bytes()).is_ok());

        assert_eq!(PermanentAttributes::OWNER_AUTH_SET, 1);
        assert_eq!(PermanentAttributes::ENDORSEMENT_AUTH_SET, 2);
        assert_eq!(PermanentAttributes::LOCKOUT_AUTH_SET, 4);
        assert_eq!(PermanentAttributes::DISABLE_CLEAR, 0x100);
        assert_eq!(PermanentAttributes::IN_LOCKOUT, 0x200);
        assert_eq!(PermanentAttributes::TPM_GENERATED_EPS, 0x400);
        // Bits 7:3 and 31:11 are reserved.
        assert!(PermanentAttributes::from_bytes(&0x08u32.to_be_bytes()).is_err());
        assert!(PermanentAttributes::from_bytes(&0x800u32.to_be_bytes()).is_err());
        assert!(PermanentAttributes::from_bytes(&0x707u32.to_be_bytes()).is_ok());
    }

    #[test]
    fn modes_indicator_field() {
        assert_eq!(ModesAttributes::FIPS_140_2, 1);
        assert_eq!(ModesAttributes::FIPS_140_3, 2);
        let m = ModesAttributes(0x0000_000C);
        assert_eq!(m.fips_140_3_indicator(), 3);
        // Bits 31:4 are reserved, bits 3:2 are not.
        assert!(ModesAttributes::from_bytes(&0x0Fu32.to_be_bytes()).is_ok());
        assert!(ModesAttributes::from_bytes(&0x10u32.to_be_bytes()).is_err());
    }

    #[test]
    fn command_attribute_reserved_bits() {
        // Bits 21:16 and 31:30 are reserved. The command index and cHandles
        // ranges are not.
        assert!(CommandAttributes::from_bytes(&0x0001_0000u32.to_be_bytes()).is_err());
        assert!(CommandAttributes::from_bytes(&0x0020_0000u32.to_be_bytes()).is_err());
        assert!(CommandAttributes::from_bytes(&0x4000_0000u32.to_be_bytes()).is_err());
        assert!(CommandAttributes::from_bytes(&0x0FC0_FFFFu32.to_be_bytes()).is_ok());
        assert_eq!(CommandAttributes::NV, 1 << 22);
        assert_eq!(CommandAttributes::EXTENSIVE, 1 << 23);
        assert_eq!(CommandAttributes::FLUSHED, 1 << 24);
        assert_eq!(CommandAttributes::R_HANDLE, 1 << 28);
        assert_eq!(CommandAttributes::V, 1 << 29);
    }

    #[test]
    fn helper_methods() {
        let mut a = ObjectAttributes(0);
        a.set(ObjectAttributes::SIGN_ENCRYPT, true);
        assert!(a.has(ObjectAttributes::SIGN_ENCRYPT));
        assert!(a.any(ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::DECRYPT));
        assert!(!a.has(ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::DECRYPT));
        a.set(ObjectAttributes::SIGN_ENCRYPT, false);
        assert_eq!(a, ObjectAttributes(0));
        assert!(a.with(ObjectAttributes::NO_DA).has(ObjectAttributes::NO_DA));
        assert!(!a
            .with(ObjectAttributes::NO_DA)
            .without(ObjectAttributes::NO_DA)
            .has(ObjectAttributes::NO_DA));
    }

    #[test]
    fn command_attributes_pack_index_and_handles() {
        let a = CommandAttributes::build(0x0144, 0, 0);
        assert_eq!(a.command_index(), 0x0144);
        assert_eq!(a.handles(), 0);
        let a = CommandAttributes::build(0x0153, 1, CommandAttributes::NV);
        assert_eq!(a.command_index(), 0x0153);
        assert_eq!(a.handles(), 1);
        assert!(a.has(CommandAttributes::NV));
        let a = CommandAttributes::build(0x0176, 2, 0);
        assert_eq!(a.handles(), 2);
    }

    #[test]
    fn attributes_round_trip_big_endian() {
        let a = ObjectAttributes(0x0004_0072);
        let bytes = a.to_bytes();
        assert_eq!(bytes, vec![0x00, 0x04, 0x00, 0x72]);
        assert_eq!(ObjectAttributes::from_bytes(&bytes).unwrap(), a);

        let s = SessionAttributes(0x81);
        assert_eq!(s.to_bytes(), vec![0x81]);
    }
}
