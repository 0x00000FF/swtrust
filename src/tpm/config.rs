//! Implementation dependent values.
//!
//! Part 2 defines several constants in terms of implementation choices such as
//! `IMPLEMENTATION_PCR` and `MAX_ACTIVE_SESSIONS`. They are collected here and
//! reported through TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES).

#![allow(dead_code)]

use crate::tpm::constants::{alg, curve};

/// Number of PCR implemented in each bank.
pub const IMPLEMENTATION_PCR: u16 = 24;
/// Number of PCR that are under platform control.
pub const PLATFORM_PCR: u16 = 24;
/// PCR reset by a D-RTM event.
pub const DRTM_PCR: u16 = 17;
/// PCR extended by an H-CRTM event.
pub const HCRTM_PCR: u16 = 0;
/// Number of localities, 0 through 4.
pub const NUM_LOCALITIES: u8 = 5;
/// Minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect.
pub const PCR_SELECT_MIN: u8 = ((IMPLEMENTATION_PCR + 7) / 8) as u8;
/// Maximum number of octets in a TPMS_PCR_SELECT.sizeOfSelect.
pub const PCR_SELECT_MAX: u8 = PCR_SELECT_MIN;

/// Number of PCR groups that have individual policies.
///
/// The PC Client Platform TPM Profile 1.07 clause 4.2 requires zero, and
/// clause 4.7 item 6 requires every PCR to have an Empty Policy, so there is no
/// group to give a policy of its own.
pub const NUM_POLICY_PCR_GROUP: u16 = 0;
/// Number of PCR groups that have individual authorization values.
///
/// Zero for the same reason: clause 4.7 item 5 requires every PCR to have an
/// Empty Auth.
pub const NUM_AUTHVALUE_PCR_GROUP: u16 = 0;

/// Maximum number of simultaneously loaded transient objects.
pub const MAX_LOADED_OBJECTS: u16 = 32;
/// Maximum number of simultaneously loaded sessions.
pub const MAX_LOADED_SESSIONS: u16 = 32;
/// Maximum number of sessions the TPM tracks, loaded or saved.
pub const MAX_ACTIVE_SESSIONS: u16 = 64;

/// Split ECC operations that may be outstanding at once.
///
/// Part 1 clause 44.2.2 tracks outstanding commits in a bit array whose length
/// is a power of two, and TPM2_GetCapability reports this as
/// TPM_PT_SPLIT_MAX.
pub const MAX_COMMIT_SEQUENCES: u16 = 128;

/// Size of the commit nonce, in octets.
///
/// Clause 44.2.3 asks for twice the security strength of any ECDAA key the TPM
/// supports. The largest curve here is NIST P-521, whose strength is 256 bits,
/// so the nonce is 512 bits.
pub const COMMIT_NONCE_BYTES: usize = 64;

/// The hash used to derive a commit value that has no key behind it.
///
/// TPM2_EC_Ephemeral names no key, so Equation 60 has no nameAlg to take from
/// one. The strongest hash this TPM implements is used instead.
pub const COMMIT_EPHEMERAL_HASH_ALG: u16 = crate::tpm::constants::alg::SHA384;
/// Maximum number of sessions in the authorization area of one command.
pub const MAX_SESSION_NUM: usize = 3;
/// Maximum number of handles in the handle area of one command.
pub const MAX_HANDLE_NUM: usize = 3;
/// Minimum number of persistent objects the TPM guarantees space for.
pub const MIN_EVICT_OBJECTS: u16 = 32;
/// Largest gap allowed between the oldest and newest saved session context.
pub const CONTEXT_GAP_MAX: u32 = u16::MAX as u32;

/// Number of bits in the orderly shutdown counter.
pub const ORDERLY_BITS: u32 = 8;
/// Largest number of increments an orderly counter may take between the NV
/// writes that record its value.
pub const MAX_ORDERLY_COUNT: u64 = (1u64 << ORDERLY_BITS) - 1;
/// Number of clock updates between NV writes of the clock value, in ms.
pub const NV_CLOCK_UPDATE_INTERVAL: u32 = 1 << 17;
/// Largest value TPM2_ClockSet may set.
///
/// Part 3 clause 29.2.1 fails the command when "the new time is greater than
/// FF FF 00 00 00 00 00 00". Part 1 clause 33.3.1 gives the reason: it leaves
/// enough room that Clock cannot roll over in the lifetime of the TPM, so
/// nothing that uses Clock has to allow for it wrapping.
pub const MAX_CLOCK: u64 = 0xFFFF_0000_0000_0000;

/// Size of a primary seed in octets.
pub const PRIMARY_SEED_SIZE: usize = 32;
/// Size of the context encryption and integrity key seed.
pub const CONTEXT_INTEGRITY_HASH_ALG: u16 = alg::SHA256;
/// Symmetric algorithm used to protect saved contexts.
pub const CONTEXT_ENCRYPT_ALG: u16 = alg::AES;
/// Key size, in bits, used to protect saved contexts.
pub const CONTEXT_ENCRYPT_KEY_BITS: u16 = 256;

/// Largest command the TPM accepts, in octets.
pub const MAX_COMMAND_SIZE: u32 = 4096;
/// Largest response the TPM produces, in octets.
pub const MAX_RESPONSE_SIZE: u32 = 4096;
/// Size of the command and response buffer.
pub const MAX_BUFFER_SIZE: usize = 4096;
/// Largest value for TPM2B_MAX_BUFFER.
pub const MAX_DIGEST_BUFFER: usize = 1024;
/// Largest value for TPM2B_MAX_NV_BUFFER.
pub const MAX_NV_BUFFER_SIZE: usize = 1024;
/// Largest NV Index data size.
///
/// The PC Client Platform TPM Profile 1.07 clause 4.2 asks for at least 8500,
/// which is the size of an X.509 endorsement key certificate for an ML-KEM-1024
/// key signed with an ML-DSA-87 key, together with its authorization.
pub const MAX_NV_INDEX_SIZE: usize = 8500;
/// Total NV storage available to Index data and persistent objects.
pub const NV_MEMORY_SIZE: usize = 128 * 1024;
/// Space reserved for orderly (RAM backed) NV Index data.
pub const RAM_INDEX_SPACE: usize = 512;
/// Minimum number of NV counter Indices the TPM guarantees space for.
pub const MIN_COUNTER_INDICES: u32 = 8;
/// Largest capability response payload.
pub const MAX_CAP_BUFFER: usize = 1024;
/// Largest vendor specific buffer.
pub const MAX_VENDOR_BUFFER_SIZE: usize = 1024;
/// Largest saved object context.
pub const MAX_OBJECT_CONTEXT: u32 = 2048;
/// Largest saved session context.
pub const MAX_SESSION_CONTEXT: u32 = 1024;
/// Largest context that is encrypted and saved.
///
/// Part 2 Table 257 sizes this as the larger of the object and session
/// contexts.
pub const MAX_CONTEXT_SIZE: usize = if MAX_OBJECT_CONTEXT > MAX_SESSION_CONTEXT {
    MAX_OBJECT_CONTEXT as usize
} else {
    MAX_SESSION_CONTEXT as usize
};
/// Largest number of octets accepted by TPM2_StirRandom.
pub const MAX_RNG_ENTROPY_SIZE: usize = 64;
/// Largest number of algorithms in a TPML_ALG.
pub const MAX_ALG_LIST_SIZE: usize = 128;
/// Largest number of digests in a TPML_DIGEST_VALUES.
pub const HASH_COUNT: usize = 8;
/// Largest number of digests in a TPML_DIGEST.
pub const MAX_DIGEST_LIST: usize = 8;
/// Largest label accepted for key derivation.
pub const LABEL_MAX_BUFFER: usize = 32;

/// Default RSA public exponent when the template specifies zero.
pub const RSA_DEFAULT_PUBLIC_EXPONENT: u32 = 0x0001_0001;
/// Largest RSA modulus supported, in bits.
pub const MAX_RSA_KEY_BITS: u16 = 4096;
/// Largest symmetric key supported, in bits.
pub const MAX_SYM_KEY_BITS: u16 = 256;
/// Largest symmetric block size, in octets.
pub const MAX_SYM_BLOCK_SIZE: usize = 16;
/// Largest ECC key supported, in bits.
pub const MAX_ECC_KEY_BITS: u16 = 521;
/// Largest ECC key, in octets.
pub const MAX_ECC_KEY_BYTES: usize = 66;

/// Dictionary attack defaults applied on TPM2_Clear.
pub const DEFAULT_MAX_AUTH_FAIL: u32 = 32;
pub const DEFAULT_LOCKOUT_INTERVAL: u32 = 1000;
pub const DEFAULT_LOCKOUT_RECOVERY: u32 = 1000;

// ---------------------------------------------------------------------------
// Vendor identification
// ---------------------------------------------------------------------------

/// TPM_PT_MANUFACTURER, "SWT" as four ASCII octets.
pub const MANUFACTURER: u32 = u32::from_be_bytes(*b"SWT\0");
/// TPM_PT_VENDOR_STRING_1 through _4, "SWT" then padding.
pub const VENDOR_STRING_1: u32 = u32::from_be_bytes(*b"SWT\0");
pub const VENDOR_STRING_2: u32 = 0;
pub const VENDOR_STRING_3: u32 = 0;
pub const VENDOR_STRING_4: u32 = 0;
/// TPM_PT_VENDOR_TPM_TYPE.
///
/// The PC Client Platform TPM Profile 1.07 clause 4.2 gives this the value zero
/// and describes it as reserved and not used.
pub const VENDOR_TPM_TYPE: u32 = 0;

/// TPM_PT_PS_REVISION, the revision of the platform profile this TPM follows.
///
/// The PC Client Platform TPM Profile 1.07 clause 4.2 fixes the format as
/// 0xAABBCCDD, where AA and BB are zero, CC is the major revision of that
/// specification and DD the minor, and requires 0x00000107 for revision 1.07.
/// It is not the revision of the Library specification, which is reported
/// separately as TPM_PT_REVISION.
pub const PS_REVISION: u32 = 0x0000_0107;
/// TPM_PT_FIRMWARE_VERSION_1, major in the high half and minor in the low half.
pub const FIRMWARE_VERSION_1: u32 = 0x0001_0000;
/// TPM_PT_FIRMWARE_VERSION_2, build in the high half and revision in the low half.
pub const FIRMWARE_VERSION_2: u32 = 0x0000_0000;
/// Firmware version rendered as major.minor.build.revision.
pub const FIRMWARE_VERSION_STRING: &str = "1.0.0.0";
/// Manufacturer name rendered as text.
pub const MANUFACTURER_STRING: &str = "SWT";

// ---------------------------------------------------------------------------
// Supported algorithms
// ---------------------------------------------------------------------------

/// Hash algorithms the TPM implements, in the order reported by GetCapability.
///
/// SHA-1 is absent because the PC Client Platform TPM Profile 1.07 clause 4.3
/// Table 3 lists it as Not Allowed.
pub const IMPLEMENTED_HASHES: &[u16] = &[
    alg::SHA256,
    alg::SHA384,
    alg::SHA512,
    alg::SHA3_256,
    alg::SHA3_384,
    alg::SHA3_512,
];

/// PCR banks that are allocated after TPM2_Clear.
/// The PC Client Platform TPM Profile 1.07 clause 4.7 item 3 requires SHA-256
/// and SHA-384, and item 3.a.i requires the required algorithms to be the ones
/// enabled by default.
pub const DEFAULT_PCR_BANKS: &[u16] = &[alg::SHA256, alg::SHA384];

/// PCR banks that may be allocated.
pub const IMPLEMENTED_PCR_BANKS: &[u16] = &[
    alg::SHA256,
    alg::SHA384,
    alg::SHA512,
    alg::SHA3_256,
    alg::SHA3_384,
    alg::SHA3_512,
];

/// ECC curves the TPM implements.
///
/// NIST P-192 is left out because the underlying library does not provide the
/// group. Part 2 leaves the curve set to the implementation and reports it
/// through TPM2_GetCapability(TPM_CAP_ECC_CURVES).
pub const IMPLEMENTED_CURVES: &[u16] = &[
    curve::NIST_P224,
    curve::NIST_P256,
    curve::NIST_P384,
    curve::NIST_P521,
];

/// RSA key sizes the TPM implements, in bits.
///
/// 1024 is absent. The PC Client Platform TPM Profile 1.07 clause 4.3 Table 3
/// requires support for 3072 bit keys and says a TPM "SHALL NOT support
/// 1024-bit keys".
pub const IMPLEMENTED_RSA_KEY_BITS: &[u16] = &[2048, 3072, 4096];

/// AES key sizes the TPM implements, in bits.
pub const IMPLEMENTED_AES_KEY_BITS: &[u16] = &[128, 192, 256];

/// Every algorithm identifier the TPM implements, reported by TPM_CAP_ALGS.
pub const IMPLEMENTED_ALGORITHMS: &[u16] = &[
    alg::RSA,
    alg::HMAC,
    alg::AES,
    alg::MGF1,
    alg::KEYEDHASH,
    alg::XOR,
    alg::SHA256,
    alg::SHA384,
    alg::SHA512,
    alg::NULL,
    alg::RSASSA,
    alg::RSAES,
    alg::RSAPSS,
    alg::OAEP,
    alg::ECDSA,
    alg::ECDH,
    alg::ECDAA,
    alg::ECSCHNORR,
    alg::KDF1_SP800_56A,
    alg::KDF2,
    alg::KDF1_SP800_108,
    alg::ECC,
    alg::SYMCIPHER,
    alg::SHA3_256,
    alg::SHA3_384,
    alg::SHA3_512,
    alg::CTR,
    alg::OFB,
    alg::CBC,
    alg::CFB,
    alg::ECB,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manufacturer_is_swt() {
        assert_eq!(MANUFACTURER, 0x5357_5400);
        assert_eq!(MANUFACTURER.to_be_bytes(), *b"SWT\0");
        assert_eq!(MANUFACTURER_STRING, "SWT");
    }

    #[test]
    fn firmware_version_is_one_zero_zero_zero() {
        let major = FIRMWARE_VERSION_1 >> 16;
        let minor = FIRMWARE_VERSION_1 & 0xffff;
        let build = FIRMWARE_VERSION_2 >> 16;
        let revision = FIRMWARE_VERSION_2 & 0xffff;
        assert_eq!(format!("{major}.{minor}.{build}.{revision}"), "1.0.0.0");
        assert_eq!(FIRMWARE_VERSION_STRING, "1.0.0.0");
    }

    #[test]
    fn pcr_select_size_covers_all_pcr() {
        assert_eq!(PCR_SELECT_MIN, 3);
        assert!(PCR_SELECT_MIN as u16 * 8 >= IMPLEMENTATION_PCR);
    }

    #[test]
    fn algorithm_list_has_no_duplicates() {
        let mut v = IMPLEMENTED_ALGORITHMS.to_vec();
        v.sort_unstable();
        let len = v.len();
        v.dedup();
        assert_eq!(v.len(), len);
    }
}
