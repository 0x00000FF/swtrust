//! Constant values from TPM 2.0 Library Part 2: Structures, version 185.
//!
//! Names follow the specification exactly so tables can be checked against the
//! document. Values are grouped by the table they come from.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Table 6: TPM_SPEC
// ---------------------------------------------------------------------------

/// ASCII "2.0" with a null terminator.
pub const TPM_SPEC_FAMILY: u32 = 0x322E3000;
pub const TPM_SPEC_LEVEL: u32 = 0;
pub const TPM_SPEC_VERSION: u32 = 185;
/// Zero since version 185; the errata level is reported separately.
pub const TPM_SPEC_YEAR: u32 = 0;
pub const TPM_SPEC_ERRATA: u32 = 0;

// ---------------------------------------------------------------------------
// Table 7: TPM_CONSTANTS32
// ---------------------------------------------------------------------------

/// 0xFF 'T' 'C' 'G', marks a structure as TPM generated.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
pub const TPM_MAX_DERIVATION_BITS: u32 = 8192;

// ---------------------------------------------------------------------------
// Table 8: TPM_ALG_ID
// ---------------------------------------------------------------------------

pub mod alg {
    // 0x0000 is reserved by Table 8 and names no algorithm.
    pub const RSA: u16 = 0x0001;
    pub const TDES: u16 = 0x0003;
    pub const SHA1: u16 = 0x0004;
    pub const HMAC: u16 = 0x0005;
    pub const AES: u16 = 0x0006;
    pub const MGF1: u16 = 0x0007;
    pub const KEYEDHASH: u16 = 0x0008;
    pub const XOR: u16 = 0x000A;
    pub const SHA256: u16 = 0x000B;
    pub const SHA384: u16 = 0x000C;
    pub const SHA512: u16 = 0x000D;
    pub const NULL: u16 = 0x0010;
    pub const SM3_256: u16 = 0x0012;
    pub const SM4: u16 = 0x0013;
    pub const RSASSA: u16 = 0x0014;
    pub const RSAES: u16 = 0x0015;
    pub const RSAPSS: u16 = 0x0016;
    pub const OAEP: u16 = 0x0017;
    pub const ECDSA: u16 = 0x0018;
    pub const ECDH: u16 = 0x0019;
    pub const ECDAA: u16 = 0x001A;
    pub const SM2: u16 = 0x001B;
    pub const ECSCHNORR: u16 = 0x001C;
    pub const ECMQV: u16 = 0x001D;
    pub const HKDF: u16 = 0x001F;
    pub const KDF1_SP800_56A: u16 = 0x0020;
    pub const KDF2: u16 = 0x0021;
    pub const KDF1_SP800_108: u16 = 0x0022;
    pub const ECC: u16 = 0x0023;
    pub const SYMCIPHER: u16 = 0x0025;
    pub const CAMELLIA: u16 = 0x0026;
    pub const SHA3_256: u16 = 0x0027;
    pub const SHA3_384: u16 = 0x0028;
    pub const SHA3_512: u16 = 0x0029;
    pub const CMAC: u16 = 0x003F;
    pub const CTR: u16 = 0x0040;
    pub const OFB: u16 = 0x0041;
    pub const CBC: u16 = 0x0042;
    pub const CFB: u16 = 0x0043;
    pub const ECB: u16 = 0x0044;
    pub const EDDSA: u16 = 0x0060;
    pub const HASH_EDDSA: u16 = 0x0061;
    pub const MLKEM: u16 = 0x00A0;
    pub const MLDSA: u16 = 0x00A1;
    pub const HASH_MLDSA: u16 = 0x00A2;
}

// ---------------------------------------------------------------------------
// Table 9: TPM_ECC_CURVE
// ---------------------------------------------------------------------------

pub mod curve {
    pub const NONE: u16 = 0x0000;
    pub const NIST_P192: u16 = 0x0001;
    pub const NIST_P224: u16 = 0x0002;
    pub const NIST_P256: u16 = 0x0003;
    pub const NIST_P384: u16 = 0x0004;
    pub const NIST_P521: u16 = 0x0005;
    pub const BN_P256: u16 = 0x0010;
    pub const BN_P638: u16 = 0x0011;
    pub const SM2_P256: u16 = 0x0020;
    pub const BP_P256_R1: u16 = 0x0030;
    pub const BP_P384_R1: u16 = 0x0031;
    pub const BP_P512_R1: u16 = 0x0032;
    pub const CURVE_25519: u16 = 0x0040;
    pub const CURVE_448: u16 = 0x0041;
}

// ---------------------------------------------------------------------------
// Table 12: TPM_CC
// ---------------------------------------------------------------------------

pub mod cc {
    // Command code names are spelled exactly as Part 2 Table 12 spells them so
    // the table can be checked against the specification line by line.
    #![allow(non_upper_case_globals)]

    pub const FIRST: u32 = 0x0000_011F;
    pub const NV_UndefineSpaceSpecial: u32 = 0x0000_011F;
    pub const EvictControl: u32 = 0x0000_0120;
    pub const HierarchyControl: u32 = 0x0000_0121;
    pub const NV_UndefineSpace: u32 = 0x0000_0122;
    pub const ChangeEPS: u32 = 0x0000_0124;
    pub const ChangePPS: u32 = 0x0000_0125;
    pub const Clear: u32 = 0x0000_0126;
    pub const ClearControl: u32 = 0x0000_0127;
    pub const ClockSet: u32 = 0x0000_0128;
    pub const HierarchyChangeAuth: u32 = 0x0000_0129;
    pub const NV_DefineSpace: u32 = 0x0000_012A;
    pub const PCR_Allocate: u32 = 0x0000_012B;
    pub const PCR_SetAuthPolicy: u32 = 0x0000_012C;
    pub const PP_Commands: u32 = 0x0000_012D;
    pub const SetPrimaryPolicy: u32 = 0x0000_012E;
    pub const FieldUpgradeStart: u32 = 0x0000_012F;
    pub const ClockRateAdjust: u32 = 0x0000_0130;
    pub const CreatePrimary: u32 = 0x0000_0131;
    pub const NV_GlobalWriteLock: u32 = 0x0000_0132;
    pub const GetCommandAuditDigest: u32 = 0x0000_0133;
    pub const NV_Increment: u32 = 0x0000_0134;
    pub const NV_SetBits: u32 = 0x0000_0135;
    pub const NV_Extend: u32 = 0x0000_0136;
    pub const NV_Write: u32 = 0x0000_0137;
    pub const NV_WriteLock: u32 = 0x0000_0138;
    pub const DictionaryAttackLockReset: u32 = 0x0000_0139;
    pub const DictionaryAttackParameters: u32 = 0x0000_013A;
    pub const NV_ChangeAuth: u32 = 0x0000_013B;
    pub const PCR_Event: u32 = 0x0000_013C;
    pub const PCR_Reset: u32 = 0x0000_013D;
    pub const SequenceComplete: u32 = 0x0000_013E;
    pub const SetAlgorithmSet: u32 = 0x0000_013F;
    pub const SetCommandCodeAuditStatus: u32 = 0x0000_0140;
    pub const FieldUpgradeData: u32 = 0x0000_0141;
    pub const IncrementalSelfTest: u32 = 0x0000_0142;
    pub const SelfTest: u32 = 0x0000_0143;
    pub const Startup: u32 = 0x0000_0144;
    pub const Shutdown: u32 = 0x0000_0145;
    pub const StirRandom: u32 = 0x0000_0146;
    pub const ActivateCredential: u32 = 0x0000_0147;
    pub const Certify: u32 = 0x0000_0148;
    pub const PolicyNV: u32 = 0x0000_0149;
    pub const CertifyCreation: u32 = 0x0000_014A;
    pub const Duplicate: u32 = 0x0000_014B;
    pub const GetTime: u32 = 0x0000_014C;
    pub const GetSessionAuditDigest: u32 = 0x0000_014D;
    pub const NV_Read: u32 = 0x0000_014E;
    pub const NV_ReadLock: u32 = 0x0000_014F;
    pub const ObjectChangeAuth: u32 = 0x0000_0150;
    pub const PolicySecret: u32 = 0x0000_0151;
    pub const Rewrap: u32 = 0x0000_0152;
    pub const Create: u32 = 0x0000_0153;
    pub const ECDH_ZGen: u32 = 0x0000_0154;
    /// Also TPM_CC_MAC on a TPM that implements CMAC. This implementation
    /// provides TPM2_HMAC and TPM2_HMAC_Start.
    pub const HMAC: u32 = 0x0000_0155;
    pub const MAC: u32 = 0x0000_0155;
    pub const Import: u32 = 0x0000_0156;
    pub const Load: u32 = 0x0000_0157;
    pub const Quote: u32 = 0x0000_0158;
    pub const RSA_Decrypt: u32 = 0x0000_0159;
    pub const HMAC_Start: u32 = 0x0000_015B;
    pub const MAC_Start: u32 = 0x0000_015B;
    pub const SequenceUpdate: u32 = 0x0000_015C;
    pub const Sign: u32 = 0x0000_015D;
    pub const Unseal: u32 = 0x0000_015E;
    pub const PolicySigned: u32 = 0x0000_0160;
    pub const ContextLoad: u32 = 0x0000_0161;
    pub const ContextSave: u32 = 0x0000_0162;
    pub const ECDH_KeyGen: u32 = 0x0000_0163;
    pub const EncryptDecrypt: u32 = 0x0000_0164;
    pub const FlushContext: u32 = 0x0000_0165;
    pub const LoadExternal: u32 = 0x0000_0167;
    pub const MakeCredential: u32 = 0x0000_0168;
    pub const NV_ReadPublic: u32 = 0x0000_0169;
    pub const PolicyAuthorize: u32 = 0x0000_016A;
    pub const PolicyAuthValue: u32 = 0x0000_016B;
    pub const PolicyCommandCode: u32 = 0x0000_016C;
    pub const PolicyCounterTimer: u32 = 0x0000_016D;
    pub const PolicyCpHash: u32 = 0x0000_016E;
    pub const PolicyLocality: u32 = 0x0000_016F;
    pub const PolicyNameHash: u32 = 0x0000_0170;
    pub const PolicyOR: u32 = 0x0000_0171;
    pub const PolicyTicket: u32 = 0x0000_0172;
    pub const ReadPublic: u32 = 0x0000_0173;
    pub const RSA_Encrypt: u32 = 0x0000_0174;
    pub const StartAuthSession: u32 = 0x0000_0176;
    pub const VerifySignature: u32 = 0x0000_0177;
    pub const ECC_Parameters: u32 = 0x0000_0178;
    pub const FirmwareRead: u32 = 0x0000_0179;
    pub const GetCapability: u32 = 0x0000_017A;
    pub const GetRandom: u32 = 0x0000_017B;
    pub const GetTestResult: u32 = 0x0000_017C;
    pub const Hash: u32 = 0x0000_017D;
    pub const PCR_Read: u32 = 0x0000_017E;
    pub const PolicyPCR: u32 = 0x0000_017F;
    pub const PolicyRestart: u32 = 0x0000_0180;
    pub const ReadClock: u32 = 0x0000_0181;
    pub const PCR_Extend: u32 = 0x0000_0182;
    pub const PCR_SetAuthValue: u32 = 0x0000_0183;
    pub const NV_Certify: u32 = 0x0000_0184;
    pub const EventSequenceComplete: u32 = 0x0000_0185;
    pub const HashSequenceStart: u32 = 0x0000_0186;
    pub const PolicyPhysicalPresence: u32 = 0x0000_0187;
    pub const PolicyDuplicationSelect: u32 = 0x0000_0188;
    pub const PolicyGetDigest: u32 = 0x0000_0189;
    pub const TestParms: u32 = 0x0000_018A;
    pub const Commit: u32 = 0x0000_018B;
    pub const PolicyPassword: u32 = 0x0000_018C;
    pub const ZGen_2Phase: u32 = 0x0000_018D;
    pub const EC_Ephemeral: u32 = 0x0000_018E;
    pub const PolicyNvWritten: u32 = 0x0000_018F;
    pub const PolicyTemplate: u32 = 0x0000_0190;
    pub const CreateLoaded: u32 = 0x0000_0191;
    pub const PolicyAuthorizeNV: u32 = 0x0000_0192;
    pub const EncryptDecrypt2: u32 = 0x0000_0193;
    pub const AC_GetCapability: u32 = 0x0000_0194;
    pub const AC_Send: u32 = 0x0000_0195;
    pub const Policy_AC_SendSelect: u32 = 0x0000_0196;
    pub const CertifyX509: u32 = 0x0000_0197;
    pub const ACT_SetTimeout: u32 = 0x0000_0198;
    pub const ECC_Encrypt: u32 = 0x0000_0199;
    pub const ECC_Decrypt: u32 = 0x0000_019A;
    pub const PolicyCapability: u32 = 0x0000_019B;
    pub const PolicyParameters: u32 = 0x0000_019C;
    pub const NV_DefineSpace2: u32 = 0x0000_019D;
    pub const NV_ReadPublic2: u32 = 0x0000_019E;
    pub const SetCapability: u32 = 0x0000_019F;
    pub const ReadOnlyControl: u32 = 0x0000_01A0;
    pub const PolicyTransportSPDM: u32 = 0x0000_01A1;
    pub const VerifySequenceComplete: u32 = 0x0000_01A3;
    pub const SignSequenceComplete: u32 = 0x0000_01A4;
    pub const VerifyDigestSignature: u32 = 0x0000_01A5;
    pub const SignDigest: u32 = 0x0000_01A6;
    pub const Encapsulate: u32 = 0x0000_01A7;
    pub const Decapsulate: u32 = 0x0000_01A8;
    pub const VerifySequenceStart: u32 = 0x0000_01A9;
    pub const SignSequenceStart: u32 = 0x0000_01AA;
    pub const LAST: u32 = 0x0000_01AA;

    pub const CC_VEND: u32 = 0x2000_0000;
    pub const Vendor_TCG_Test: u32 = CC_VEND;
}

// ---------------------------------------------------------------------------
// Table 18: TPM_RC
// ---------------------------------------------------------------------------

pub mod rc {
    pub const SUCCESS: u32 = 0x000;
    pub const BAD_TAG: u32 = 0x01E;

    /// Set for all format-zero response codes.
    pub const RC_VER1: u32 = 0x100;
    pub const INITIALIZE: u32 = RC_VER1 + 0x000;
    pub const FAILURE: u32 = RC_VER1 + 0x001;
    pub const SEQUENCE: u32 = RC_VER1 + 0x003;
    pub const PRIVATE: u32 = RC_VER1 + 0x00B;
    pub const HMAC: u32 = RC_VER1 + 0x019;
    pub const DISABLED: u32 = RC_VER1 + 0x020;
    pub const EXCLUSIVE: u32 = RC_VER1 + 0x021;
    pub const AUTH_TYPE: u32 = RC_VER1 + 0x024;
    pub const AUTH_MISSING: u32 = RC_VER1 + 0x025;
    pub const POLICY: u32 = RC_VER1 + 0x026;
    pub const PCR: u32 = RC_VER1 + 0x027;
    pub const PCR_CHANGED: u32 = RC_VER1 + 0x028;
    pub const UPGRADE: u32 = RC_VER1 + 0x02D;
    pub const TOO_MANY_CONTEXTS: u32 = RC_VER1 + 0x02E;
    pub const AUTH_UNAVAILABLE: u32 = RC_VER1 + 0x02F;
    pub const REBOOT: u32 = RC_VER1 + 0x030;
    pub const UNBALANCED: u32 = RC_VER1 + 0x031;
    pub const COMMAND_SIZE: u32 = RC_VER1 + 0x042;
    pub const COMMAND_CODE: u32 = RC_VER1 + 0x043;
    pub const AUTHSIZE: u32 = RC_VER1 + 0x044;
    pub const AUTH_CONTEXT: u32 = RC_VER1 + 0x045;
    pub const NV_RANGE: u32 = RC_VER1 + 0x046;
    pub const NV_SIZE: u32 = RC_VER1 + 0x047;
    pub const NV_LOCKED: u32 = RC_VER1 + 0x048;
    pub const NV_AUTHORIZATION: u32 = RC_VER1 + 0x049;
    pub const NV_UNINITIALIZED: u32 = RC_VER1 + 0x04A;
    pub const NV_SPACE: u32 = RC_VER1 + 0x04B;
    pub const NV_DEFINED: u32 = RC_VER1 + 0x04C;
    pub const BAD_CONTEXT: u32 = RC_VER1 + 0x050;
    pub const CPHASH: u32 = RC_VER1 + 0x051;
    pub const PARENT: u32 = RC_VER1 + 0x052;
    pub const NEEDS_TEST: u32 = RC_VER1 + 0x053;
    pub const NO_RESULT: u32 = RC_VER1 + 0x054;
    pub const SENSITIVE: u32 = RC_VER1 + 0x055;
    pub const READ_ONLY: u32 = RC_VER1 + 0x056;
    pub const RC_MAX_FM0: u32 = RC_VER1 + 0x07F;

    /// Set for all format-one response codes.
    pub const RC_FMT1: u32 = 0x080;
    pub const ASYMMETRIC: u32 = RC_FMT1 + 0x001;
    pub const ATTRIBUTES: u32 = RC_FMT1 + 0x002;
    pub const HASH: u32 = RC_FMT1 + 0x003;
    pub const VALUE: u32 = RC_FMT1 + 0x004;
    pub const HIERARCHY: u32 = RC_FMT1 + 0x005;
    pub const KEY_SIZE: u32 = RC_FMT1 + 0x007;
    pub const MGF: u32 = RC_FMT1 + 0x008;
    pub const MODE: u32 = RC_FMT1 + 0x009;
    pub const TYPE: u32 = RC_FMT1 + 0x00A;
    pub const HANDLE: u32 = RC_FMT1 + 0x00B;
    pub const KDF: u32 = RC_FMT1 + 0x00C;
    pub const RANGE: u32 = RC_FMT1 + 0x00D;
    pub const AUTH_FAIL: u32 = RC_FMT1 + 0x00E;
    pub const NONCE: u32 = RC_FMT1 + 0x00F;
    pub const PP: u32 = RC_FMT1 + 0x010;
    pub const SCHEME: u32 = RC_FMT1 + 0x012;
    pub const SIZE: u32 = RC_FMT1 + 0x015;
    pub const SYMMETRIC: u32 = RC_FMT1 + 0x016;
    pub const TAG: u32 = RC_FMT1 + 0x017;
    pub const SELECTOR: u32 = RC_FMT1 + 0x018;
    pub const INSUFFICIENT: u32 = RC_FMT1 + 0x01A;
    pub const SIGNATURE: u32 = RC_FMT1 + 0x01B;
    pub const KEY: u32 = RC_FMT1 + 0x01C;
    pub const POLICY_FAIL: u32 = RC_FMT1 + 0x01D;
    pub const INTEGRITY: u32 = RC_FMT1 + 0x01F;
    pub const TICKET: u32 = RC_FMT1 + 0x020;
    pub const RESERVED_BITS: u32 = RC_FMT1 + 0x021;
    pub const BAD_AUTH: u32 = RC_FMT1 + 0x022;
    pub const EXPIRED: u32 = RC_FMT1 + 0x023;
    pub const POLICY_CC: u32 = RC_FMT1 + 0x024;
    pub const BINDING: u32 = RC_FMT1 + 0x025;
    pub const CURVE: u32 = RC_FMT1 + 0x026;
    pub const ECC_POINT: u32 = RC_FMT1 + 0x027;
    pub const FW_LIMITED: u32 = RC_FMT1 + 0x028;
    pub const SVN_LIMITED: u32 = RC_FMT1 + 0x029;
    pub const PARMS: u32 = RC_FMT1 + 0x02A;
    pub const EXT_MU: u32 = RC_FMT1 + 0x02B;
    pub const ONE_SHOT_SIGNATURE: u32 = RC_FMT1 + 0x02C;
    pub const SIGN_CONTEXT_KEY: u32 = RC_FMT1 + 0x02D;
    pub const CHANNEL: u32 = RC_FMT1 + 0x030;
    pub const CHANNEL_KEY: u32 = RC_FMT1 + 0x031;

    /// Set for all warnings.
    pub const RC_WARN: u32 = 0x900;
    pub const CONTEXT_GAP: u32 = RC_WARN + 0x001;
    pub const OBJECT_MEMORY: u32 = RC_WARN + 0x002;
    pub const SESSION_MEMORY: u32 = RC_WARN + 0x003;
    pub const MEMORY: u32 = RC_WARN + 0x004;
    pub const SESSION_HANDLES: u32 = RC_WARN + 0x005;
    pub const OBJECT_HANDLES: u32 = RC_WARN + 0x006;
    pub const LOCALITY: u32 = RC_WARN + 0x007;
    pub const YIELDED: u32 = RC_WARN + 0x008;
    pub const CANCELED: u32 = RC_WARN + 0x009;
    pub const TESTING: u32 = RC_WARN + 0x00A;
    pub const REFERENCE_H0: u32 = RC_WARN + 0x010;
    pub const REFERENCE_H1: u32 = RC_WARN + 0x011;
    pub const REFERENCE_H2: u32 = RC_WARN + 0x012;
    pub const REFERENCE_H3: u32 = RC_WARN + 0x013;
    pub const REFERENCE_H4: u32 = RC_WARN + 0x014;
    pub const REFERENCE_H5: u32 = RC_WARN + 0x015;
    pub const REFERENCE_H6: u32 = RC_WARN + 0x016;
    pub const REFERENCE_S0: u32 = RC_WARN + 0x018;
    pub const REFERENCE_S1: u32 = RC_WARN + 0x019;
    pub const REFERENCE_S2: u32 = RC_WARN + 0x01A;
    pub const REFERENCE_S3: u32 = RC_WARN + 0x01B;
    pub const REFERENCE_S4: u32 = RC_WARN + 0x01C;
    pub const REFERENCE_S5: u32 = RC_WARN + 0x01D;
    pub const REFERENCE_S6: u32 = RC_WARN + 0x01E;
    pub const NV_RATE: u32 = RC_WARN + 0x020;
    pub const LOCKOUT: u32 = RC_WARN + 0x021;
    pub const RETRY: u32 = RC_WARN + 0x022;
    pub const NV_UNAVAILABLE: u32 = RC_WARN + 0x023;
    pub const NOT_USED: u32 = RC_WARN + 0x07F;

    // Position qualifiers added to format-one codes, Part 2 Table 18.
    pub const H: u32 = 0x000;
    pub const P: u32 = 0x040;
    pub const S: u32 = 0x800;
    pub const N_1: u32 = 0x100;
    pub const N_2: u32 = 0x200;
    pub const N_3: u32 = 0x300;
    pub const N_4: u32 = 0x400;
    pub const N_5: u32 = 0x500;
    pub const N_6: u32 = 0x600;
    pub const N_7: u32 = 0x700;
    pub const N_8: u32 = 0x800;
    pub const N_9: u32 = 0x900;
    pub const N_A: u32 = 0xA00;
    pub const N_B: u32 = 0xB00;
    pub const N_C: u32 = 0xC00;
    pub const N_D: u32 = 0xD00;
    pub const N_E: u32 = 0xE00;
    pub const N_F: u32 = 0xF00;
    pub const N_MASK: u32 = 0xF00;
}

// ---------------------------------------------------------------------------
// Table 19: TPM_CLOCK_ADJUST
// ---------------------------------------------------------------------------

pub mod clock_adjust {
    pub const COARSE_SLOWER: i8 = -3;
    pub const MEDIUM_SLOWER: i8 = -2;
    pub const FINE_SLOWER: i8 = -1;
    pub const NO_CHANGE: i8 = 0;
    pub const FINE_FASTER: i8 = 1;
    pub const MEDIUM_FASTER: i8 = 2;
    pub const COARSE_FASTER: i8 = 3;
}

// ---------------------------------------------------------------------------
// Table 20: TPM_EO
// ---------------------------------------------------------------------------

pub mod eo {
    pub const EQ: u16 = 0x0000;
    pub const NEQ: u16 = 0x0001;
    pub const SIGNED_GT: u16 = 0x0002;
    pub const UNSIGNED_GT: u16 = 0x0003;
    pub const SIGNED_LT: u16 = 0x0004;
    pub const UNSIGNED_LT: u16 = 0x0005;
    pub const SIGNED_GE: u16 = 0x0006;
    pub const UNSIGNED_GE: u16 = 0x0007;
    pub const SIGNED_LE: u16 = 0x0008;
    pub const UNSIGNED_LE: u16 = 0x0009;
    pub const BITSET: u16 = 0x000A;
    pub const BITCLEAR: u16 = 0x000B;
}

// ---------------------------------------------------------------------------
// Table 21: TPM_ST
// ---------------------------------------------------------------------------

pub mod st {
    pub const RSP_COMMAND: u16 = 0x00C4;
    pub const NULL: u16 = 0x8000;
    pub const NO_SESSIONS: u16 = 0x8001;
    pub const SESSIONS: u16 = 0x8002;
    pub const ATTEST_NV: u16 = 0x8014;
    pub const ATTEST_COMMAND_AUDIT: u16 = 0x8015;
    pub const ATTEST_SESSION_AUDIT: u16 = 0x8016;
    pub const ATTEST_CERTIFY: u16 = 0x8017;
    pub const ATTEST_QUOTE: u16 = 0x8018;
    pub const ATTEST_TIME: u16 = 0x8019;
    pub const ATTEST_CREATION: u16 = 0x801A;
    pub const ATTEST_NV_DIGEST: u16 = 0x801C;
    pub const CREATION: u16 = 0x8021;
    pub const VERIFIED: u16 = 0x8022;
    pub const AUTH_SECRET: u16 = 0x8023;
    pub const HASHCHECK: u16 = 0x8024;
    pub const AUTH_SIGNED: u16 = 0x8025;
    pub const MESSAGE_VERIFIED: u16 = 0x8026;
    pub const DIGEST_VERIFIED: u16 = 0x8027;
    pub const FU_MANIFEST: u16 = 0x8029;
}

// ---------------------------------------------------------------------------
// Table 22: TPM_SU, Table 23: TPM_SE
// ---------------------------------------------------------------------------

pub mod su {
    pub const CLEAR: u16 = 0x0000;
    pub const STATE: u16 = 0x0001;
    /// Not a TPM_SU value. It is recorded in place of a shutdown type while
    /// the TPM is running, so a state file reloaded after power was lost
    /// shows that no TPM2_Shutdown arrived.
    pub const NONE: u16 = 0xFFFF;
}

pub mod se {
    pub const HMAC: u8 = 0x00;
    pub const POLICY: u8 = 0x01;
    pub const TRIAL: u8 = 0x03;
}

// ---------------------------------------------------------------------------
// Table 24: TPM_CAP
// ---------------------------------------------------------------------------

pub mod cap {
    pub const FIRST: u32 = 0x0000_0000;
    pub const ALGS: u32 = 0x0000_0000;
    pub const HANDLES: u32 = 0x0000_0001;
    pub const COMMANDS: u32 = 0x0000_0002;
    pub const PP_COMMANDS: u32 = 0x0000_0003;
    pub const AUDIT_COMMANDS: u32 = 0x0000_0004;
    pub const PCRS: u32 = 0x0000_0005;
    pub const TPM_PROPERTIES: u32 = 0x0000_0006;
    pub const PCR_PROPERTIES: u32 = 0x0000_0007;
    pub const ECC_CURVES: u32 = 0x0000_0008;
    pub const AUTH_POLICIES: u32 = 0x0000_0009;
    pub const ACT: u32 = 0x0000_000A;
    pub const PUB_KEYS: u32 = 0x0000_000B;
    pub const SPDM_SESSION_INFO: u32 = 0x0000_000C;
    pub const LAST: u32 = 0x0000_000C;
    pub const VENDOR_PROPERTY: u32 = 0x0000_0100;
}

// ---------------------------------------------------------------------------
// Table 28: TPM_PT
// ---------------------------------------------------------------------------

pub mod pt {
    pub const NONE: u32 = 0x0000_0000;
    pub const PT_GROUP: u32 = 0x0000_0100;
    pub const PT_FIXED: u32 = PT_GROUP;

    pub const FAMILY_INDICATOR: u32 = PT_FIXED + 0;
    pub const LEVEL: u32 = PT_FIXED + 1;
    pub const REVISION: u32 = PT_FIXED + 2;
    /// Named TPM_PT_DAY_OF_YEAR before version 185.
    pub const ERRATA: u32 = PT_FIXED + 3;
    /// Reported the publication year before version 185, now always zero.
    pub const YEAR: u32 = PT_FIXED + 4;
    pub const MANUFACTURER: u32 = PT_FIXED + 5;
    pub const VENDOR_STRING_1: u32 = PT_FIXED + 6;
    pub const VENDOR_STRING_2: u32 = PT_FIXED + 7;
    pub const VENDOR_STRING_3: u32 = PT_FIXED + 8;
    pub const VENDOR_STRING_4: u32 = PT_FIXED + 9;
    pub const VENDOR_TPM_TYPE: u32 = PT_FIXED + 10;
    pub const FIRMWARE_VERSION_1: u32 = PT_FIXED + 11;
    pub const FIRMWARE_VERSION_2: u32 = PT_FIXED + 12;
    pub const INPUT_BUFFER: u32 = PT_FIXED + 13;
    pub const HR_TRANSIENT_MIN: u32 = PT_FIXED + 14;
    pub const HR_PERSISTENT_MIN: u32 = PT_FIXED + 15;
    pub const HR_LOADED_MIN: u32 = PT_FIXED + 16;
    pub const ACTIVE_SESSIONS_MAX: u32 = PT_FIXED + 17;
    pub const PCR_COUNT: u32 = PT_FIXED + 18;
    pub const PCR_SELECT_MIN: u32 = PT_FIXED + 19;
    pub const CONTEXT_GAP_MAX: u32 = PT_FIXED + 20;
    pub const NV_COUNTERS_MAX: u32 = PT_FIXED + 22;
    pub const NV_INDEX_MAX: u32 = PT_FIXED + 23;
    pub const MEMORY: u32 = PT_FIXED + 24;
    pub const CLOCK_UPDATE: u32 = PT_FIXED + 25;
    pub const CONTEXT_HASH: u32 = PT_FIXED + 26;
    pub const CONTEXT_SYM: u32 = PT_FIXED + 27;
    pub const CONTEXT_SYM_SIZE: u32 = PT_FIXED + 28;
    pub const ORDERLY_COUNT: u32 = PT_FIXED + 29;
    pub const MAX_COMMAND_SIZE: u32 = PT_FIXED + 30;
    pub const MAX_RESPONSE_SIZE: u32 = PT_FIXED + 31;
    pub const MAX_DIGEST: u32 = PT_FIXED + 32;
    pub const MAX_OBJECT_CONTEXT: u32 = PT_FIXED + 33;
    pub const MAX_SESSION_CONTEXT: u32 = PT_FIXED + 34;
    pub const PS_FAMILY_INDICATOR: u32 = PT_FIXED + 35;
    pub const PS_LEVEL: u32 = PT_FIXED + 36;
    pub const PS_REVISION: u32 = PT_FIXED + 37;
    pub const PS_DAY_OF_YEAR: u32 = PT_FIXED + 38;
    pub const PS_YEAR: u32 = PT_FIXED + 39;
    pub const SPLIT_MAX: u32 = PT_FIXED + 40;
    pub const TOTAL_COMMANDS: u32 = PT_FIXED + 41;
    pub const LIBRARY_COMMANDS: u32 = PT_FIXED + 42;
    pub const VENDOR_COMMANDS: u32 = PT_FIXED + 43;
    pub const NV_BUFFER_MAX: u32 = PT_FIXED + 44;
    pub const MODES: u32 = PT_FIXED + 45;
    pub const MAX_CAP_BUFFER: u32 = PT_FIXED + 46;
    pub const FIRMWARE_SVN: u32 = PT_FIXED + 47;
    pub const FIRMWARE_MAX_SVN: u32 = PT_FIXED + 48;
    pub const ML_PARAMETER_SETS: u32 = PT_FIXED + 49;

    pub const PT_VAR: u32 = PT_GROUP * 2;
    pub const PERMANENT: u32 = PT_VAR + 0;
    pub const STARTUP_CLEAR: u32 = PT_VAR + 1;
    pub const HR_NV_INDEX: u32 = PT_VAR + 2;
    pub const HR_LOADED: u32 = PT_VAR + 3;
    pub const HR_LOADED_AVAIL: u32 = PT_VAR + 4;
    pub const HR_ACTIVE: u32 = PT_VAR + 5;
    pub const HR_ACTIVE_AVAIL: u32 = PT_VAR + 6;
    pub const HR_TRANSIENT_AVAIL: u32 = PT_VAR + 7;
    pub const HR_PERSISTENT: u32 = PT_VAR + 8;
    pub const HR_PERSISTENT_AVAIL: u32 = PT_VAR + 9;
    pub const NV_COUNTERS: u32 = PT_VAR + 10;
    pub const NV_COUNTERS_AVAIL: u32 = PT_VAR + 11;
    pub const ALGORITHM_SET: u32 = PT_VAR + 12;
    pub const LOADED_CURVES: u32 = PT_VAR + 13;
    pub const LOCKOUT_COUNTER: u32 = PT_VAR + 14;
    pub const MAX_AUTH_FAIL: u32 = PT_VAR + 15;
    pub const LOCKOUT_INTERVAL: u32 = PT_VAR + 16;
    pub const LOCKOUT_RECOVERY: u32 = PT_VAR + 17;
    pub const NV_WRITE_RECOVERY: u32 = PT_VAR + 18;
    pub const AUDIT_COUNTER_0: u32 = PT_VAR + 19;
    pub const AUDIT_COUNTER_1: u32 = PT_VAR + 20;
}

// ---------------------------------------------------------------------------
// Table 29: TPM_PT_PCR
// ---------------------------------------------------------------------------

pub mod pt_pcr {
    pub const FIRST: u32 = 0x0000_0000;
    pub const SAVE: u32 = 0x0000_0000;
    pub const EXTEND_L0: u32 = 0x0000_0001;
    pub const RESET_L0: u32 = 0x0000_0002;
    pub const EXTEND_L1: u32 = 0x0000_0003;
    pub const RESET_L1: u32 = 0x0000_0004;
    pub const EXTEND_L2: u32 = 0x0000_0005;
    pub const RESET_L2: u32 = 0x0000_0006;
    pub const EXTEND_L3: u32 = 0x0000_0007;
    pub const RESET_L3: u32 = 0x0000_0008;
    pub const EXTEND_L4: u32 = 0x0000_0009;
    pub const RESET_L4: u32 = 0x0000_000A;
    pub const NO_INCREMENT: u32 = 0x0000_0011;
    pub const DRTM_RESET: u32 = 0x0000_0012;
    pub const POLICY: u32 = 0x0000_0013;
    pub const AUTH: u32 = 0x0000_0014;
    pub const LAST: u32 = 0x0000_0014;
}

// ---------------------------------------------------------------------------
// Table 30: TPM_PS
// ---------------------------------------------------------------------------

pub mod ps {
    pub const MAIN: u32 = 0x0000_0000;
    pub const PC: u32 = 0x0000_0001;
    pub const PDA: u32 = 0x0000_0002;
    pub const CELL_PHONE: u32 = 0x0000_0003;
    pub const SERVER: u32 = 0x0000_0004;
    pub const PERIPHERAL: u32 = 0x0000_0005;
    pub const TSS: u32 = 0x0000_0006;
    pub const STORAGE: u32 = 0x0000_0007;
    pub const AUTHENTICATION: u32 = 0x0000_0008;
    pub const EMBEDDED: u32 = 0x0000_0009;
    pub const HARDCOPY: u32 = 0x0000_000A;
    pub const INFRASTRUCTURE: u32 = 0x0000_000B;
    pub const VIRTUALIZATION: u32 = 0x0000_000C;
    pub const TNC: u32 = 0x0000_000D;
    pub const MULTI_TENANT: u32 = 0x0000_000E;
    pub const TC: u32 = 0x0000_000F;
}

// ---------------------------------------------------------------------------
// Table 33: TPM_HT
// ---------------------------------------------------------------------------

pub mod ht {
    pub const PCR: u8 = 0x00;
    pub const NV_INDEX: u8 = 0x01;
    pub const HMAC_SESSION: u8 = 0x02;
    pub const LOADED_SESSION: u8 = 0x02;
    pub const POLICY_SESSION: u8 = 0x03;
    pub const SAVED_SESSION: u8 = 0x03;
    pub const EXTERNAL_NV: u8 = 0x11;
    pub const PERMANENT_NV: u8 = 0x12;
    pub const PERMANENT: u8 = 0x40;
    pub const TRANSIENT: u8 = 0x80;
    pub const PERSISTENT: u8 = 0x81;
    pub const AC: u8 = 0x90;
}

// ---------------------------------------------------------------------------
// Table 34: TPM_RH
// ---------------------------------------------------------------------------

pub mod rh {
    pub const FIRST: u32 = 0x4000_0000;
    pub const SRK: u32 = 0x4000_0000;
    pub const OWNER: u32 = 0x4000_0001;
    pub const REVOKE: u32 = 0x4000_0002;
    pub const TRANSPORT: u32 = 0x4000_0003;
    pub const OPERATOR: u32 = 0x4000_0004;
    pub const ADMIN: u32 = 0x4000_0005;
    pub const EK: u32 = 0x4000_0006;
    pub const NULL: u32 = 0x4000_0007;
    pub const UNASSIGNED: u32 = 0x4000_0008;
    /// TPM_RS_PW, the password authorization session handle.
    pub const RS_PW: u32 = 0x4000_0009;
    pub const LOCKOUT: u32 = 0x4000_000A;
    pub const ENDORSEMENT: u32 = 0x4000_000B;
    pub const PLATFORM: u32 = 0x4000_000C;
    pub const PLATFORM_NV: u32 = 0x4000_000D;
    pub const AUTH_00: u32 = 0x4000_0010;
    pub const AUTH_FF: u32 = 0x4000_010F;
    pub const ACT_0: u32 = 0x4000_0110;
    pub const ACT_F: u32 = 0x4000_011F;
    pub const FW_OWNER: u32 = 0x4000_0140;
    pub const FW_ENDORSEMENT: u32 = 0x4000_0141;
    pub const FW_PLATFORM: u32 = 0x4000_0142;
    pub const FW_NULL: u32 = 0x4000_0143;
    pub const SVN_OWNER_BASE: u32 = 0x4001_0000;
    pub const SVN_ENDORSEMENT_BASE: u32 = 0x4002_0000;
    pub const SVN_PLATFORM_BASE: u32 = 0x4003_0000;
    pub const SVN_NULL_BASE: u32 = 0x4004_0000;
    pub const LAST: u32 = 0x4004_FFFF;
}

// ---------------------------------------------------------------------------
// Table 35: TPM_HC
// ---------------------------------------------------------------------------

pub mod hc {
    use super::{ht, rh};
    use crate::tpm::config;

    pub const HR_HANDLE_MASK: u32 = 0x00FF_FFFF;
    pub const HR_RANGE_MASK: u32 = 0xFF00_0000;
    pub const HR_SHIFT: u32 = 24;

    pub const HR_PCR: u32 = (ht::PCR as u32) << HR_SHIFT;
    pub const HR_HMAC_SESSION: u32 = (ht::HMAC_SESSION as u32) << HR_SHIFT;
    pub const HR_POLICY_SESSION: u32 = (ht::POLICY_SESSION as u32) << HR_SHIFT;
    pub const HR_TRANSIENT: u32 = (ht::TRANSIENT as u32) << HR_SHIFT;
    pub const HR_PERSISTENT: u32 = (ht::PERSISTENT as u32) << HR_SHIFT;
    pub const HR_NV_INDEX: u32 = (ht::NV_INDEX as u32) << HR_SHIFT;
    pub const HR_EXTERNAL_NV: u32 = (ht::EXTERNAL_NV as u32) << HR_SHIFT;
    pub const HR_PERMANENT_NV: u32 = (ht::PERMANENT_NV as u32) << HR_SHIFT;
    pub const HR_PERMANENT: u32 = (ht::PERMANENT as u32) << HR_SHIFT;

    pub const PCR_FIRST: u32 = HR_PCR;
    pub const PCR_LAST: u32 = PCR_FIRST + config::IMPLEMENTATION_PCR as u32 - 1;
    pub const HMAC_SESSION_FIRST: u32 = HR_HMAC_SESSION;
    pub const HMAC_SESSION_LAST: u32 = HMAC_SESSION_FIRST + config::MAX_ACTIVE_SESSIONS as u32 - 1;
    pub const LOADED_SESSION_FIRST: u32 = HMAC_SESSION_FIRST;
    pub const LOADED_SESSION_LAST: u32 = HMAC_SESSION_LAST;
    pub const POLICY_SESSION_FIRST: u32 = HR_POLICY_SESSION;
    pub const POLICY_SESSION_LAST: u32 =
        POLICY_SESSION_FIRST + config::MAX_ACTIVE_SESSIONS as u32 - 1;
    pub const ACTIVE_SESSION_FIRST: u32 = POLICY_SESSION_FIRST;
    pub const ACTIVE_SESSION_LAST: u32 = POLICY_SESSION_LAST;
    pub const TRANSIENT_FIRST: u32 = HR_TRANSIENT;
    pub const TRANSIENT_LAST: u32 = TRANSIENT_FIRST + config::MAX_LOADED_OBJECTS as u32 - 1;
    pub const PERSISTENT_FIRST: u32 = HR_PERSISTENT;
    pub const PERSISTENT_LAST: u32 = PERSISTENT_FIRST + 0x00FF_FFFF;
    pub const PLATFORM_PERSISTENT: u32 = PERSISTENT_FIRST + 0x0080_0000;
    pub const NV_INDEX_FIRST: u32 = HR_NV_INDEX;
    pub const NV_INDEX_LAST: u32 = NV_INDEX_FIRST + 0x00FF_FFFF;
    pub const EXTERNAL_NV_FIRST: u32 = HR_EXTERNAL_NV;
    pub const EXTERNAL_NV_LAST: u32 = EXTERNAL_NV_FIRST + 0x00FF_FFFF;
    pub const PERMANENT_NV_FIRST: u32 = HR_PERMANENT_NV;
    pub const PERMANENT_NV_LAST: u32 = PERMANENT_NV_FIRST + 0x00FF_FFFF;
    pub const PERMANENT_FIRST: u32 = rh::FIRST;
    pub const PERMANENT_LAST: u32 = rh::LAST;
    pub const SVN_OWNER_FIRST: u32 = rh::SVN_OWNER_BASE;
    pub const SVN_OWNER_LAST: u32 = rh::SVN_OWNER_BASE + 0xFFFF;
    pub const SVN_ENDORSEMENT_FIRST: u32 = rh::SVN_ENDORSEMENT_BASE;
    pub const SVN_ENDORSEMENT_LAST: u32 = rh::SVN_ENDORSEMENT_BASE + 0xFFFF;
    pub const SVN_PLATFORM_FIRST: u32 = rh::SVN_PLATFORM_BASE;
    pub const SVN_PLATFORM_LAST: u32 = rh::SVN_PLATFORM_BASE + 0xFFFF;
    pub const SVN_NULL_FIRST: u32 = rh::SVN_NULL_BASE;
    pub const SVN_NULL_LAST: u32 = rh::SVN_NULL_BASE + 0xFFFF;
    pub const HR_NV_AC: u32 = HR_NV_INDEX + 0x00D0_0000;
    pub const NV_AC_FIRST: u32 = HR_NV_AC;
    pub const NV_AC_LAST: u32 = HR_NV_AC + 0x0000_FFFF;
    pub const HR_AC: u32 = (ht::AC as u32) << HR_SHIFT;
    pub const AC_FIRST: u32 = HR_AC;
    pub const AC_LAST: u32 = HR_AC + 0x0000_FFFF;
}

/// Map a command code to the specification name of the command, for logging.
pub fn cc_name(code: u32) -> Option<&'static str> {
    let name = match code {
        cc::NV_UndefineSpaceSpecial => "TPM2_NV_UndefineSpaceSpecial",
        cc::EvictControl => "TPM2_EvictControl",
        cc::HierarchyControl => "TPM2_HierarchyControl",
        cc::NV_UndefineSpace => "TPM2_NV_UndefineSpace",
        cc::ChangeEPS => "TPM2_ChangeEPS",
        cc::ChangePPS => "TPM2_ChangePPS",
        cc::Clear => "TPM2_Clear",
        cc::ClearControl => "TPM2_ClearControl",
        cc::ClockSet => "TPM2_ClockSet",
        cc::HierarchyChangeAuth => "TPM2_HierarchyChangeAuth",
        cc::NV_DefineSpace => "TPM2_NV_DefineSpace",
        cc::PCR_Allocate => "TPM2_PCR_Allocate",
        cc::PCR_SetAuthPolicy => "TPM2_PCR_SetAuthPolicy",
        cc::PP_Commands => "TPM2_PP_Commands",
        cc::SetPrimaryPolicy => "TPM2_SetPrimaryPolicy",
        cc::FieldUpgradeStart => "TPM2_FieldUpgradeStart",
        cc::ClockRateAdjust => "TPM2_ClockRateAdjust",
        cc::CreatePrimary => "TPM2_CreatePrimary",
        cc::NV_GlobalWriteLock => "TPM2_NV_GlobalWriteLock",
        cc::GetCommandAuditDigest => "TPM2_GetCommandAuditDigest",
        cc::NV_Increment => "TPM2_NV_Increment",
        cc::NV_SetBits => "TPM2_NV_SetBits",
        cc::NV_Extend => "TPM2_NV_Extend",
        cc::NV_Write => "TPM2_NV_Write",
        cc::NV_WriteLock => "TPM2_NV_WriteLock",
        cc::DictionaryAttackLockReset => "TPM2_DictionaryAttackLockReset",
        cc::DictionaryAttackParameters => "TPM2_DictionaryAttackParameters",
        cc::NV_ChangeAuth => "TPM2_NV_ChangeAuth",
        cc::PCR_Event => "TPM2_PCR_Event",
        cc::PCR_Reset => "TPM2_PCR_Reset",
        cc::SequenceComplete => "TPM2_SequenceComplete",
        cc::SetAlgorithmSet => "TPM2_SetAlgorithmSet",
        cc::SetCommandCodeAuditStatus => "TPM2_SetCommandCodeAuditStatus",
        cc::FieldUpgradeData => "TPM2_FieldUpgradeData",
        cc::IncrementalSelfTest => "TPM2_IncrementalSelfTest",
        cc::SelfTest => "TPM2_SelfTest",
        cc::Startup => "TPM2_Startup",
        cc::Shutdown => "TPM2_Shutdown",
        cc::StirRandom => "TPM2_StirRandom",
        cc::ActivateCredential => "TPM2_ActivateCredential",
        cc::Certify => "TPM2_Certify",
        cc::PolicyNV => "TPM2_PolicyNV",
        cc::CertifyCreation => "TPM2_CertifyCreation",
        cc::Duplicate => "TPM2_Duplicate",
        cc::GetTime => "TPM2_GetTime",
        cc::GetSessionAuditDigest => "TPM2_GetSessionAuditDigest",
        cc::NV_Read => "TPM2_NV_Read",
        cc::NV_ReadLock => "TPM2_NV_ReadLock",
        cc::ObjectChangeAuth => "TPM2_ObjectChangeAuth",
        cc::PolicySecret => "TPM2_PolicySecret",
        cc::Rewrap => "TPM2_Rewrap",
        cc::Create => "TPM2_Create",
        cc::ECDH_ZGen => "TPM2_ECDH_ZGen",
        cc::HMAC => "TPM2_HMAC",
        cc::Import => "TPM2_Import",
        cc::Load => "TPM2_Load",
        cc::Quote => "TPM2_Quote",
        cc::RSA_Decrypt => "TPM2_RSA_Decrypt",
        cc::HMAC_Start => "TPM2_HMAC_Start",
        cc::SequenceUpdate => "TPM2_SequenceUpdate",
        cc::Sign => "TPM2_Sign",
        cc::Unseal => "TPM2_Unseal",
        cc::PolicySigned => "TPM2_PolicySigned",
        cc::ContextLoad => "TPM2_ContextLoad",
        cc::ContextSave => "TPM2_ContextSave",
        cc::ECDH_KeyGen => "TPM2_ECDH_KeyGen",
        cc::EncryptDecrypt => "TPM2_EncryptDecrypt",
        cc::FlushContext => "TPM2_FlushContext",
        cc::LoadExternal => "TPM2_LoadExternal",
        cc::MakeCredential => "TPM2_MakeCredential",
        cc::NV_ReadPublic => "TPM2_NV_ReadPublic",
        cc::PolicyAuthorize => "TPM2_PolicyAuthorize",
        cc::PolicyAuthValue => "TPM2_PolicyAuthValue",
        cc::PolicyCommandCode => "TPM2_PolicyCommandCode",
        cc::PolicyCounterTimer => "TPM2_PolicyCounterTimer",
        cc::PolicyCpHash => "TPM2_PolicyCpHash",
        cc::PolicyLocality => "TPM2_PolicyLocality",
        cc::PolicyNameHash => "TPM2_PolicyNameHash",
        cc::PolicyOR => "TPM2_PolicyOR",
        cc::PolicyTicket => "TPM2_PolicyTicket",
        cc::ReadPublic => "TPM2_ReadPublic",
        cc::RSA_Encrypt => "TPM2_RSA_Encrypt",
        cc::StartAuthSession => "TPM2_StartAuthSession",
        cc::VerifySignature => "TPM2_VerifySignature",
        cc::ECC_Parameters => "TPM2_ECC_Parameters",
        cc::FirmwareRead => "TPM2_FirmwareRead",
        cc::GetCapability => "TPM2_GetCapability",
        cc::GetRandom => "TPM2_GetRandom",
        cc::GetTestResult => "TPM2_GetTestResult",
        cc::Hash => "TPM2_Hash",
        cc::PCR_Read => "TPM2_PCR_Read",
        cc::PolicyPCR => "TPM2_PolicyPCR",
        cc::PolicyRestart => "TPM2_PolicyRestart",
        cc::ReadClock => "TPM2_ReadClock",
        cc::PCR_Extend => "TPM2_PCR_Extend",
        cc::PCR_SetAuthValue => "TPM2_PCR_SetAuthValue",
        cc::NV_Certify => "TPM2_NV_Certify",
        cc::EventSequenceComplete => "TPM2_EventSequenceComplete",
        cc::HashSequenceStart => "TPM2_HashSequenceStart",
        cc::PolicyPhysicalPresence => "TPM2_PolicyPhysicalPresence",
        cc::PolicyDuplicationSelect => "TPM2_PolicyDuplicationSelect",
        cc::PolicyGetDigest => "TPM2_PolicyGetDigest",
        cc::TestParms => "TPM2_TestParms",
        cc::Commit => "TPM2_Commit",
        cc::PolicyPassword => "TPM2_PolicyPassword",
        cc::ZGen_2Phase => "TPM2_ZGen_2Phase",
        cc::EC_Ephemeral => "TPM2_EC_Ephemeral",
        cc::PolicyNvWritten => "TPM2_PolicyNvWritten",
        cc::PolicyTemplate => "TPM2_PolicyTemplate",
        cc::CreateLoaded => "TPM2_CreateLoaded",
        cc::PolicyAuthorizeNV => "TPM2_PolicyAuthorizeNV",
        cc::EncryptDecrypt2 => "TPM2_EncryptDecrypt2",
        cc::AC_GetCapability => "TPM2_AC_GetCapability",
        cc::AC_Send => "TPM2_AC_Send",
        cc::Policy_AC_SendSelect => "TPM2_Policy_AC_SendSelect",
        cc::CertifyX509 => "TPM2_CertifyX509",
        cc::ACT_SetTimeout => "TPM2_ACT_SetTimeout",
        cc::ECC_Encrypt => "TPM2_ECC_Encrypt",
        cc::ECC_Decrypt => "TPM2_ECC_Decrypt",
        cc::PolicyCapability => "TPM2_PolicyCapability",
        cc::PolicyParameters => "TPM2_PolicyParameters",
        cc::NV_DefineSpace2 => "TPM2_NV_DefineSpace2",
        cc::NV_ReadPublic2 => "TPM2_NV_ReadPublic2",
        cc::SetCapability => "TPM2_SetCapability",
        cc::ReadOnlyControl => "TPM2_ReadOnlyControl",
        cc::PolicyTransportSPDM => "TPM2_PolicyTransportSPDM",
        cc::VerifySequenceComplete => "TPM2_VerifySequenceComplete",
        cc::SignSequenceComplete => "TPM2_SignSequenceComplete",
        cc::VerifyDigestSignature => "TPM2_VerifyDigestSignature",
        cc::SignDigest => "TPM2_SignDigest",
        cc::Encapsulate => "TPM2_Encapsulate",
        cc::Decapsulate => "TPM2_Decapsulate",
        cc::VerifySequenceStart => "TPM2_VerifySequenceStart",
        cc::SignSequenceStart => "TPM2_SignSequenceStart",
        cc::Vendor_TCG_Test => "TPM2_Vendor_TCG_Test",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_code_groups() {
        // Format-zero codes derive from RC_VER1.
        assert_eq!(rc::INITIALIZE, 0x100);
        assert_eq!(rc::FAILURE, 0x101);
        assert_eq!(rc::READ_ONLY, 0x156);
        assert_eq!(rc::RC_MAX_FM0, 0x17F);
        // Format-one codes derive from RC_FMT1.
        assert_eq!(rc::ASYMMETRIC, 0x081);
        assert_eq!(rc::VALUE, 0x084);
        assert_eq!(rc::CHANNEL_KEY, 0x0B1);
        // Warnings derive from RC_WARN.
        assert_eq!(rc::CONTEXT_GAP, 0x901);
        assert_eq!(rc::NOT_USED, 0x97F);
    }

    #[test]
    fn handle_ranges_follow_table_35() {
        assert_eq!(hc::HR_PCR, 0x0000_0000);
        assert_eq!(hc::HR_NV_INDEX, 0x0100_0000);
        assert_eq!(hc::HR_HMAC_SESSION, 0x0200_0000);
        assert_eq!(hc::HR_POLICY_SESSION, 0x0300_0000);
        assert_eq!(hc::HR_PERMANENT, 0x4000_0000);
        assert_eq!(hc::HR_TRANSIENT, 0x8000_0000);
        assert_eq!(hc::HR_PERSISTENT, 0x8100_0000);
        assert_eq!(hc::PERSISTENT_LAST, 0x81FF_FFFF);
        assert_eq!(hc::PLATFORM_PERSISTENT, 0x8180_0000);
        assert_eq!(hc::NV_INDEX_LAST, 0x01FF_FFFF);
        assert_eq!(hc::HR_NV_AC, 0x01D0_0000);
        assert_eq!(hc::HR_AC, 0x9000_0000);
    }

    /// Every code between TPM_CC_FIRST and TPM_CC_LAST that Part 2 Table 12
    /// leaves unassigned. Everything else in the range must have a name.
    const UNASSIGNED_COMMAND_CODES: &[u32] = &[
        0x0000_0123,
        0x0000_015A,
        0x0000_015F,
        0x0000_0166,
        0x0000_0175,
        0x0000_01A2,
    ];

    #[test]
    fn every_assigned_command_code_has_a_name() {
        for code in cc::FIRST..=cc::LAST {
            let named = cc_name(code).is_some();
            let unassigned = UNASSIGNED_COMMAND_CODES.contains(&code);
            assert_eq!(
                named, !unassigned,
                "0x{code:08x} named={named} unassigned={unassigned}"
            );
        }
        assert!(cc_name(cc::FIRST - 1).is_none());
        assert!(cc_name(cc::LAST + 1).is_none());
        // The vendor test command sits outside the library range.
        assert_eq!(cc_name(cc::Vendor_TCG_Test), Some("TPM2_Vendor_TCG_Test"));
    }

    #[test]
    fn command_names_are_unique() {
        let mut names: Vec<&str> = (cc::FIRST..=cc::LAST).filter_map(cc_name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate command name");
    }

    #[test]
    fn command_code_count_matches_the_table() {
        // Table 12 assigns 134 command codes between TPM_CC_FIRST and
        // TPM_CC_LAST, two of which share a code with a MAC variant.
        let assigned = (cc::FIRST..=cc::LAST).filter(|c| cc_name(*c).is_some()).count();
        let range = (cc::LAST - cc::FIRST + 1) as usize;
        assert_eq!(assigned, range - UNASSIGNED_COMMAND_CODES.len());
    }

    #[test]
    fn algorithm_identifiers() {
        assert_eq!(alg::RSA, 0x0001);
        assert_eq!(alg::SHA256, 0x000B);
        assert_eq!(alg::NULL, 0x0010);
        assert_eq!(alg::ECC, 0x0023);
        assert_eq!(alg::CFB, 0x0043);
    }

    #[test]
    fn property_groups() {
        assert_eq!(pt::FAMILY_INDICATOR, 0x100);
        assert_eq!(pt::MANUFACTURER, 0x105);
        assert_eq!(pt::PERMANENT, 0x200);
        assert_eq!(pt::AUDIT_COUNTER_1, 0x214);
    }
}
