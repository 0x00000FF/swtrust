//! The command table.
//!
//! For every command Part 3 defines, this records how many handles are in the
//! handle area, how many of those need authorization, whether the response has
//! a handle, and the TPMA_CC flags reported by
//! TPM2_GetCapability(TPM_CAP_COMMANDS).

use crate::tpm::constants::cc;
use crate::tpm::structures::attributes::CommandAttributes;

/// What the dispatcher needs to know about one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandInfo {
    pub code: u32,
    /// Handles in the command handle area.
    pub handles: u8,
    /// Leading handles that carry an authorization.
    pub auth_handles: u8,
    /// True when the response starts with a handle.
    pub response_handle: bool,
    /// True when the command may write to NV.
    pub nv: bool,
    /// True when the command may remove many objects or Indices.
    pub extensive: bool,
    /// True when the command flushes the handle it was given.
    pub flushed: bool,
}

impl CommandInfo {
    const fn new(
        code: u32,
        handles: u8,
        auth_handles: u8,
        response_handle: bool,
        nv: bool,
        extensive: bool,
        flushed: bool,
    ) -> CommandInfo {
        CommandInfo {
            code,
            handles,
            auth_handles,
            response_handle,
            nv,
            extensive,
            flushed,
        }
    }

    /// The TPMA_CC this command reports.
    pub fn attributes(&self) -> CommandAttributes {
        let mut flags = 0u32;
        if self.nv {
            flags |= CommandAttributes::NV;
        }
        if self.extensive {
            flags |= CommandAttributes::EXTENSIVE;
        }
        if self.flushed {
            flags |= CommandAttributes::FLUSHED;
        }
        if self.response_handle {
            flags |= CommandAttributes::R_HANDLE;
        }
        CommandAttributes::build(self.code as u16, self.handles, flags)
    }
}

/// Shorthand for a command with no NV write and no response handle.
const fn plain(code: u32, handles: u8, auth: u8) -> CommandInfo {
    CommandInfo::new(code, handles, auth, false, false, false, false)
}

/// Shorthand for a command that writes NV.
const fn nv(code: u32, handles: u8, auth: u8) -> CommandInfo {
    CommandInfo::new(code, handles, auth, false, true, false, false)
}

/// Shorthand for a command that returns a handle.
const fn rhandle(code: u32, handles: u8, auth: u8) -> CommandInfo {
    CommandInfo::new(code, handles, auth, true, false, false, false)
}

/// Shorthand for a command that returns a handle and writes NV.
const fn rhandle_nv(code: u32, handles: u8, auth: u8) -> CommandInfo {
    CommandInfo::new(code, handles, auth, true, true, false, false)
}

/// Every command this TPM implements, in command code order.
pub const COMMANDS: &[CommandInfo] = &[
    nv(cc::NV_UndefineSpaceSpecial, 2, 2),
    nv(cc::EvictControl, 2, 1),
    nv(cc::HierarchyControl, 1, 1),
    nv(cc::NV_UndefineSpace, 2, 1),
    CommandInfo::new(cc::ChangeEPS, 1, 1, false, true, true, false),
    CommandInfo::new(cc::ChangePPS, 1, 1, false, true, true, false),
    CommandInfo::new(cc::Clear, 1, 1, false, true, true, false),
    nv(cc::ClearControl, 1, 1),
    nv(cc::ClockSet, 1, 1),
    nv(cc::HierarchyChangeAuth, 1, 1),
    nv(cc::NV_DefineSpace, 1, 1),
    nv(cc::PCR_Allocate, 1, 1),
    nv(cc::PCR_SetAuthPolicy, 1, 1),
    nv(cc::PP_Commands, 1, 1),
    nv(cc::SetPrimaryPolicy, 1, 1),
    nv(cc::FieldUpgradeStart, 2, 1),
    nv(cc::ClockRateAdjust, 1, 1),
    rhandle_nv(cc::CreatePrimary, 1, 1),
    nv(cc::NV_GlobalWriteLock, 1, 1),
    plain(cc::GetCommandAuditDigest, 2, 2),
    nv(cc::NV_Increment, 2, 1),
    nv(cc::NV_SetBits, 2, 1),
    nv(cc::NV_Extend, 2, 1),
    nv(cc::NV_Write, 2, 1),
    nv(cc::NV_WriteLock, 2, 1),
    nv(cc::DictionaryAttackLockReset, 1, 1),
    nv(cc::DictionaryAttackParameters, 1, 1),
    nv(cc::NV_ChangeAuth, 1, 1),
    nv(cc::PCR_Event, 1, 1),
    nv(cc::PCR_Reset, 1, 1),
    CommandInfo::new(cc::SequenceComplete, 1, 1, false, false, false, true),
    nv(cc::SetAlgorithmSet, 1, 1),
    nv(cc::SetCommandCodeAuditStatus, 1, 1),
    nv(cc::FieldUpgradeData, 0, 0),
    plain(cc::IncrementalSelfTest, 0, 0),
    plain(cc::SelfTest, 0, 0),
    plain(cc::Startup, 0, 0),
    nv(cc::Shutdown, 0, 0),
    plain(cc::StirRandom, 0, 0),
    plain(cc::ActivateCredential, 2, 2),
    plain(cc::Certify, 2, 2),
    plain(cc::PolicyNV, 3, 1),
    plain(cc::CertifyCreation, 2, 1),
    plain(cc::Duplicate, 2, 1),
    plain(cc::GetTime, 2, 2),
    plain(cc::GetSessionAuditDigest, 3, 2),
    plain(cc::NV_Read, 2, 1),
    nv(cc::NV_ReadLock, 2, 1),
    plain(cc::ObjectChangeAuth, 2, 1),
    plain(cc::PolicySecret, 2, 1),
    plain(cc::Rewrap, 2, 1),
    plain(cc::Create, 1, 1),
    plain(cc::ECDH_ZGen, 1, 1),
    plain(cc::HMAC, 1, 1),
    plain(cc::Import, 1, 1),
    rhandle(cc::Load, 1, 1),
    plain(cc::Quote, 1, 1),
    plain(cc::RSA_Decrypt, 1, 1),
    rhandle(cc::HMAC_Start, 1, 1),
    plain(cc::SequenceUpdate, 1, 1),
    plain(cc::Sign, 1, 1),
    plain(cc::Unseal, 1, 1),
    plain(cc::PolicySigned, 2, 0),
    rhandle(cc::ContextLoad, 0, 0),
    plain(cc::ContextSave, 1, 0),
    plain(cc::ECDH_KeyGen, 1, 0),
    plain(cc::EncryptDecrypt, 1, 1),
    CommandInfo::new(cc::FlushContext, 0, 0, false, false, false, false),
    rhandle(cc::LoadExternal, 0, 0),
    plain(cc::MakeCredential, 1, 0),
    plain(cc::NV_ReadPublic, 1, 0),
    plain(cc::PolicyAuthorize, 1, 0),
    plain(cc::PolicyAuthValue, 1, 0),
    plain(cc::PolicyCommandCode, 1, 0),
    plain(cc::PolicyCounterTimer, 1, 0),
    plain(cc::PolicyCpHash, 1, 0),
    plain(cc::PolicyLocality, 1, 0),
    plain(cc::PolicyNameHash, 1, 0),
    plain(cc::PolicyOR, 1, 0),
    plain(cc::PolicyTicket, 1, 0),
    plain(cc::ReadPublic, 1, 0),
    plain(cc::RSA_Encrypt, 1, 0),
    rhandle(cc::StartAuthSession, 2, 0),
    plain(cc::VerifySignature, 1, 0),
    plain(cc::ECC_Parameters, 0, 0),
    plain(cc::FirmwareRead, 0, 0),
    plain(cc::GetCapability, 0, 0),
    plain(cc::GetRandom, 0, 0),
    plain(cc::GetTestResult, 0, 0),
    plain(cc::Hash, 0, 0),
    plain(cc::PCR_Read, 0, 0),
    plain(cc::PolicyPCR, 1, 0),
    plain(cc::PolicyRestart, 1, 0),
    plain(cc::ReadClock, 0, 0),
    nv(cc::PCR_Extend, 1, 1),
    nv(cc::PCR_SetAuthValue, 1, 1),
    plain(cc::NV_Certify, 3, 2),
    CommandInfo::new(cc::EventSequenceComplete, 2, 2, false, true, false, true),
    rhandle(cc::HashSequenceStart, 0, 0),
    plain(cc::PolicyPhysicalPresence, 1, 0),
    plain(cc::PolicyDuplicationSelect, 1, 0),
    plain(cc::PolicyGetDigest, 1, 0),
    plain(cc::TestParms, 0, 0),
    plain(cc::Commit, 1, 1),
    plain(cc::PolicyPassword, 1, 0),
    plain(cc::ZGen_2Phase, 1, 1),
    plain(cc::EC_Ephemeral, 0, 0),
    plain(cc::PolicyNvWritten, 1, 0),
    plain(cc::PolicyTemplate, 1, 0),
    rhandle_nv(cc::CreateLoaded, 1, 1),
    plain(cc::PolicyAuthorizeNV, 3, 1),
    plain(cc::EncryptDecrypt2, 1, 1),
    plain(cc::AC_GetCapability, 1, 0),
    plain(cc::AC_Send, 3, 2),
    plain(cc::Policy_AC_SendSelect, 1, 0),
    plain(cc::CertifyX509, 2, 2),
    nv(cc::ACT_SetTimeout, 1, 1),
    plain(cc::ECC_Encrypt, 1, 0),
    plain(cc::ECC_Decrypt, 1, 1),
    plain(cc::PolicyCapability, 1, 0),
    plain(cc::PolicyParameters, 1, 0),
    nv(cc::NV_DefineSpace2, 1, 1),
    plain(cc::NV_ReadPublic2, 1, 0),
    nv(cc::SetCapability, 1, 1),
    nv(cc::ReadOnlyControl, 1, 1),
    plain(cc::PolicyTransportSPDM, 1, 0),
    // Part 3 Table 118 authorizes the sequence but not the verification key.
    CommandInfo::new(cc::VerifySequenceComplete, 2, 1, false, false, false, true),
    CommandInfo::new(cc::SignSequenceComplete, 2, 2, false, false, false, true),
    plain(cc::VerifyDigestSignature, 1, 0),
    plain(cc::SignDigest, 1, 1),
    plain(cc::Encapsulate, 1, 0),
    plain(cc::Decapsulate, 1, 1),
    // Part 3 Tables 87 and 89 give the key handle no authorization; the
    // sequence takes its own value from the auth parameter.
    rhandle(cc::VerifySequenceStart, 1, 0),
    rhandle(cc::SignSequenceStart, 1, 0),
    plain(cc::Vendor_TCG_Test, 0, 0),
];

/// Look up a command, or `None` when the code is not implemented.
pub fn lookup(code: u32) -> Option<&'static CommandInfo> {
    COMMANDS.iter().find(|c| c.code == code)
}

/// Every implemented command code, in increasing order.
pub fn implemented_codes() -> Vec<u32> {
    let mut v: Vec<u32> = COMMANDS.iter().map(|c| c.code).collect();
    v.sort_unstable();
    v
}

/// Number of library commands implemented.
pub fn library_command_count() -> usize {
    COMMANDS
        .iter()
        .filter(|c| c.code < cc::CC_VEND)
        .count()
}

/// Number of vendor commands implemented.
pub fn vendor_command_count() -> usize {
    COMMANDS
        .iter()
        .filter(|c| c.code >= cc::CC_VEND)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::config;
    use crate::tpm::constants::cc_name;

    #[test]
    fn every_named_command_is_in_the_table() {
        for code in cc::FIRST..=cc::LAST {
            if cc_name(code).is_none() {
                continue;
            }
            assert!(
                lookup(code).is_some(),
                "missing table entry for 0x{code:08x} ({})",
                cc_name(code).unwrap()
            );
        }
    }

    #[test]
    fn the_table_has_no_duplicates() {
        let codes = implemented_codes();
        let mut deduped = codes.clone();
        deduped.dedup();
        assert_eq!(codes.len(), deduped.len());
    }

    #[test]
    fn every_table_entry_names_a_real_command() {
        for info in COMMANDS {
            assert!(
                cc_name(info.code).is_some(),
                "0x{:08x} is not a command code",
                info.code
            );
        }
    }

    #[test]
    fn handle_counts_are_within_the_limits() {
        for info in COMMANDS {
            assert!(
                info.handles as usize <= config::MAX_HANDLE_NUM,
                "{} has {} handles",
                cc_name(info.code).unwrap(),
                info.handles
            );
            assert!(
                info.auth_handles <= info.handles,
                "{} authorizes more handles than it takes",
                cc_name(info.code).unwrap()
            );
        }
    }

    #[test]
    fn attributes_carry_the_index_and_handle_count() {
        let info = lookup(cc::Create).unwrap();
        let a = info.attributes();
        assert_eq!(a.command_index(), 0x0153);
        assert_eq!(a.handles(), 1);
        assert!(a.has(CommandAttributes::NV) == info.nv);

        let info = lookup(cc::CreatePrimary).unwrap();
        assert!(info.attributes().has(CommandAttributes::R_HANDLE));
        assert!(info.attributes().has(CommandAttributes::NV));

        let info = lookup(cc::Clear).unwrap();
        assert!(info.attributes().has(CommandAttributes::EXTENSIVE));

        let info = lookup(cc::SequenceComplete).unwrap();
        assert!(info.attributes().has(CommandAttributes::FLUSHED));
    }

    #[test]
    fn known_commands_have_the_expected_shape() {
        // Commands with no handles at all.
        for code in [cc::Startup, cc::GetRandom, cc::GetCapability, cc::PCR_Read] {
            let info = lookup(code).unwrap();
            assert_eq!(info.handles, 0);
            assert_eq!(info.auth_handles, 0);
        }
        // TPM2_FlushContext takes its handle as a parameter, not in the handle
        // area, so that a saved context can be named.
        assert_eq!(lookup(cc::FlushContext).unwrap().handles, 0);
        // Two handle commands where only the first is authorized.
        for code in [cc::NV_Read, cc::NV_Write, cc::Duplicate, cc::EvictControl] {
            let info = lookup(code).unwrap();
            assert_eq!(info.handles, 2, "{}", cc_name(code).unwrap());
            assert_eq!(info.auth_handles, 1, "{}", cc_name(code).unwrap());
        }
        // Three handle commands.
        assert_eq!(lookup(cc::PolicyNV).unwrap().handles, 3);
        assert_eq!(lookup(cc::NV_Certify).unwrap().handles, 3);
        // Policy commands take the session handle without authorizing it.
        for code in [cc::PolicyOR, cc::PolicyPCR, cc::PolicyCommandCode] {
            let info = lookup(code).unwrap();
            assert_eq!(info.handles, 1);
            assert_eq!(info.auth_handles, 0);
        }
    }

    #[test]
    fn command_counts_are_reported() {
        assert!(library_command_count() > 100);
        assert_eq!(vendor_command_count(), 1);
        assert_eq!(
            library_command_count() + vendor_command_count(),
            COMMANDS.len()
        );
    }
}
