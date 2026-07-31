//! Handle interface types and authorization roles, from the Part 3 command
//! schematics.
//!
//! Every command names the interface type of each of its handles, which fixes
//! the set of values that handle may take, and the authorization role of the
//! handles that need one. Part 3 clause 5.4 refuses a handle that the command
//! syntax does not allow, and clause 5.6 refuses an authorization that does
//! not match the role.

use crate::tpm::constants::{cc, hc, rh};
use crate::tpm::core::hierarchy::Hierarchies;
use crate::tpm::core::nv::NvStore;
use crate::tpm::core::object::ObjectSlots;
use crate::tpm::core::session;

/// The interface type of one handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// TPMI_DH_OBJECT, a loaded transient or persistent object.
    Object,
    /// TPMI_DH_PARENT, an object or a hierarchy.
    Parent,
    /// TPMI_DH_ENTITY, anything that can carry an authorization value.
    Entity,
    /// TPMI_DH_PCR.
    Pcr,
    /// TPMI_DH_CONTEXT, a session or a transient object.
    Context,
    /// TPMI_DH_PERSISTENT.
    Persistent,
    /// TPMI_SH_POLICY.
    PolicySession,
    /// TPMI_SH_HMAC.
    HmacSession,
    /// TPMI_SH_AUTH_SESSION.
    AuthSession,
    /// TPMI_RH_NV_INDEX and the Index types that narrow it.
    NvIndex,
    /// TPMI_RH_NV_AUTH: platform, owner or the Index itself.
    NvAuth,
    /// TPMI_RH_PLATFORM.
    Platform,
    /// TPMI_RH_OWNER.
    Owner,
    /// TPMI_RH_ENDORSEMENT.
    Endorsement,
    /// TPMI_RH_PROVISION: owner or platform.
    Provision,
    /// TPMI_RH_CLEAR: lockout or platform.
    Clear,
    /// TPMI_RH_LOCKOUT.
    Lockout,
    /// TPMI_RH_HIERARCHY.
    Hierarchy,
    /// TPMI_RH_HIERARCHY_AUTH.
    HierarchyAuth,
    /// TPMI_RH_HIERARCHY_POLICY.
    HierarchyPolicy,
    /// TPMI_RH_BASE_HIERARCHY.
    BaseHierarchy,
}

/// The authorization role of one handle, Part 3 clause 4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The handle carries no authorization.
    None,
    /// USER role, which any authorization type may satisfy.
    User,
    /// ADMIN role.
    Admin,
    /// DUP role, which only a policy session may satisfy.
    Dup,
}

use Kind::*;
use Role as R;

/// One handle of a command schematic.
///
/// `nullable` is the plus the specification writes after an interface type,
/// which means TPM_RH_NULL is also allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    pub kind: Kind,
    pub nullable: bool,
}

/// Shorthand for one row entry.
#[allow(non_snake_case)]
const fn H(kind: Kind, nullable: bool) -> Handle {
    Handle { kind, nullable }
}

/// One row of the command schematics: the handles in the order the handle
/// area carries them, and the authorization role of each.
type Row = (u32, &'static [Handle], &'static [Role]);

const ROWS: &[Row] = &[
    (cc::ActivateCredential, &[H(Object, false), H(Object, false)], &[R::Admin, R::User]),
    (cc::Certify, &[H(Object, false), H(Object, true)], &[R::Admin, R::User]),
    (cc::CertifyCreation, &[H(Object, true), H(Object, false)], &[R::User, R::None]),
    (cc::CertifyX509, &[H(Object, false), H(Object, false)], &[R::Admin, R::User]),
    (cc::ChangeEPS, &[H(Platform, false)], &[R::User]),
    (cc::ChangePPS, &[H(Platform, false)], &[R::User]),
    (cc::Clear, &[H(Clear, false)], &[R::User]),
    (cc::ClearControl, &[H(Clear, false)], &[R::User]),
    (cc::ClockRateAdjust, &[H(Provision, false)], &[R::User]),
    (cc::ClockSet, &[H(Provision, false)], &[R::User]),
    (cc::Commit, &[H(Object, false)], &[R::User]),
    (cc::ContextSave, &[H(Context, false)], &[R::None]),
    (cc::Create, &[H(Object, false)], &[R::User]),
    (cc::CreateLoaded, &[H(Parent, false)], &[R::User]),
    (cc::CreatePrimary, &[H(Hierarchy, false)], &[R::User]),
    (cc::Decapsulate, &[H(Object, false)], &[R::User]),
    (cc::DictionaryAttackLockReset, &[H(Lockout, false), H(Lockout, false)], &[R::None, R::User]),
    (cc::DictionaryAttackParameters, &[H(Lockout, false), H(Lockout, false)], &[R::None, R::User]),
    (cc::Duplicate, &[H(Object, false), H(Object, true)], &[R::Dup, R::None]),
    (cc::ECC_Decrypt, &[H(Object, false)], &[R::User]),
    (cc::ECC_Encrypt, &[H(Object, false)], &[R::None]),
    (cc::ECDH_KeyGen, &[H(Object, false)], &[R::None]),
    (cc::ECDH_ZGen, &[H(Object, false)], &[R::User]),
    (cc::Encapsulate, &[H(Object, false)], &[R::None]),
    (cc::EncryptDecrypt, &[H(Object, false)], &[R::User]),
    (cc::EncryptDecrypt2, &[H(Object, false)], &[R::User]),
    (cc::EventSequenceComplete, &[H(Pcr, true), H(Object, false)], &[R::User, R::User]),
    (cc::EvictControl, &[H(Provision, false), H(Object, false)], &[R::User, R::None]),
    (cc::FieldUpgradeStart, &[H(Platform, false), H(Object, false)], &[R::Admin, R::None]),
    (cc::GetCommandAuditDigest, &[H(Endorsement, false), H(Object, true)], &[R::User, R::User]),
    (cc::GetSessionAuditDigest, &[H(Endorsement, false), H(Object, true), H(HmacSession, false)], &[R::User, R::User, R::None]),
    (cc::GetTime, &[H(Endorsement, false), H(Object, true)], &[R::User, R::User]),
    (cc::HMAC, &[H(Object, false)], &[R::User]),
    (cc::HMAC_Start, &[H(Object, false)], &[R::User]),
    (cc::HierarchyChangeAuth, &[H(HierarchyAuth, false)], &[R::User]),
    (cc::HierarchyControl, &[H(BaseHierarchy, false)], &[R::User]),
    (cc::Import, &[H(Object, false)], &[R::User]),
    (cc::Load, &[H(Object, false)], &[R::User]),
    (cc::MAC, &[H(Object, false)], &[R::User]),
    (cc::MAC_Start, &[H(Object, false)], &[R::User]),
    (cc::MakeCredential, &[H(Object, false)], &[R::None]),
    (cc::NV_Certify, &[H(Object, true), H(NvAuth, false), H(NvIndex, false)], &[R::User, R::User, R::None]),
    (cc::NV_ChangeAuth, &[H(NvIndex, false)], &[R::Admin]),
    (cc::NV_DefineSpace, &[H(Provision, false)], &[R::User]),
    (cc::NV_DefineSpace2, &[H(Provision, false)], &[R::User]),
    (cc::NV_Extend, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_GlobalWriteLock, &[H(Provision, false)], &[R::User]),
    (cc::NV_Increment, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_Read, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_ReadLock, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_ReadPublic, &[H(NvIndex, false)], &[R::None]),
    (cc::NV_ReadPublic2, &[H(NvIndex, false)], &[R::None]),
    (cc::NV_SetBits, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_UndefineSpace, &[H(Provision, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_UndefineSpaceSpecial, &[H(NvIndex, false), H(Platform, false)], &[R::Admin, R::User]),
    (cc::NV_Write, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::NV_WriteLock, &[H(NvAuth, false), H(NvIndex, false)], &[R::User, R::None]),
    (cc::ObjectChangeAuth, &[H(Object, false), H(Object, false)], &[R::Admin, R::None]),
    (cc::PCR_Allocate, &[H(Platform, false)], &[R::User]),
    (cc::PCR_Event, &[H(Pcr, true)], &[R::User]),
    (cc::PCR_Extend, &[H(Pcr, true)], &[R::User]),
    (cc::PCR_Reset, &[H(Pcr, false)], &[R::User]),
    (cc::PCR_SetAuthPolicy, &[H(Platform, false)], &[R::User]),
    (cc::PCR_SetAuthValue, &[H(Pcr, false)], &[R::User]),
    (cc::PP_Commands, &[H(Platform, false)], &[R::User]),
    (cc::PolicyAuthValue, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyAuthorize, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyAuthorizeNV, &[H(NvAuth, false), H(NvIndex, false), H(PolicySession, false)], &[R::User, R::None, R::None]),
    (cc::PolicyCapability, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyCommandCode, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyCounterTimer, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyCpHash, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyDuplicationSelect, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyGetDigest, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyLocality, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyNV, &[H(NvAuth, false), H(NvIndex, false), H(PolicySession, false)], &[R::User, R::None, R::None]),
    (cc::PolicyNameHash, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyNvWritten, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyOR, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyPCR, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyParameters, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyPassword, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyPhysicalPresence, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyRestart, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicySecret, &[H(Entity, false), H(PolicySession, false)], &[R::User, R::None]),
    (cc::PolicySigned, &[H(Object, false), H(PolicySession, false)], &[R::None, R::None]),
    (cc::PolicyTemplate, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyTicket, &[H(PolicySession, false)], &[R::None]),
    (cc::PolicyTransportSPDM, &[H(PolicySession, false)], &[R::None]),
    (cc::Policy_AC_SendSelect, &[H(PolicySession, false)], &[R::None]),
    (cc::Quote, &[H(Object, true)], &[R::User]),
    (cc::RSA_Decrypt, &[H(Object, false)], &[R::User]),
    (cc::RSA_Encrypt, &[H(Object, false)], &[R::None]),
    (cc::ReadOnlyControl, &[H(Platform, false)], &[R::User]),
    (cc::ReadPublic, &[H(Object, false)], &[R::None]),
    (cc::Rewrap, &[H(Object, true), H(Object, true)], &[R::User, R::None]),
    (cc::SequenceComplete, &[H(Object, false)], &[R::User]),
    (cc::SequenceUpdate, &[H(Object, false)], &[R::User]),
    (cc::SetAlgorithmSet, &[H(Platform, false), H(Platform, false)], &[R::None, R::User]),
    (cc::SetCapability, &[H(HierarchyAuth, true)], &[R::User]),
    (cc::SetCommandCodeAuditStatus, &[H(Provision, false)], &[R::User]),
    (cc::Sign, &[H(Object, false)], &[R::User]),
    (cc::SignDigest, &[H(Object, false)], &[R::User]),
    (cc::SignSequenceComplete, &[H(Object, false), H(Object, false)], &[R::User, R::User]),
    (cc::SignSequenceStart, &[H(Object, false)], &[R::None]),
    (cc::StartAuthSession, &[H(Object, true), H(Entity, true)], &[R::None, R::None]),
    (cc::Unseal, &[H(Object, false)], &[R::User]),
    (cc::VerifyDigestSignature, &[H(Object, false)], &[R::None]),
    (cc::VerifySequenceComplete, &[H(Object, false), H(Object, false)], &[R::User, R::None]),
    (cc::VerifySequenceStart, &[H(Object, false)], &[R::None]),
    (cc::VerifySignature, &[H(Object, false)], &[R::None]),
    (cc::ZGen_2Phase, &[H(Object, false)], &[R::User]),
];

/// The interface type and role of the handles of `code`.
fn row(code: u32) -> Option<&'static Row> {
    ROWS.iter().find(|r| r.0 == code)
}

/// The handle the schematic gives position `index`, counting from zero.
pub fn kind(code: u32, index: usize) -> Option<Handle> {
    row(code).and_then(|r| r.1.get(index).copied())
}

/// The authorization role of the handle at `index`, counting from zero.
///
/// A command this table does not name, or a handle past the ones it lists,
/// takes the USER role, which is what the great majority of handles have.
pub fn role(code: u32, index: usize) -> Role {
    row(code)
        .and_then(|r| r.2.get(index).copied())
        .unwrap_or(Role::User)
}

/// True when `handle` is a value the interface type allows.
///
/// Only the shape of the handle is judged here. Whether the entity exists is
/// the business of the command, which reports TPM_RC_HANDLE or
/// TPM_RC_REFERENCE for a value that is well formed but absent.
pub fn allows(handle_spec: Handle, handle: u32) -> bool {
    // A type written with a trailing plus also takes the null handle.
    if handle_spec.nullable && handle == rh::NULL {
        return true;
    }
    let kind = handle_spec.kind;
    let hierarchy = |h: u32| matches!(h, rh::OWNER | rh::PLATFORM | rh::ENDORSEMENT);
    let object = |h: u32| {
        ObjectSlots::is_transient(h) || (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&h)
    };
    match kind {
        Kind::Object | Kind::Persistent => match kind {
            Kind::Persistent => (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&handle),
            _ => object(handle),
        },
        // A parent is an object or any hierarchy, including the null one.
        Kind::Parent => object(handle) || hierarchy(handle) || handle == rh::NULL,
        // An entity is anything that can hold an authorization value.
        Kind::Entity => {
            object(handle)
                || NvStore::is_nv_handle(handle)
                || (hc::PCR_FIRST..=hc::PCR_LAST).contains(&handle)
                || hierarchy(handle)
                || handle == rh::LOCKOUT
                || handle == rh::NULL
        }
        Kind::Pcr => (hc::PCR_FIRST..=hc::PCR_LAST).contains(&handle),
        Kind::Context => session::is_session_handle(handle) || ObjectSlots::is_transient(handle),
        Kind::PolicySession => {
            (hc::POLICY_SESSION_FIRST..hc::POLICY_SESSION_FIRST + 0x0100_0000).contains(&handle)
                && handle >> 24 == hc::POLICY_SESSION_FIRST >> 24
        }
        Kind::HmacSession => handle >> 24 == hc::HMAC_SESSION_FIRST >> 24,
        Kind::AuthSession => session::is_session_handle(handle) || handle == rh::RS_PW,
        Kind::NvIndex => NvStore::is_nv_handle(handle),
        Kind::NvAuth => {
            handle == rh::PLATFORM || handle == rh::OWNER || NvStore::is_nv_handle(handle)
        }
        Kind::Platform => handle == rh::PLATFORM,
        Kind::Owner => handle == rh::OWNER || handle == rh::NULL,
        Kind::Endorsement => handle == rh::ENDORSEMENT || handle == rh::NULL,
        Kind::Provision => handle == rh::OWNER || handle == rh::PLATFORM,
        Kind::Clear => handle == rh::LOCKOUT || handle == rh::PLATFORM,
        Kind::Lockout => handle == rh::LOCKOUT,
        Kind::Hierarchy => hierarchy(handle) || handle == rh::NULL,
        Kind::HierarchyAuth => hierarchy(handle) || handle == rh::LOCKOUT,
        Kind::HierarchyPolicy => hierarchy(handle) || handle == rh::LOCKOUT,
        Kind::BaseHierarchy => hierarchy(handle),
    }
}

/// True when the hierarchy module knows this handle, used by the tests.
#[allow(dead_code)]
fn is_hierarchy(handle: u32) -> bool {
    Hierarchies::is_hierarchy(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::cc;

    #[test]
    fn a_clear_handle_takes_only_lockout_and_platform() {
        // Part 2 Table 68 defines TPMI_RH_CLEAR, which is what TPM2_Clear and
        // TPM2_ClearControl take.
        let h = kind(cc::Clear, 0).unwrap();
        assert_eq!(h.kind, Kind::Clear);
        assert!(allows(h, rh::LOCKOUT));
        assert!(allows(h, rh::PLATFORM));
        assert!(!allows(h, rh::OWNER));
        assert!(!allows(h, rh::ENDORSEMENT));
        // A transient object the caller controls cannot stand in for it.
        assert!(!allows(h, hc::TRANSIENT_FIRST));
    }

    #[test]
    fn a_platform_handle_takes_nothing_else() {
        for code in [cc::ChangePPS, cc::ChangeEPS, cc::PP_Commands] {
            let h = kind(code, 0).unwrap();
            assert_eq!(h.kind, Kind::Platform, "{code:#x}");
            assert!(allows(h, rh::PLATFORM));
            assert!(!allows(h, rh::OWNER));
            assert!(!allows(h, hc::TRANSIENT_FIRST));
        }
    }

    #[test]
    fn a_lockout_handle_takes_nothing_else() {
        for code in [
            cc::DictionaryAttackLockReset,
            cc::DictionaryAttackParameters,
        ] {
            let h = kind(code, 0).unwrap();
            assert_eq!(h.kind, Kind::Lockout, "{code:#x}");
            assert!(allows(h, rh::LOCKOUT));
            assert!(!allows(h, rh::PLATFORM));
            assert!(!allows(h, hc::TRANSIENT_FIRST));
        }
    }

    #[test]
    fn an_optional_handle_also_takes_the_null_handle() {
        // TPM2_StartAuthSession writes both of its handles with a trailing
        // plus, so an unsalted and unbound session names TPM_RH_NULL twice.
        for index in 0..2 {
            let h = kind(cc::StartAuthSession, index).unwrap();
            assert!(h.nullable, "handle {index}");
            assert!(allows(h, rh::NULL));
        }
        // TPM2_Clear does not, so the null handle is refused there.
        assert!(!allows(kind(cc::Clear, 0).unwrap(), rh::NULL));
    }

    #[test]
    fn the_roles_match_the_command_schematics() {
        // Part 3 gives these handles the DUP and ADMIN roles, which clause
        // 5.6.4 and clause 5.6.5 reserve for policy sessions.
        assert_eq!(role(cc::Duplicate, 0), Role::Dup);
        assert_eq!(role(cc::NV_ChangeAuth, 0), Role::Admin);
        assert_eq!(role(cc::ObjectChangeAuth, 0), Role::Admin);
        assert_eq!(role(cc::Certify, 0), Role::Admin);
        assert_eq!(role(cc::ActivateCredential, 0), Role::Admin);
        assert_eq!(role(cc::NV_UndefineSpaceSpecial, 0), Role::Admin);
        // Ordinary use is the USER role.
        assert_eq!(role(cc::Unseal, 0), Role::User);
        assert_eq!(role(cc::NV_Write, 0), Role::User);
        // A handle that carries no authorization has no role.
        assert_eq!(role(cc::Duplicate, 1), Role::None);
    }
}
