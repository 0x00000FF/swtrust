//! NV storage commands, Part 3 clause 31.

use crate::tpm::config;
use crate::tpm::constants::{rc, rh};
use crate::tpm::core::nv::{NvIndex, NvStore};
use crate::tpm::core::state::TpmState;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attributes::{nt, NvAttributes};
use crate::tpm::structures::base::{Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bName};
use crate::tpm::structures::nv::{
    NvPublic, NvPublic2, Tpm2bNvPublic, Tpm2bNvPublic2, TpmtNvPublic2,
};

use super::dispatch::{Request, Response};
use super::execute::respond;

/// The Index a handle names, checking that it exists.
fn index_of(state: &TpmState, handle: u32) -> TpmResult<&NvIndex> {
    state.nv.get(handle)
}

/// Check that the authorization handle may write this Index.
///
/// Part 3 clause 31.2 lets a write be authorized by platform authorization,
/// owner authorization or the Index itself. When the Index authorizes itself,
/// clause 5.6.7.2 also fixes which authorization method applies: TPMA_NV_
/// AUTHWRITE accepts a password or HMAC session and TPMA_NV_POLICYWRITE
/// accepts a policy session, so one does not stand in for the other.
fn check_write_authority(index: &NvIndex, auth_handle: u32, is_policy: bool) -> TpmResult<()> {
    let a = index.public.attributes;
    let allowed = match auth_handle {
        rh::PLATFORM => a.has(NvAttributes::PPWRITE),
        rh::OWNER => a.has(NvAttributes::OWNERWRITE),
        h if h == index.public.nv_index => {
            if is_policy {
                a.has(NvAttributes::POLICYWRITE)
            } else {
                a.has(NvAttributes::AUTHWRITE)
            }
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(TpmRc(rc::NV_AUTHORIZATION))
    }
}

/// Check that the authorization handle may read this Index.
fn check_read_authority(index: &NvIndex, auth_handle: u32, is_policy: bool) -> TpmResult<()> {
    let a = index.public.attributes;
    let allowed = match auth_handle {
        rh::PLATFORM => a.has(NvAttributes::PPREAD),
        rh::OWNER => a.has(NvAttributes::OWNERREAD),
        h if h == index.public.nv_index => {
            if is_policy {
                a.has(NvAttributes::POLICYREAD)
            } else {
                a.has(NvAttributes::AUTHREAD)
            }
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(TpmRc(rc::NV_AUTHORIZATION))
    }
}

/// True when the first authorization of the command came from a policy
/// session rather than a password or HMAC session.
fn first_auth_is_policy(state: &TpmState, request: &Request) -> bool {
    let Some(input) = request.sessions.first() else {
        return false;
    };
    if input.handle == rh::RS_PW {
        return false;
    }
    state
        .sessions
        .get(input.handle)
        .map(|s| s.is_policy())
        .unwrap_or(false)
}

/// Common checks before any write.
fn writable(state: &TpmState, request: &Request, handle: u32, auth_handle: u32) -> TpmResult<()> {
    let is_policy = first_auth_is_policy(state, request);
    let index = index_of(state, handle).map_err(|e| e.with_handle(2))?;
    check_write_authority(index, auth_handle, is_policy)?;
    if index.write_locked {
        return Err(TpmRc(rc::NV_LOCKED));
    }
    Ok(())
}

/// Build the public area of a new Index and check it.
fn validate_new_public(state: &TpmState, public: &NvPublic, auth_handle: u32) -> TpmResult<()> {
    if !NvStore::is_nv_handle(public.nv_index) {
        return Err(TpmRc(rc::HANDLE).with_parameter(2));
    }
    if state.nv.contains(public.nv_index) {
        return Err(TpmRc(rc::NV_DEFINED));
    }
    let a = public.attributes;
    // Exactly one write authorization and one read authorization must be set.
    let writes = [
        NvAttributes::PPWRITE,
        NvAttributes::OWNERWRITE,
        NvAttributes::AUTHWRITE,
        NvAttributes::POLICYWRITE,
    ]
    .iter()
    .filter(|m| a.has(**m))
    .count();
    let reads = [
        NvAttributes::PPREAD,
        NvAttributes::OWNERREAD,
        NvAttributes::AUTHREAD,
        NvAttributes::POLICYREAD,
    ]
    .iter()
    .filter(|m| a.has(**m))
    .count();
    if writes == 0 || reads == 0 {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }
    // TPMA_NV_POLICY_DELETE needs platform authorization to define.
    if a.has(NvAttributes::POLICY_DELETE) && auth_handle != rh::PLATFORM {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }
    // A policy based access needs a policy to be present.
    if (a.has(NvAttributes::POLICYWRITE) || a.has(NvAttributes::POLICYREAD))
        && public.auth_policy.is_empty()
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }
    // The written bit is set by the TPM, never by the caller.
    if a.has(NvAttributes::WRITTEN) {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }
    // The size must match the Index type.
    let size = public.data_size as usize;
    let required = match a.index_type() {
        nt::COUNTER | nt::BITS => Some(8),
        nt::PIN_FAIL | nt::PIN_PASS => Some(8),
        nt::EXTEND => crate::tpm::structures::base::digest_size(public.name_alg),
        nt::ORDINARY => None,
        _ => return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2)),
    };
    match required {
        Some(n) if size != n => return Err(TpmRc(rc::SIZE).with_parameter(2)),
        _ => {}
    }
    if size > config::MAX_NV_INDEX_SIZE {
        return Err(TpmRc(rc::SIZE).with_parameter(2));
    }
    Ok(())
}

/// TPM2_NV_DefineSpace, Part 3 clause 31.3.
pub fn nv_define_space(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    let public = Tpm2bNvPublic::unmarshal(&mut r)?.nv_public;
    define(state, auth_handle, auth.as_slice().to_vec(), public)
}

/// TPM2_NV_DefineSpace2, Part 3 clause 31.4.
pub fn nv_define_space2(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    let public2 = Tpm2bNvPublic2::unmarshal(&mut r)?.nv_public;
    let public = match public2.public_area {
        NvPublic2::Index(p) | NvPublic2::Permanent(p) => p,
        NvPublic2::External(_) => {
            // External NV is not implemented, so an external definition is
            // refused rather than silently treated as an ordinary Index.
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
        }
    };
    define(state, auth_handle, auth.as_slice().to_vec(), public)
}

fn define(
    state: &mut TpmState,
    auth_handle: u32,
    auth: Vec<u8>,
    mut public: NvPublic,
) -> TpmResult<Response> {
    validate_new_public(state, &public, auth_handle)?;
    if auth.len() > crate::tpm::structures::base::MAX_DIGEST_SIZE {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    // The TPM records which authority defined the Index.
    public
        .attributes
        .set(NvAttributes::PLATFORMCREATE, auth_handle == rh::PLATFORM);
    if public.attributes.index_type() == nt::COUNTER
        && state.nv.counter_count() as u32 >= config::MIN_COUNTER_INDICES
    {
        return Err(TpmRc(rc::NV_SPACE));
    }
    state.nv.define(NvIndex {
        public,
        auth,
        data: Vec::new(),
        read_locked: false,
        write_locked: false,
    })?;
    respond(|_| Ok(()))
}

/// TPM2_NV_UndefineSpace, Part 3 clause 31.5.
pub fn nv_undefine_space(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(2))?;
    if index.public.attributes.has(NvAttributes::POLICY_DELETE) {
        // Such an Index only goes away through TPM2_NV_UndefineSpaceSpecial.
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    let platform_created = index.public.attributes.has(NvAttributes::PLATFORMCREATE);
    if platform_created && auth_handle != rh::PLATFORM {
        return Err(TpmRc(rc::NV_AUTHORIZATION).with_handle(1));
    }
    if !platform_created && auth_handle != rh::OWNER {
        return Err(TpmRc(rc::NV_AUTHORIZATION).with_handle(1));
    }
    state.nv.undefine(nv_handle)?;
    respond(|_| Ok(()))
}

/// TPM2_NV_UndefineSpaceSpecial, Part 3 clause 31.6.
pub fn nv_undefine_space_special(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let nv_handle = request.handle(0)?;
    let platform = request.handle(1)?;
    if platform != rh::PLATFORM {
        return Err(TpmRc(rc::AUTH_TYPE).with_handle(2));
    }
    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(1))?;
    if !index.public.attributes.has(NvAttributes::POLICY_DELETE) {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    state.nv.undefine(nv_handle)?;
    respond(|_| Ok(()))
}

/// TPM2_NV_ReadPublic, Part 3 clause 31.7.
pub fn nv_read_public(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let nv_handle = request.handle(0)?;
    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(1))?;
    let public = index.public.clone();
    let name = index.name()?;
    respond(move |w| {
        Tpm2bNvPublic { nv_public: public }.marshal(w);
        Tpm2bName::new(name)?.marshal(w);
        Ok(())
    })
}

/// TPM2_NV_ReadPublic2, Part 3 clause 31.8.
pub fn nv_read_public2(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let nv_handle = request.handle(0)?;
    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(1))?;
    let public = index.public.clone();
    let name = index.name()?;
    respond(move |w| {
        Tpm2bNvPublic2 {
            nv_public: TpmtNvPublic2 {
                public_area: NvPublic2::Index(public),
            },
        }
        .marshal(w);
        Tpm2bName::new(name)?.marshal(w);
        Ok(())
    })
}

/// TPM2_NV_Write, Part 3 clause 31.9.
pub fn nv_write(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let mut r = request.reader();
    let data = Tpm2bMaxNvBuffer::unmarshal(&mut r)?;
    let offset = r.u16()?;

    writable(state, request, nv_handle, auth_handle)?;
    let index = state.nv.get_mut(nv_handle)?;
    if index.index_type() != nt::ORDINARY {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    index
        .write(offset, data.as_slice())
        .map_err(|e| if e.0 == rc::NV_RANGE { e } else { e.with_parameter(1) })?;
    note_orderly_write(state, nv_handle);
    respond(|_| Ok(()))
}

/// TPM2_NV_Increment, Part 3 clause 31.10.
pub fn nv_increment(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    writable(state, request, nv_handle, auth_handle)?;
    state.nv.get_mut(nv_handle)?.increment()?;
    note_orderly_write(state, nv_handle);
    respond(|_| Ok(()))
}

/// TPM2_NV_Extend, Part 3 clause 31.11.
pub fn nv_extend(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let mut r = request.reader();
    let data = Tpm2bMaxNvBuffer::unmarshal(&mut r)?;
    writable(state, request, nv_handle, auth_handle)?;
    state.nv.get_mut(nv_handle)?.extend(data.as_slice())?;
    note_orderly_write(state, nv_handle);
    respond(|_| Ok(()))
}

/// TPM2_NV_SetBits, Part 3 clause 31.12.
pub fn nv_set_bits(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let mut r = request.reader();
    let bits = r.u64()?;
    writable(state, request, nv_handle, auth_handle)?;
    state.nv.get_mut(nv_handle)?.set_bits(bits)?;
    note_orderly_write(state, nv_handle);
    respond(|_| Ok(()))
}

/// Record that an Index with TPMA_NV_ORDERLY has moved away from the value NV
/// holds, which clears TPMA_STARTUP_CLEAR.orderly until the next shutdown.
fn note_orderly_write(state: &mut TpmState, nv_handle: u32) {
    let orderly = state
        .nv
        .get(nv_handle)
        .map(|i| i.public.attributes.has(NvAttributes::ORDERLY))
        .unwrap_or(false);
    if orderly {
        state.nv_is_no_longer_orderly();
    }
}

/// TPM2_NV_WriteLock, Part 3 clause 31.13.
pub fn nv_write_lock(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(2))?;
    check_write_authority(index, auth_handle, first_auth_is_policy(state, request))?;
    let a = index.public.attributes;
    if !a.has(NvAttributes::WRITEDEFINE) && !a.has(NvAttributes::WRITE_STCLEAR) {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    state.nv.get_mut(nv_handle)?.set_write_lock(true);
    respond(|_| Ok(()))
}

/// TPM2_NV_GlobalWriteLock, Part 3 clause 31.14.
pub fn nv_global_write_lock(state: &mut TpmState, _request: &Request) -> TpmResult<Response> {
    state.nv.global_write_lock();
    respond(|_| Ok(()))
}

/// TPM2_NV_Read, Part 3 clause 31.15.
pub fn nv_read(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let mut r = request.reader();
    let size = r.u16()?;
    let offset = r.u16()?;

    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(2))?;
    check_read_authority(index, auth_handle, first_auth_is_policy(state, request))?;
    if index.read_locked {
        return Err(TpmRc(rc::NV_LOCKED));
    }
    if size as usize > config::MAX_NV_BUFFER_SIZE {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    let data = index.read(offset, size)?;
    respond(move |w| {
        Tpm2bMaxNvBuffer::new(data)?.marshal(w);
        Ok(())
    })
}

/// TPM2_NV_ReadLock, Part 3 clause 31.16.
pub fn nv_read_lock(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let nv_handle = request.handle(1)?;
    let index = index_of(state, nv_handle).map_err(|e| e.with_handle(2))?;
    check_read_authority(index, auth_handle, first_auth_is_policy(state, request))?;
    if !index.public.attributes.has(NvAttributes::READ_STCLEAR) {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    state.nv.get_mut(nv_handle)?.set_read_lock(true);
    respond(|_| Ok(()))
}

/// TPM2_NV_ChangeAuth, Part 3 clause 31.17.
pub fn nv_change_auth(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let nv_handle = request.handle(0)?;
    let mut r = request.reader();
    let new_auth = Tpm2bDigest::unmarshal(&mut r)?;
    if new_auth.len() > crate::tpm::structures::base::MAX_DIGEST_SIZE {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    state.nv.get_mut(nv_handle).map_err(|e| e.with_handle(1))?.auth =
        new_auth.as_slice().to_vec();
    respond(|_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{alg, hc};

    fn index(attributes: u32, index_type: u8, size: u16) -> NvIndex {
        NvIndex {
            public: NvPublic {
                nv_index: hc::NV_INDEX_FIRST + 1,
                name_alg: alg::SHA256,
                attributes: NvAttributes(attributes).with_index_type(index_type),
                auth_policy: Tpm2bDigest::empty(),
                data_size: size,
            },
            auth: Vec::new(),
            data: Vec::new(),
            read_locked: false,
            write_locked: false,
        }
    }

    #[test]
    fn write_authority_follows_the_attributes() {
        let i = index(NvAttributes::OWNERWRITE, nt::ORDINARY, 8);
        assert!(check_write_authority(&i, rh::OWNER, false).is_ok());
        assert_eq!(
            check_write_authority(&i, rh::PLATFORM, false).unwrap_err(),
            TpmRc(rc::NV_AUTHORIZATION)
        );

        let i = index(NvAttributes::AUTHWRITE, nt::ORDINARY, 8);
        assert!(check_write_authority(&i, i.public.nv_index, false).is_ok());
        assert!(check_write_authority(&i, rh::OWNER, false).is_err());
    }

    #[test]
    fn read_authority_follows_the_attributes() {
        let i = index(NvAttributes::PPREAD, nt::ORDINARY, 8);
        assert!(check_read_authority(&i, rh::PLATFORM, false).is_ok());
        assert!(check_read_authority(&i, rh::OWNER, false).is_err());
    }

    #[test]
    fn the_authorization_method_must_match_the_attribute() {
        // A policy-only Index is not reachable with a password or HMAC
        // session, and an authValue-only Index is not reachable with a policy
        // session. Part 3 clause 5.6.7.2.
        let policy_only = index(NvAttributes::POLICYREAD, nt::ORDINARY, 8);
        let handle = policy_only.public.nv_index;
        assert!(check_read_authority(&policy_only, handle, true).is_ok());
        assert_eq!(
            check_read_authority(&policy_only, handle, false).unwrap_err(),
            TpmRc(rc::NV_AUTHORIZATION)
        );

        let auth_only = index(NvAttributes::AUTHREAD, nt::ORDINARY, 8);
        assert!(check_read_authority(&auth_only, handle, false).is_ok());
        assert_eq!(
            check_read_authority(&auth_only, handle, true).unwrap_err(),
            TpmRc(rc::NV_AUTHORIZATION)
        );

        // The same split applies to writing.
        let policy_write = index(NvAttributes::POLICYWRITE, nt::ORDINARY, 8);
        assert!(check_write_authority(&policy_write, handle, true).is_ok());
        assert!(check_write_authority(&policy_write, handle, false).is_err());
        let auth_write = index(NvAttributes::AUTHWRITE, nt::ORDINARY, 8);
        assert!(check_write_authority(&auth_write, handle, false).is_ok());
        assert!(check_write_authority(&auth_write, handle, true).is_err());
    }

    #[test]
    fn a_definition_needs_one_read_and_one_write_authority() {
        let state = TpmState::manufacture().unwrap();
        let i = index(NvAttributes::OWNERWRITE, nt::ORDINARY, 8);
        assert_eq!(
            validate_new_public(&state, &i.public, rh::OWNER)
                .unwrap_err()
                .0
                & 0x03F,
            rc::ATTRIBUTES & 0x03F
        );
        let i = index(
            NvAttributes::OWNERWRITE | NvAttributes::OWNERREAD,
            nt::ORDINARY,
            8,
        );
        assert!(validate_new_public(&state, &i.public, rh::OWNER).is_ok());
    }

    #[test]
    fn counter_and_bit_indices_are_eight_octets() {
        let state = TpmState::manufacture().unwrap();
        let attrs = NvAttributes::OWNERWRITE | NvAttributes::OWNERREAD;
        for kind in [nt::COUNTER, nt::BITS, nt::PIN_FAIL, nt::PIN_PASS] {
            let good = index(attrs, kind, 8);
            assert!(validate_new_public(&state, &good.public, rh::OWNER).is_ok());
            let bad = index(attrs, kind, 4);
            assert_eq!(
                validate_new_public(&state, &bad.public, rh::OWNER)
                    .unwrap_err()
                    .0
                    & 0x03F,
                rc::SIZE & 0x03F
            );
        }
        // An extend Index is the size of its name algorithm digest.
        let good = index(attrs, nt::EXTEND, 32);
        assert!(validate_new_public(&state, &good.public, rh::OWNER).is_ok());
        let bad = index(attrs, nt::EXTEND, 20);
        assert!(validate_new_public(&state, &bad.public, rh::OWNER).is_err());
    }

    #[test]
    fn the_written_bit_may_not_be_asked_for() {
        let state = TpmState::manufacture().unwrap();
        let i = index(
            NvAttributes::OWNERWRITE | NvAttributes::OWNERREAD | NvAttributes::WRITTEN,
            nt::ORDINARY,
            8,
        );
        assert!(validate_new_public(&state, &i.public, rh::OWNER).is_err());
    }

    #[test]
    fn a_policy_based_index_needs_a_policy() {
        let state = TpmState::manufacture().unwrap();
        let i = index(
            NvAttributes::POLICYWRITE | NvAttributes::OWNERREAD,
            nt::ORDINARY,
            8,
        );
        assert!(validate_new_public(&state, &i.public, rh::OWNER).is_err());
        let mut i = i;
        i.public.auth_policy = Tpm2bDigest::from_slice(&[0u8; 32]).unwrap();
        assert!(validate_new_public(&state, &i.public, rh::OWNER).is_ok());
    }

    #[test]
    fn policy_delete_needs_platform_authorization() {
        let state = TpmState::manufacture().unwrap();
        let mut i = index(
            NvAttributes::OWNERWRITE | NvAttributes::OWNERREAD | NvAttributes::POLICY_DELETE,
            nt::ORDINARY,
            8,
        );
        i.public.auth_policy = Tpm2bDigest::from_slice(&[0u8; 32]).unwrap();
        assert!(validate_new_public(&state, &i.public, rh::OWNER).is_err());
        assert!(validate_new_public(&state, &i.public, rh::PLATFORM).is_ok());
    }
}
