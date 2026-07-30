//! Session and policy commands, Part 3 clauses 11 and 23.

use crate::tpm::constants::{alg, cc, rc, rh, se, st};
use crate::tpm::core::session::{self, Session};
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{hash, rand::Rng};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal, Writer};
use crate::tpm::structures::attributes::LocalityAttributes;
use crate::tpm::structures::base::{
    Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, Tpm2bOperand, Tpm2bTimeout,
};
use crate::tpm::structures::lists::{TpmlDigest, TpmlPcrSelection};
use crate::tpm::structures::schemes::SymDef;
use crate::tpm::structures::signature::Ticket;

use super::dispatch::{Request, Response};
use super::execute::{respond, respond_with_handle};

/// TPM2_StartAuthSession, Part 3 clause 11.1.
pub fn start_auth_session(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let tpm_key = request.handle(0)?;
    let bind = request.handle(1)?;
    let mut r = request.reader();
    let nonce_caller = Tpm2bNonce::unmarshal(&mut r)?;
    let encrypted_salt = Tpm2bEncryptedSecret::unmarshal(&mut r)?;
    let session_type = r.u8()?;
    let symmetric = SymDef::unmarshal_sym_def(&mut r)?;
    let auth_hash = r.u16()?;

    if !session::is_session_type(session_type) {
        return Err(TpmRc(rc::VALUE).with_parameter(3));
    }
    if !session::is_valid_auth_hash(auth_hash) {
        return Err(TpmRc(rc::HASH).with_parameter(5));
    }
    // Part 3 clause 11.1.2 requires a nonce at least sixteen octets long and
    // no longer than the session hash.
    let digest_size = hash::digest_size(auth_hash)?;
    if nonce_caller.len() < 16 || nonce_caller.len() > digest_size {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    if tpm_key != rh::NULL && !encrypted_salt.is_empty() {
        // Salt decryption needs the key's private area, which only a loaded
        // decryption key has.
        return Err(TpmRc(rc::VALUE).with_handle(1));
    }
    if tpm_key == rh::NULL && !encrypted_salt.is_empty() {
        return Err(TpmRc(rc::VALUE).with_parameter(2));
    }

    let bind_auth = if bind == rh::NULL {
        Vec::new()
    } else {
        super::dispatch::entity(state, bind)
            .map_err(|e| e.with_handle(2))?
            .auth
    };
    let bind_name = if bind == rh::NULL {
        Vec::new()
    } else {
        super::dispatch::handle_name(state, bind)?
    };

    let nonce_tpm = state.rng.bytes(digest_size)?;
    let session_key = session::derive_session_key(
        auth_hash,
        &bind_auth,
        &[],
        &nonce_tpm,
        nonce_caller.as_slice(),
    )?;

    let handle = state.sessions.allocate_handle(session_type)?;
    let s = Session::new(
        handle,
        session_type,
        auth_hash,
        nonce_tpm.clone(),
        nonce_caller.as_slice().to_vec(),
        session_key,
        bind,
        bind_name,
        symmetric,
    )?;
    state.sessions.insert(s)?;

    respond_with_handle(handle, move |w| {
        Tpm2bNonce::new(nonce_tpm)?.marshal(w);
        Ok(())
    })
}

/// TPM2_PolicyRestart, Part 3 clause 11.2.
pub fn policy_restart(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    state
        .sessions
        .get_mut(handle)
        .map_err(|e| e.with_handle(1))?
        .restart_policy()?;
    respond(|_| Ok(()))
}

/// The policy session a policy command names.
fn policy_session(state: &mut TpmState, handle: u32) -> TpmResult<&mut Session> {
    let s = state.sessions.get_mut(handle).map_err(|e| e.with_handle(1))?;
    if !s.is_policy() {
        return Err(TpmRc(rc::MODE).with_handle(1));
    }
    Ok(s)
}

/// TPM2_PolicySigned, Part 3 clause 23.3, and TPM2_PolicySecret, clause 23.4,
/// share this update.
///
/// `policyDigest = H(policyDigest || commandCode || authName || policyRef)`,
/// then the cpHash is recorded when one was given.
fn policy_authorization_update(
    s: &mut Session,
    command_code: u32,
    auth_name: &[u8],
    policy_ref: &[u8],
) -> TpmResult<()> {
    let mut data = auth_name.to_vec();
    data.extend_from_slice(policy_ref);
    s.extend_policy(command_code, &data)
}

/// TPM2_PolicySigned, Part 3 clause 23.3.
pub fn policy_signed(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_object = request.handle(0)?;
    let policy_session_handle = request.handle(1)?;
    let mut r = request.reader();
    let _nonce_tpm = Tpm2bNonce::unmarshal(&mut r)?;
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;
    let policy_ref = Tpm2bNonce::unmarshal(&mut r)?;
    let _expiration = r.u32()?;
    // The signature is checked against the loaded key. Signature verification
    // needs the object, which is only present once key loading is available,
    // so an unloaded handle is reported rather than silently accepted.
    let auth_name = super::dispatch::handle_name(state, auth_object)
        .map_err(|e| e.with_handle(1))?;

    let s = policy_session(state, policy_session_handle)?;
    policy_authorization_update(s, cc::PolicySigned, &auth_name, policy_ref.as_slice())?;
    if !cp_hash_a.is_empty() {
        s.policy.cp_hash = Some(cp_hash_a.as_slice().to_vec());
    }

    respond(|w| {
        Tpm2bTimeout::empty().marshal(w);
        Ticket::null(st::AUTH_SIGNED).marshal(w);
        Ok(())
    })
}

/// TPM2_PolicySecret, Part 3 clause 23.4.
pub fn policy_secret(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let policy_session_handle = request.handle(1)?;
    let mut r = request.reader();
    let _nonce_tpm = Tpm2bNonce::unmarshal(&mut r)?;
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;
    let policy_ref = Tpm2bNonce::unmarshal(&mut r)?;
    let _expiration = r.u32()?;

    let auth_name = super::dispatch::handle_name(state, auth_handle)
        .map_err(|e| e.with_handle(1))?;
    let s = policy_session(state, policy_session_handle)?;
    policy_authorization_update(s, cc::PolicySecret, &auth_name, policy_ref.as_slice())?;
    if !cp_hash_a.is_empty() {
        s.policy.cp_hash = Some(cp_hash_a.as_slice().to_vec());
    }

    respond(|w| {
        Tpm2bTimeout::empty().marshal(w);
        Ticket::null(st::AUTH_SECRET).marshal(w);
        Ok(())
    })
}

/// TPM2_PolicyTicket, Part 3 clause 23.5.
pub fn policy_ticket(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let policy_session_handle = request.handle(0)?;
    let mut r = request.reader();
    let _timeout = Tpm2bTimeout::unmarshal(&mut r)?;
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;
    let policy_ref = Tpm2bNonce::unmarshal(&mut r)?;
    let auth_name = Tpm2bName::unmarshal(&mut r)?;
    let ticket = Ticket::unmarshal_tagged(&mut r, &[st::AUTH_SIGNED, st::AUTH_SECRET])?;

    // A null ticket carries no proof, so it authorizes nothing.
    if ticket.digest.is_empty() {
        return Err(TpmRc(rc::TICKET).with_parameter(5));
    }
    let command_code = if ticket.tag == st::AUTH_SIGNED {
        cc::PolicySigned
    } else {
        cc::PolicySecret
    };
    let s = policy_session(state, policy_session_handle)?;
    policy_authorization_update(s, command_code, auth_name.as_slice(), policy_ref.as_slice())?;
    if !cp_hash_a.is_empty() {
        s.policy.cp_hash = Some(cp_hash_a.as_slice().to_vec());
    }
    respond(|_| Ok(()))
}

/// TPM2_PolicyOR, Part 3 clause 23.6.
pub fn policy_or(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let list = TpmlDigest::unmarshal(&mut r)?;

    let s = policy_session(state, handle)?;
    // The current digest must be one of the branches.
    let matched = list
        .digests
        .iter()
        .any(|d| d.as_slice() == s.policy.digest.as_slice());
    if !matched {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    // The digest is reset and then extended with every branch, so the result
    // is the same whichever branch was taken.
    let mut data = Writer::new();
    for d in &list.digests {
        data.bytes(d.as_slice());
    }
    let data = data.finish()?;
    s.policy.digest = vec![0u8; hash::digest_size(s.auth_hash)?];
    s.extend_policy(cc::PolicyOR, &data)?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyPCR, Part 3 clause 23.7.
pub fn policy_pcr(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let expected = Tpm2bDigest::unmarshal(&mut r)?;
    let selection = TpmlPcrSelection::unmarshal(&mut r)?;

    let auth_hash = policy_session(state, handle)?.auth_hash;
    let filtered = state.pcr.filter_selection(&selection);
    let digest = state.pcr.selection_digest(auth_hash, &filtered)?;
    let counter = state.pcr.update_counter();

    let s = policy_session(state, handle)?;
    // A trial session records the caller's claim; a real session checks it.
    if !s.is_trial() && !expected.is_empty() && expected.as_slice() != digest.as_slice() {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    let mut data = filtered.to_bytes();
    if s.is_trial() && !expected.is_empty() {
        data.extend_from_slice(expected.as_slice());
    } else {
        data.extend_from_slice(&digest);
    }
    s.extend_policy(cc::PolicyPCR, &data)?;
    if !s.is_trial() {
        s.policy.pcr_update_counter = Some(counter);
    }
    respond(|_| Ok(()))
}

/// TPM2_PolicyLocality, Part 3 clause 23.8.
pub fn policy_locality(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let locality = LocalityAttributes::unmarshal(&mut r)?;
    if locality.0 == 0 {
        return Err(TpmRc(rc::RANGE).with_parameter(1));
    }

    let s = policy_session(state, handle)?;
    // Narrowing only: a second call may not widen what the first allowed.
    let combined = match s.policy.locality {
        Some(existing) => {
            let both = existing & locality.0;
            if both == 0 {
                return Err(TpmRc(rc::RANGE).with_parameter(1));
            }
            both
        }
        None => locality.0,
    };
    s.extend_policy(cc::PolicyLocality, &[locality.0])?;
    s.policy.locality = Some(combined);
    respond(|_| Ok(()))
}

/// TPM2_PolicyCommandCode, Part 3 clause 23.11.
pub fn policy_command_code(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let code = r.u32()?;
    if super::table::lookup(code).is_none() {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    let s = policy_session(state, handle)?;
    if let Some(existing) = s.policy.command_code {
        if existing != code {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
    }
    s.extend_policy(cc::PolicyCommandCode, &code.to_be_bytes())?;
    s.policy.command_code = Some(code);
    respond(|_| Ok(()))
}

/// TPM2_PolicyPhysicalPresence, Part 3 clause 23.12.
pub fn policy_physical_presence(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let s = policy_session(state, handle)?;
    s.extend_policy(cc::PolicyPhysicalPresence, &[])?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyCpHash, Part 3 clause 23.13.
pub fn policy_cp_hash(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;

    let s = policy_session(state, handle)?;
    if cp_hash_a.len() != hash::digest_size(s.auth_hash)? {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    if let Some(existing) = &s.policy.cp_hash {
        if existing != cp_hash_a.as_slice() {
            return Err(TpmRc(rc::CPHASH));
        }
    }
    s.extend_policy(cc::PolicyCpHash, cp_hash_a.as_slice())?;
    s.policy.cp_hash = Some(cp_hash_a.as_slice().to_vec());
    respond(|_| Ok(()))
}

/// TPM2_PolicyNameHash, Part 3 clause 23.14.
pub fn policy_name_hash(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let name_hash = Tpm2bDigest::unmarshal(&mut r)?;

    let s = policy_session(state, handle)?;
    if name_hash.len() != hash::digest_size(s.auth_hash)? {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    if s.policy.cp_hash.is_some() {
        return Err(TpmRc(rc::CPHASH));
    }
    s.extend_policy(cc::PolicyNameHash, name_hash.as_slice())?;
    s.policy.name_hash = Some(name_hash.as_slice().to_vec());
    respond(|_| Ok(()))
}

/// TPM2_PolicyAuthValue, Part 3 clause 23.17.
pub fn policy_auth_value(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let s = policy_session(state, handle)?;
    s.extend_policy(cc::PolicyAuthValue, &[])?;
    s.policy.auth_value_needed = true;
    s.policy.password_needed = false;
    respond(|_| Ok(()))
}

/// TPM2_PolicyPassword, Part 3 clause 23.18.
///
/// The digest is the same as TPM2_PolicyAuthValue so that a policy can be
/// satisfied either way; only how the value is proven differs.
pub fn policy_password(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let s = policy_session(state, handle)?;
    s.extend_policy(cc::PolicyAuthValue, &[])?;
    s.policy.password_needed = true;
    s.policy.auth_value_needed = false;
    respond(|_| Ok(()))
}

/// TPM2_PolicyGetDigest, Part 3 clause 23.19.
pub fn policy_get_digest(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let digest = policy_session(state, handle)?.policy.digest.clone();
    respond(move |w| {
        Tpm2bDigest::new(digest)?.marshal(w);
        Ok(())
    })
}

/// TPM2_PolicyNvWritten, Part 3 clause 23.20.
pub fn policy_nv_written(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let written = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(TpmRc(rc::VALUE).with_parameter(1)),
    };
    let s = policy_session(state, handle)?;
    if let Some(existing) = s.policy.nv_written {
        if existing != written {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
    }
    s.extend_policy(cc::PolicyNvWritten, &[u8::from(written)])?;
    s.policy.nv_written = Some(written);
    respond(|_| Ok(()))
}

/// TPM2_PolicyTemplate, Part 3 clause 23.21.
pub fn policy_template(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let template_hash = Tpm2bDigest::unmarshal(&mut r)?;

    let s = policy_session(state, handle)?;
    if template_hash.len() != hash::digest_size(s.auth_hash)? {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    if s.policy.cp_hash.is_some() {
        return Err(TpmRc(rc::CPHASH));
    }
    s.extend_policy(cc::PolicyTemplate, template_hash.as_slice())?;
    s.policy.template_hash = Some(template_hash.as_slice().to_vec());
    respond(|_| Ok(()))
}

/// TPM2_PolicyCounterTimer, Part 3 clause 23.10.
pub fn policy_counter_timer(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::constants::eo;

    let handle = request.handle(0)?;
    let mut r = request.reader();
    let operand_b = Tpm2bOperand::unmarshal(&mut r)?;
    let offset = r.u16()?;
    let operation = r.u16()?;

    // The comparison is against the marshalled TPMS_TIME_INFO.
    let time_info = crate::tpm::structures::attest::TimeInfo {
        time: state.clock.time,
        clock_info: super::management::clock_info(state),
    };
    let bytes = time_info.to_bytes();
    let start = offset as usize;
    let end = start
        .checked_add(operand_b.len())
        .ok_or(TpmRc(rc::VALUE).with_parameter(2))?;
    if end > bytes.len() {
        return Err(TpmRc(rc::RANGE).with_parameter(2));
    }
    let operand_a = &bytes[start..end];

    let satisfied = compare(operand_a, operand_b.as_slice(), operation)
        .ok_or(TpmRc(rc::VALUE).with_parameter(3))?;
    let is_trial = policy_session(state, handle)?.is_trial();
    if !satisfied && !is_trial {
        return Err(TpmRc(rc::POLICY));
    }
    let _ = eo::EQ;

    // The digest covers the hash of the operand, the offset and the operation.
    let auth_hash = policy_session(state, handle)?.auth_hash;
    let args = hash::digest_parts(
        auth_hash,
        &[
            operand_b.as_slice(),
            &offset.to_be_bytes(),
            &operation.to_be_bytes(),
        ],
    )?;
    let s = policy_session(state, handle)?;
    s.extend_policy(cc::PolicyCounterTimer, &args)?;
    respond(|_| Ok(()))
}

/// Apply a TPM_EO comparison to two equal length operands.
fn compare(a: &[u8], b: &[u8], operation: u16) -> Option<bool> {
    use crate::tpm::constants::eo;

    if a.len() != b.len() {
        return None;
    }
    let unsigned = a.cmp(b);
    // A signed comparison treats the top bit of the first octet as the sign.
    let signed = if a.is_empty() {
        std::cmp::Ordering::Equal
    } else {
        let sa = a[0] & 0x80 != 0;
        let sb = b[0] & 0x80 != 0;
        match (sa, sb) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => unsigned,
        }
    };

    Some(match operation {
        eo::EQ => unsigned.is_eq(),
        eo::NEQ => unsigned.is_ne(),
        eo::SIGNED_GT => signed.is_gt(),
        eo::UNSIGNED_GT => unsigned.is_gt(),
        eo::SIGNED_LT => signed.is_lt(),
        eo::UNSIGNED_LT => unsigned.is_lt(),
        eo::SIGNED_GE => signed.is_ge(),
        eo::UNSIGNED_GE => unsigned.is_ge(),
        eo::SIGNED_LE => signed.is_le(),
        eo::UNSIGNED_LE => unsigned.is_le(),
        eo::BITSET => a.iter().zip(b.iter()).all(|(x, y)| x & y == *y),
        eo::BITCLEAR => a.iter().zip(b.iter()).all(|(x, y)| x & y == 0),
        _ => return None,
    })
}

/// TPM2_PolicyAuthorize, Part 3 clause 23.16.
pub fn policy_authorize(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let approved_policy = Tpm2bDigest::unmarshal(&mut r)?;
    let policy_ref = Tpm2bNonce::unmarshal(&mut r)?;
    let key_sign = Tpm2bName::unmarshal(&mut r)?;
    let check_ticket = Ticket::unmarshal_tagged(&mut r, &[st::VERIFIED])?;

    let s = policy_session(state, handle)?;
    if !s.is_trial() {
        // The running digest must already equal the policy that was approved.
        if s.policy.digest.as_slice() != approved_policy.as_slice() {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
        if check_ticket.digest.is_empty() {
            return Err(TpmRc(rc::TICKET).with_parameter(4));
        }
    }
    // The digest restarts and records who approved the policy.
    let digest_len = hash::digest_size(s.auth_hash)?;
    s.policy.digest = vec![0u8; digest_len];
    let mut data = key_sign.as_slice().to_vec();
    data.extend_from_slice(policy_ref.as_slice());
    s.extend_policy(cc::PolicyAuthorize, &data)?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyDuplicationSelect, Part 3 clause 23.15.
pub fn policy_duplication_select(
    state: &mut TpmState,
    request: &Request,
) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let object_name = Tpm2bName::unmarshal(&mut r)?;
    let new_parent_name = Tpm2bName::unmarshal(&mut r)?;
    let include_object = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(TpmRc(rc::VALUE).with_parameter(3)),
    };

    let auth_hash = policy_session(state, handle)?.auth_hash;
    let name_hash = if include_object {
        hash::digest_parts(auth_hash, &[object_name.as_slice(), new_parent_name.as_slice()])?
    } else {
        hash::digest(auth_hash, new_parent_name.as_slice())?
    };

    let s = policy_session(state, handle)?;
    if s.policy.cp_hash.is_some() {
        return Err(TpmRc(rc::CPHASH));
    }
    let mut data = Vec::new();
    if include_object {
        data.extend_from_slice(object_name.as_slice());
    }
    data.extend_from_slice(new_parent_name.as_slice());
    data.push(u8::from(include_object));
    s.extend_policy(cc::PolicyDuplicationSelect, &data)?;
    s.policy.name_hash = Some(name_hash);
    s.policy.command_code = Some(cc::Duplicate);
    respond(|_| Ok(()))
}

/// TPM2_PolicyNV, Part 3 clause 23.9.
pub fn policy_nv(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let nv_handle = request.handle(1)?;
    let handle = request.handle(2)?;
    let mut r = request.reader();
    let operand_b = Tpm2bOperand::unmarshal(&mut r)?;
    let offset = r.u16()?;
    let operation = r.u16()?;

    let index = state.nv.get(nv_handle).map_err(|e| e.with_handle(2))?;
    if index.read_locked {
        return Err(TpmRc(rc::NV_LOCKED));
    }
    let data = index.read(offset, operand_b.len() as u16)?;
    let nv_name = index.name()?;

    let satisfied = compare(&data, operand_b.as_slice(), operation)
        .ok_or(TpmRc(rc::VALUE).with_parameter(3))?;
    let is_trial = policy_session(state, handle)?.is_trial();
    if !satisfied && !is_trial {
        return Err(TpmRc(rc::POLICY));
    }

    let auth_hash = policy_session(state, handle)?.auth_hash;
    let args = hash::digest_parts(
        auth_hash,
        &[
            operand_b.as_slice(),
            &offset.to_be_bytes(),
            &operation.to_be_bytes(),
        ],
    )?;
    let mut payload = args;
    payload.extend_from_slice(&nv_name);
    let s = policy_session(state, handle)?;
    s.extend_policy(cc::PolicyNV, &payload)?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyAuthorizeNV, Part 3 clause 23.22.
pub fn policy_authorize_nv(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let nv_handle = request.handle(1)?;
    let handle = request.handle(2)?;

    let index = state.nv.get(nv_handle).map_err(|e| e.with_handle(2))?;
    if index.read_locked {
        return Err(TpmRc(rc::NV_LOCKED));
    }
    let stored = index.read(0, index.public.data_size)?;
    let nv_name = index.name()?;

    let s = policy_session(state, handle)?;
    if !s.is_trial() {
        // The Index holds a TPMT_HA whose digest must match the session.
        let mut r = crate::tpm::marshal::Reader::new(&stored);
        let ha = crate::tpm::structures::base::TpmtHa::unmarshal(&mut r)?;
        if ha.hash_alg != s.auth_hash || ha.digest != s.policy.digest {
            return Err(TpmRc(rc::VALUE).with_handle(2));
        }
    }
    let digest_len = hash::digest_size(s.auth_hash)?;
    s.policy.digest = vec![0u8; digest_len];
    s.extend_policy(cc::PolicyAuthorizeNV, &nv_name)?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyCapability, Part 3 clause 23.23.
pub fn policy_capability(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let operand_b = Tpm2bOperand::unmarshal(&mut r)?;
    let offset = r.u16()?;
    let operation = r.u16()?;
    let capability = r.u32()?;
    let property = r.u32()?;

    let auth_hash = policy_session(state, handle)?.auth_hash;
    let args = hash::digest_parts(
        auth_hash,
        &[
            operand_b.as_slice(),
            &offset.to_be_bytes(),
            &operation.to_be_bytes(),
            &capability.to_be_bytes(),
            &property.to_be_bytes(),
        ],
    )?;
    let s = policy_session(state, handle)?;
    s.extend_policy(cc::PolicyCapability, &args)?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyParameters, Part 3 clause 23.24.
pub fn policy_parameters(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let p_hash = Tpm2bDigest::unmarshal(&mut r)?;

    let s = policy_session(state, handle)?;
    if p_hash.len() != hash::digest_size(s.auth_hash)? {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    s.extend_policy(cc::PolicyParameters, p_hash.as_slice())?;
    respond(|_| Ok(()))
}

/// TPM2_PolicyTransportSPDM, Part 3 clause 23.25.
///
/// This TPM has no SPDM transport, so the assertion can never hold outside a
/// trial session.
pub fn policy_transport_spdm(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let s = policy_session(state, handle)?;
    if !s.is_trial() {
        return Err(TpmRc(rc::CHANNEL));
    }
    s.extend_policy(cc::PolicyTransportSPDM, &[])?;
    respond(|_| Ok(()))
}

/// TPM2_Policy_AC_SendSelect, Part 3 clause 32.4.
pub fn policy_ac_send_select(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let object_name = Tpm2bName::unmarshal(&mut r)?;
    let auth_handle_name = Tpm2bName::unmarshal(&mut r)?;
    let ac_name = Tpm2bName::unmarshal(&mut r)?;
    let include_object = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(TpmRc(rc::VALUE).with_parameter(4)),
    };

    let s = policy_session(state, handle)?;
    let mut data = Vec::new();
    if include_object {
        data.extend_from_slice(object_name.as_slice());
    }
    data.extend_from_slice(auth_handle_name.as_slice());
    data.extend_from_slice(ac_name.as_slice());
    data.push(u8::from(include_object));
    s.extend_policy(cc::Policy_AC_SendSelect, &data)?;
    s.policy.command_code = Some(cc::AC_Send);
    respond(|_| Ok(()))
}

/// TPM2_FlushContext, Part 3 clause 28.4.
pub fn flush_context(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let handle = r.u32()?;

    if session::is_session_handle(handle) {
        state
            .sessions
            .remove(handle)
            .map_err(|e| e.with_parameter(1))?;
    } else if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state
            .objects
            .remove(handle)
            .map_err(|e| e.with_parameter(1))?;
        state.sessions.flush_bound_to(handle);
    } else {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    respond(|_| Ok(()))
}

/// True when `alg_id` may be the hash of a session.
pub fn is_session_hash(alg_id: u16) -> bool {
    alg_id != alg::NULL && hash::is_supported(alg_id)
}

/// The session type name, used in log messages.
pub fn session_type_name(session_type: u8) -> &'static str {
    match session_type {
        se::HMAC => "HMAC",
        se::POLICY => "policy",
        se::TRIAL => "trial",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::eo;

    #[test]
    fn comparisons_follow_the_operation() {
        let a = [0x00u8, 0x10];
        let b = [0x00u8, 0x20];
        assert_eq!(compare(&a, &b, eo::EQ), Some(false));
        assert_eq!(compare(&a, &a, eo::EQ), Some(true));
        assert_eq!(compare(&a, &b, eo::NEQ), Some(true));
        assert_eq!(compare(&a, &b, eo::UNSIGNED_LT), Some(true));
        assert_eq!(compare(&b, &a, eo::UNSIGNED_GT), Some(true));
        assert_eq!(compare(&a, &a, eo::UNSIGNED_GE), Some(true));
        assert_eq!(compare(&a, &a, eo::UNSIGNED_LE), Some(true));
    }

    #[test]
    fn signed_comparisons_use_the_top_bit() {
        let negative = [0xffu8, 0x00];
        let positive = [0x00u8, 0x01];
        assert_eq!(compare(&negative, &positive, eo::SIGNED_LT), Some(true));
        assert_eq!(compare(&negative, &positive, eo::UNSIGNED_LT), Some(false));
        assert_eq!(compare(&positive, &negative, eo::SIGNED_GT), Some(true));
    }

    #[test]
    fn bit_comparisons() {
        let value = [0b1010_1010u8];
        assert_eq!(compare(&value, &[0b1000_0000], eo::BITSET), Some(true));
        assert_eq!(compare(&value, &[0b0100_0000], eo::BITSET), Some(false));
        assert_eq!(compare(&value, &[0b0101_0101], eo::BITCLEAR), Some(true));
        assert_eq!(compare(&value, &[0b1000_0000], eo::BITCLEAR), Some(false));
    }

    #[test]
    fn a_length_mismatch_or_unknown_operation_has_no_answer() {
        assert_eq!(compare(&[0u8], &[0u8, 0], eo::EQ), None);
        assert_eq!(compare(&[0u8], &[0u8], 0x00ff), None);
    }

    #[test]
    fn session_type_names() {
        assert_eq!(session_type_name(se::HMAC), "HMAC");
        assert_eq!(session_type_name(se::POLICY), "policy");
        assert_eq!(session_type_name(se::TRIAL), "trial");
        assert_eq!(session_type_name(9), "unknown");
        assert!(is_session_hash(alg::SHA256));
        assert!(!is_session_hash(alg::NULL));
    }
}
