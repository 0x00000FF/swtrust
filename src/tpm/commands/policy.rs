//! Session and policy commands, Part 3 clauses 11 and 23.

use crate::tpm::constants::{alg, cc, rc, rh, se, st};
use crate::tpm::core::session::{self, Session};
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{ecc, hash, rand::Rng};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal, Writer};
use crate::tpm::structures::attributes::LocalityAttributes;
use crate::tpm::structures::base::{
    Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, Tpm2bOperand, Tpm2bTimeout,
};
use crate::tpm::structures::lists::{TpmlDigest, TpmlPcrSelection};
use crate::tpm::structures::schemes::SymDef;
use crate::tpm::structures::signature::{Ticket, VerifiedTicket};

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
    r.expect_end()?;

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
    // A salt is only meaningful with a key to decrypt it, and a key is only
    // useful when a salt arrives with it.
    if tpm_key == rh::NULL && !encrypted_salt.is_empty() {
        return Err(TpmRc(rc::VALUE).with_parameter(2));
    }
    let salt = if tpm_key == rh::NULL {
        Vec::new()
    } else {
        decrypt_salt(state, tpm_key, encrypted_salt.as_slice())?
    };

    let (bind_auth, bind_uses_lockout) = if bind == rh::NULL {
        (Vec::new(), false)
    } else {
        let entity = super::dispatch::entity(state, bind).map_err(|e| e.with_handle(2))?;
        (entity.auth, entity.uses_lockout)
    };
    // The bound entity is identified by its Name and its authorization value
    // together, so an entity that is removed and recreated with the same Name
    // but a different value is not the bound one. Part 1 clause 19.6.10.
    let bind_name = if bind == rh::NULL {
        Vec::new()
    } else {
        Session::bind_id(&super::dispatch::handle_name(state, bind)?, &bind_auth)
    };

    let nonce_tpm = state.rng.bytes(digest_size)?;
    let session_key = session::derive_session_key(
        auth_hash,
        &bind_auth,
        &salt,
        &nonce_tpm,
        nonce_caller.as_slice(),
    )?;

    let handle = state.sessions.allocate_handle(session_type)?;
    let mut s = Session::new(
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
    s.bind_uses_lockout = bind_uses_lockout;
    s.start_time = state.clock.time;
    s.time_epoch = state.clock.time_epoch;
    state.sessions.insert(s)?;

    respond_with_handle(handle, move |w| {
        Tpm2bNonce::new(nonce_tpm)?.marshal(w);
        Ok(())
    })
}

/// Recover the salt a caller encrypted to `tpm_key`.
///
/// Part 1 clause 19.6.4.2 protects the salt with the same construction as a
/// credential: RSA-OAEP with the label "SECRET" for an RSA key, and the KDFe
/// derivation of the shared point for an ECC key.
fn decrypt_salt(state: &TpmState, tpm_key: u32, encrypted: &[u8]) -> TpmResult<Vec<u8>> {
    use crate::tpm::structures::keys::{PublicId, PublicParms};

    let object = if crate::tpm::core::object::ObjectSlots::is_transient(tpm_key) {
        state.objects.object(tpm_key).map_err(|e| e.with_handle(1))?
    } else {
        state
            .persistent
            .get(&tpm_key)
            .ok_or(TpmRc(rc::HANDLE).with_handle(1))?
    };
    if !object
        .public
        .object_attributes
        .has(crate::tpm::structures::attributes::ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let name_alg = object.public.name_alg;

    match (&object.public.unique, object.public.object_type) {
        (PublicId::Rsa(modulus), alg::RSA) => {
            let PublicParms::Rsa { exponent, .. } = object.public.parameters else {
                return Err(TpmRc(rc::TYPE).with_handle(1));
            };
            let key = crate::tpm::crypto::rsa::RsaPrivate::from_prime(
                modulus.as_slice(),
                exponent,
                sensitive.sensitive.as_slice(),
            )?;
            let plain = crate::tpm::crypto::rsa::private_op(&key, encrypted)
                .map_err(|_| TpmRc(rc::VALUE).with_parameter(2))?;
            crate::tpm::crypto::rsa::oaep_decode(name_alg, &plain, b"SECRET\0")
                .map_err(|_| TpmRc(rc::VALUE).with_parameter(2))
        }
        (PublicId::Ecc(point), alg::ECC) => {
            let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
                return Err(TpmRc(rc::TYPE).with_handle(1));
            };
            // The encrypted salt is the caller's ephemeral public point.
            let peer = crate::tpm::structures::schemes::Tpm2bEccPoint::from_bytes(encrypted)
                .map_err(|_| TpmRc(rc::VALUE).with_parameter(2))?;
            let curve = ecc::Curve::new(curve_id)?;
            let private =
                crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;
            let (zx, _) = ecc::ecdh(
                &curve,
                &private,
                peer.point.x.as_slice(),
                peer.point.y.as_slice(),
            )
            .map_err(|_| TpmRc(rc::VALUE).with_parameter(2))?;
            crate::tpm::crypto::hmac::kdfe(
                name_alg,
                &zx,
                "SECRET",
                peer.point.x.as_slice(),
                point.x.as_slice(),
                (hash::digest_size(name_alg)? * 8) as u32,
            )
        }
        _ => Err(TpmRc(rc::TYPE).with_handle(1)),
    }
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

/// The policy update shared by TPM2_PolicySigned, TPM2_PolicySecret,
/// TPM2_PolicyTicket and TPM2_PolicyAuthorize.
///
/// Part 3 clause 23.2.3 makes this two sequential hashes rather than one:
///
/// ```text
/// policyDigest = H(policyDigest || commandCode || authName)
/// policyDigest = H(policyDigest || policyRef)
/// ```
fn policy_authorization_update(
    s: &mut Session,
    command_code: u32,
    auth_name: &[u8],
    policy_ref: &[u8],
) -> TpmResult<()> {
    s.extend_policy(command_code, auth_name)?;
    s.policy.digest = hash::digest_parts(s.auth_hash, &[&s.policy.digest, policy_ref])?;
    Ok(())
}

/// The HMAC of an authorization ticket, Part 3 clause 23.2.5.
///
/// `HMAC(proof, tag || cpHashA || policyRef || authName || timeout ||
///  timeEpoch || resetCount)`. The epoch and reset count are part of the
/// transcript so a ticket cannot outlive the clock it was issued against.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn authorization_ticket_hmac(
    state: &TpmState,
    hierarchy: u32,
    tag: u16,
    cp_hash_a: &[u8],
    policy_ref: &[u8],
    auth_name: &[u8],
    timeout: &[u8],
    with_nonce: bool,
) -> TpmResult<Vec<u8>> {
    let proof = state.hierarchy_proof(hierarchy)?.to_vec();
    let expires = timeout.iter().any(|b| *b != 0);
    let tag_bytes = tag.to_be_bytes();
    let epoch = state.clock.time_epoch.to_be_bytes();
    let reset = state.clock.total_reset_count.to_be_bytes();
    let mut parts: Vec<&[u8]> =
        vec![&tag_bytes, cp_hash_a, policy_ref, auth_name, timeout];
    // Part 3 clause 23.2.5 leaves the timeEpoch out when the ticket does not
    // expire, and the reset count out when it does not expire or when the
    // authorization already covered nonceTPM.
    if expires {
        parts.push(&epoch);
        if !with_nonce {
            parts.push(&reset);
        }
    }
    crate::tpm::crypto::hmac::hmac_parts(
        crate::tpm::config::CONTEXT_INTEGRITY_HASH_ALG,
        &proof,
        &parts,
    )
}

/// The hierarchy whose proof value keys a ticket for `auth_handle`.
///
/// Part 3 clause 23.2.5 keys the ticket with the proof of the hierarchy the
/// authorizing entity belongs to, so that changing that hierarchy's seed
/// invalidates the ticket.
fn ticket_hierarchy(state: &TpmState, auth_handle: u32) -> u32 {
    if crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(auth_handle) {
        return auth_handle;
    }
    if crate::tpm::core::object::ObjectSlots::is_transient(auth_handle) {
        if let Ok(o) = state.objects.object(auth_handle) {
            return o.hierarchy;
        }
    }
    if let Some(o) = state.persistent.get(&auth_handle) {
        return o.hierarchy;
    }
    if crate::tpm::core::nv::NvStore::is_nv_handle(auth_handle) {
        // An Index the platform created belongs to the platform hierarchy, so
        // a change of platform seed invalidates a ticket that used it.
        if let Ok(index) = state.nv.get(auth_handle) {
            return if index
                .public
                .attributes
                .has(crate::tpm::structures::attributes::NvAttributes::PLATFORMCREATE)
            {
                rh::PLATFORM
            } else {
                rh::OWNER
            };
        }
    }
    // TPM_RH_LOCKOUT and the other permanent handles sit with the platform
    // values in the permanent state.
    if auth_handle == rh::LOCKOUT || auth_handle == rh::PLATFORM_NV {
        return rh::PLATFORM;
    }
    rh::OWNER
}

/// The bit of a timeout that records that it also expires on a TPM Reset.
///
/// A timeout is a count of milliseconds, so the top bit is never part of a
/// real value and carries this flag from TPM2_PolicySigned to
/// TPM2_PolicyTicket instead.
const EXPIRES_ON_RESET: u64 = 1 << 63;

/// The timeout an authorization returns.
///
/// A non-negative expiration means the authorization does not expire, which
/// Part 3 clause 23.2.4 answers with an empty buffer. Otherwise Part 3 clause
/// 23.2.2 measures the limit from the start of the session when nonceTPM tied
/// the authorization to it, and takes the expiration as an absolute value when
/// it did not.
fn authorization_timeout(
    session_start_time: u64,
    expiration: i32,
    without_nonce: bool,
) -> Vec<u8> {
    if expiration >= 0 {
        return Vec::new();
    }
    let limit = (-(expiration as i64)) as u64 * 1000;
    let mut expires = if without_nonce {
        limit
    } else {
        session_start_time.saturating_add(limit)
    };
    if without_nonce {
        expires |= EXPIRES_ON_RESET;
    }
    expires.to_be_bytes().to_vec()
}

/// Record the command restriction an authorization carries.
///
/// Part 3 clause 23.2.2 refuses a second assertion that names a different
/// command, so a later signed authorization cannot replace the restriction an
/// earlier one set.
fn check_cp_hash(s: &Session, cp_hash_a: &[u8]) -> TpmResult<()> {
    if cp_hash_a.is_empty() {
        return Ok(());
    }
    if let Some(current) = &s.policy.cp_hash {
        if current.as_slice() != cp_hash_a {
            return Err(TpmRc(rc::CPHASH));
        }
        return Ok(());
    }
    if cp_hash_a.len() != hash::digest_size(s.auth_hash)? {
        return Err(TpmRc(rc::SIZE).with_parameter(2));
    }
    Ok(())
}

/// Apply the command restriction, once [`check_cp_hash`] has accepted it.
fn set_cp_hash(s: &mut Session, cp_hash_a: &[u8]) {
    if !cp_hash_a.is_empty() {
        s.policy.cp_hash = Some(cp_hash_a.to_vec());
    }
}

/// Record an expiry on a policy session.
///
/// Part 3 clause 23.2.4 lets a timeout only be lowered, so a second
/// authorization cannot extend what an earlier one allowed.
fn record_expiration(s: &mut Session, timeout: &[u8]) {
    let Some(expires) = timeout_value(timeout) else {
        return;
    };
    s.policy.expiration = Some(match s.policy.expiration {
        Some(current) => current.min(expires),
        None => expires,
    });
}

/// The expiry time in a timeout, without the reset flag.
fn timeout_value(timeout: &[u8]) -> Option<u64> {
    if timeout.len() != 8 {
        return None;
    }
    let raw = u64::from_be_bytes(timeout.try_into().ok()?);
    Some(raw & !EXPIRES_ON_RESET)
}

/// Build the ticket a policy authorization returns.
///
/// An expiration of zero means the authorization does not expire, so Part 3
/// clause 23.3.3 returns a null ticket because there is nothing to carry
/// forward. A trial session never produces a usable ticket either, because it
/// proved nothing.
#[allow(clippy::too_many_arguments)]
fn build_authorization_ticket(
    state: &TpmState,
    tag: u16,
    hierarchy: u32,
    expiration: i32,
    timeout: &[u8],
    cp_hash_a: &[u8],
    policy_ref: &[u8],
    auth_name: &[u8],
    is_trial: bool,
    with_nonce: bool,
) -> TpmResult<Ticket> {
    if expiration >= 0 || is_trial {
        return Ok(Ticket::null(tag));
    }
    let hmac = authorization_ticket_hmac(
        state,
        hierarchy,
        tag,
        cp_hash_a,
        policy_ref,
        auth_name,
        timeout,
        with_nonce,
    )?;
    Ok(Ticket {
        tag,
        hierarchy,
        digest: Tpm2bDigest::new(hmac)?,
    })
}

/// TPM2_PolicySigned, Part 3 clause 23.3.
pub fn policy_signed(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_object = request.handle(0)?;
    let policy_session_handle = request.handle(1)?;
    let mut r = request.reader();
    let nonce_tpm = Tpm2bNonce::unmarshal(&mut r)?;
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;
    let policy_ref = Tpm2bNonce::unmarshal(&mut r)?;
    let expiration = r.u32()? as i32;
    let signature =
        crate::tpm::structures::signature::TpmtSignature::unmarshal(&mut r)?;
    r.expect_end()?;

    let auth_name = super::dispatch::handle_name(state, auth_object)
        .map_err(|e| e.with_handle(1))?;
    let is_trial = policy_session(state, policy_session_handle)?.is_trial();
    let session_nonce = policy_session(state, policy_session_handle)?
        .nonce_tpm
        .clone();
    let auth_hash = policy_session(state, policy_session_handle)?.auth_hash;

    if !is_trial {
        // The nonce, if given, must be the current session nonce, so an
        // authorization cannot be replayed into another session.
        if !nonce_tpm.is_empty() && nonce_tpm.as_slice() != session_nonce.as_slice() {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
        // aHash = H(nonceTPM || expiration || cpHashA || policyRef), signed by
        // the authorizing key, Part 3 clause 23.3.2.
        let a_hash = hash::digest_parts(
            signature.hash_alg().unwrap_or(auth_hash),
            &[
                nonce_tpm.as_slice(),
                &expiration.to_be_bytes(),
                cp_hash_a.as_slice(),
                policy_ref.as_slice(),
            ],
        )?;
        let object = if crate::tpm::core::object::ObjectSlots::is_transient(auth_object) {
            state.objects.object(auth_object).map_err(|e| e.with_handle(1))?
        } else {
            state
                .persistent
                .get(&auth_object)
                .ok_or(TpmRc(rc::HANDLE).with_handle(1))?
        };
        // Part 3 clause 23.3.1 reports a signature that does not cover
        // toBeSigned as a failed authorization, not as a bad parameter.
        super::crypto::verify_digest_public(object, &a_hash, &signature)
            .map_err(|_| TpmRc(rc::POLICY_FAIL))?;
    }

    // The timeout is the absolute time the authorization expires, with the
    // top bit recording that it also expires on a TPM Reset.
    let session_start_time = policy_session(state, policy_session_handle)?.start_time;
    let timeout = authorization_timeout(session_start_time, expiration, nonce_tpm.is_empty());
    // Part 3 clause 23.2.2 refuses an authorization whose limit has already
    // gone by, and one recorded against an earlier run of Time.
    if let Some(expires) = timeout_value(&timeout) {
        let s = policy_session(state, policy_session_handle)?;
        let stale = s.time_epoch != state.clock.time_epoch;
        if stale || expires < state.clock.time {
            return Err(TpmRc(rc::EXPIRED).with_parameter(4));
        }
    }
    let hierarchy = ticket_hierarchy(state, auth_object);
    let ticket = build_authorization_ticket(
        state,
        st::AUTH_SIGNED,
        hierarchy,
        expiration,
        &timeout,
        cp_hash_a.as_slice(),
        policy_ref.as_slice(),
        &auth_name,
        is_trial,
        !nonce_tpm.is_empty(),
    )?;

    // Part 3 clause 5.6 leaves the TPM unchanged when a command fails, so the
    // restriction is checked before the policy digest moves.
    let s = policy_session(state, policy_session_handle)?;
    check_cp_hash(s, cp_hash_a.as_slice())?;
    policy_authorization_update(s, cc::PolicySigned, &auth_name, policy_ref.as_slice())?;
    set_cp_hash(s, cp_hash_a.as_slice());
    if expiration < 0 {
        record_expiration(s, &timeout);
    }

    respond(move |w| {
        Tpm2bTimeout::new(timeout)?.marshal(w);
        ticket.marshal(w);
        Ok(())
    })
}

/// TPM2_PolicySecret, Part 3 clause 23.4.
pub fn policy_secret(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth_handle = request.handle(0)?;
    let policy_session_handle = request.handle(1)?;
    let mut r = request.reader();
    let nonce_tpm = Tpm2bNonce::unmarshal(&mut r)?;
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;
    let policy_ref = Tpm2bNonce::unmarshal(&mut r)?;
    let expiration = r.u32()? as i32;
    r.expect_end()?;

    let auth_name = super::dispatch::handle_name(state, auth_handle)
        .map_err(|e| e.with_handle(1))?;
    let is_trial = policy_session(state, policy_session_handle)?.is_trial();
    let session_nonce = policy_session(state, policy_session_handle)?
        .nonce_tpm
        .clone();
    // A supplied nonce ties the authorization to this session, so it must be
    // the current one, Part 3 clause 23.4.2.
    if !is_trial && !nonce_tpm.is_empty() && nonce_tpm.as_slice() != session_nonce.as_slice() {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }

    let session_start_time = policy_session(state, policy_session_handle)?.start_time;
    let timeout = authorization_timeout(session_start_time, expiration, nonce_tpm.is_empty());
    if let Some(expires) = timeout_value(&timeout) {
        let s = policy_session(state, policy_session_handle)?;
        let stale = s.time_epoch != state.clock.time_epoch;
        if stale || expires < state.clock.time {
            return Err(TpmRc(rc::EXPIRED).with_parameter(4));
        }
    }
    let hierarchy = ticket_hierarchy(state, auth_handle);
    let ticket = build_authorization_ticket(
        state,
        st::AUTH_SECRET,
        hierarchy,
        expiration,
        &timeout,
        cp_hash_a.as_slice(),
        policy_ref.as_slice(),
        &auth_name,
        is_trial,
        !nonce_tpm.is_empty(),
    )?;

    // Part 3 clause 5.6 leaves the TPM unchanged when a command fails, so the
    // restriction is checked before the policy digest moves.
    let s = policy_session(state, policy_session_handle)?;
    check_cp_hash(s, cp_hash_a.as_slice())?;
    policy_authorization_update(s, cc::PolicySecret, &auth_name, policy_ref.as_slice())?;
    set_cp_hash(s, cp_hash_a.as_slice());
    if expiration < 0 {
        record_expiration(s, &timeout);
    }

    respond(move |w| {
        Tpm2bTimeout::new(timeout)?.marshal(w);
        ticket.marshal(w);
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
    r.expect_end()?;

    // A null ticket carries no proof, so it authorizes nothing.
    if ticket.digest.is_empty() {
        return Err(TpmRc(rc::TICKET).with_parameter(5));
    }
    // The authorization that produced the ticket recorded in the top bit of
    // the timeout whether it also expires on a TPM Reset, which decides which
    // counters went into the ticket.
    let expires_on_reset = _timeout
        .as_slice()
        .first()
        .map(|b| b & 0x80 != 0)
        .unwrap_or(false);
    // The ticket must be one this TPM produced for exactly these values.
    let expected = authorization_ticket_hmac(
        state,
        ticket.hierarchy,
        ticket.tag,
        cp_hash_a.as_slice(),
        policy_ref.as_slice(),
        auth_name.as_slice(),
        _timeout.as_slice(),
        !expires_on_reset,
    )
    .map_err(|_| TpmRc(rc::TICKET).with_parameter(5))?;
    if !crate::tpm::core::protect::constant_time_eq(&expected, ticket.digest.as_slice()) {
        return Err(TpmRc(rc::TICKET).with_parameter(5));
    }
    // An expired ticket no longer authorizes anything. Part 3 clause 23.2.2
    // also refuses one whose run of Time has passed, which the epoch inside
    // the ticket already covers for a ticket that expires.
    if let Some(expires) = timeout_value(_timeout.as_slice()) {
        if state.clock.time > expires {
            return Err(TpmRc(rc::EXPIRED).with_parameter(1));
        }
    }
    let command_code = if ticket.tag == st::AUTH_SIGNED {
        cc::PolicySigned
    } else {
        cc::PolicySecret
    };
    let s = policy_session(state, policy_session_handle)?;
    check_cp_hash(s, cp_hash_a.as_slice())?;
    policy_authorization_update(s, command_code, auth_name.as_slice(), policy_ref.as_slice())?;
    set_cp_hash(s, cp_hash_a.as_slice());
    record_expiration(s, _timeout.as_slice());
    respond(|_| Ok(()))
}

/// TPM2_PolicyOR, Part 3 clause 23.6.
pub fn policy_or(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let list = TpmlDigest::unmarshal(&mut r)?;
    r.expect_end()?;

    let s = policy_session(state, handle)?;
    // The current digest must be one of the branches. A trial session is
    // building a policy rather than satisfying one, so Part 3 clause 23.6.3
    // skips the check for it.
    if !s.is_trial() {
        let matched = list
            .digests
            .iter()
            .any(|d| d.as_slice() == s.policy.digest.as_slice());
        if !matched {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
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
    r.expect_end()?;

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
    r.expect_end()?;
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
    r.expect_end()?;
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
    s.policy.physical_presence_required = true;
    respond(|_| Ok(()))
}

/// TPM2_PolicyCpHash, Part 3 clause 23.13.
pub fn policy_cp_hash(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let cp_hash_a = Tpm2bDigest::unmarshal(&mut r)?;
    r.expect_end()?;

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
    r.expect_end()?;

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
    r.expect_end()?;
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
    r.expect_end()?;

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
    r.expect_end()?;

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
    // Version 185 has three commands that produce a TPMT_TK_VERIFIED, each
    // with its own tag, and Part 3 clause 23.16.1 takes any of them.
    let check_ticket = VerifiedTicket::unmarshal(&mut r)?;
    r.expect_end()?;

    // Part 3 clause 23.16.1 requires keySign to be a well formed Name: a hash
    // algorithm this TPM implements followed by a digest of its size.
    if key_sign.as_slice().len() < 2 {
        return Err(TpmRc(rc::SIZE).with_parameter(3));
    }
    let name_alg = u16::from_be_bytes([key_sign.as_slice()[0], key_sign.as_slice()[1]]);
    let name_digest_size = hash::digest_size(name_alg)
        .map_err(|_| TpmRc(rc::HASH).with_parameter(3))?;
    if key_sign.as_slice().len() != 2 + name_digest_size {
        return Err(TpmRc(rc::SIZE).with_parameter(3));
    }

    let is_trial = policy_session(state, handle)?.is_trial();
    if !is_trial {
        // The running digest must already equal the policy that was approved.
        if policy_session(state, handle)?.policy.digest.as_slice()
            != approved_policy.as_slice()
        {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
        // Part 3 clause 23.16.1 reports every way the ticket can fail to
        // authorize the approved policy as TPM_RC_POLICY.
        if check_ticket.hmac.is_empty() {
            return Err(TpmRc(rc::POLICY));
        }
        // toBeSigned is approvedPolicy followed by policyRef. What the ticket
        // committed to depends on which command produced it, Part 3 clause
        // 23.16.1 and clause 23.16.2:
        //
        // - TPM2_VerifySignature took a digest and left no record of the hash
        //   that made it, so the Name algorithm of keySign is used;
        // - TPM2_VerifyDigestSignature recorded that hash in the ticket;
        // - TPM2_VerifySequenceComplete took the message itself.
        let mut to_be_signed = approved_policy.as_slice().to_vec();
        to_be_signed.extend_from_slice(policy_ref.as_slice());
        let signed = match check_ticket.tag {
            st::MESSAGE_VERIFIED => to_be_signed,
            st::DIGEST_VERIFIED => {
                let alg = check_ticket.digest_alg.ok_or(TpmRc(rc::POLICY))?;
                hash::digest(alg, &to_be_signed)?
            }
            _ => hash::digest(name_alg, &to_be_signed)?,
        };
        let proof = state
            .hierarchy_proof(check_ticket.hierarchy)
            .map_err(|_| TpmRc(rc::POLICY))?
            .to_vec();
        let expected = super::crypto::verified_ticket_hmac(
            &proof,
            check_ticket.tag,
            &signed,
            key_sign.as_slice(),
            check_ticket.digest_alg,
        )?;
        if !crate::tpm::core::protect::constant_time_eq(
            &expected,
            check_ticket.hmac.as_slice(),
        ) {
            return Err(TpmRc(rc::POLICY));
        }
    }
    let s = policy_session(state, handle)?;
    // The digest restarts and records who approved the policy, with the same
    // two step update Part 3 clause 23.2.3 defines.
    let digest_len = hash::digest_size(s.auth_hash)?;
    s.policy.digest = vec![0u8; digest_len];
    policy_authorization_update(
        s,
        cc::PolicyAuthorize,
        key_sign.as_slice(),
        policy_ref.as_slice(),
    )?;
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
    r.expect_end()?;

    let auth_hash = policy_session(state, handle)?.auth_hash;
    // Part 3 clause 23.15.3 always covers both Names in nameHash; includeObject
    // only decides whether the object Name goes into the policy digest.
    let name_hash =
        hash::digest_parts(auth_hash, &[object_name.as_slice(), new_parent_name.as_slice()])?;

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
    r.expect_end()?;

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
    r.expect_end()?;

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
    r.expect_end()?;

    let s = policy_session(state, handle)?;
    if p_hash.len() != hash::digest_size(s.auth_hash)? {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    s.extend_policy(cc::PolicyParameters, p_hash.as_slice())?;
    s.policy.parameters_hash = Some(p_hash.as_slice().to_vec());
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
    r.expect_end()?;

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
    r.expect_end()?;

    if session::is_session_handle(handle) {
        state
            .sessions
            .remove(handle)
            .map_err(|e| e.with_parameter(1))?;
        // Part 1 clause 17.2 gives up exclusivity when the session that held
        // it is flushed.
        if state.audit.exclusive_session == handle {
            state.audit.exclusive_session = rh::UNASSIGNED;
        }
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
    use crate::tpm::constants::{eo, hc};

    /// A policy session with nothing asserted yet.
    fn empty_policy_session() -> Session {
        Session::new(
            hc::POLICY_SESSION_FIRST,
            se::POLICY,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            Vec::new(),
            rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap()
    }

    #[test]
    fn a_command_restriction_may_not_be_replaced() {
        let mut s = empty_policy_session();

        // An empty cpHashA leaves the session unrestricted.
        check_cp_hash(&s, &[]).unwrap();
        set_cp_hash(&mut s, &[]);
        assert!(s.policy.cp_hash.is_none());

        check_cp_hash(&s, &[1u8; 32]).unwrap();
        set_cp_hash(&mut s, &[1u8; 32]);
        assert_eq!(s.policy.cp_hash.as_deref(), Some(&[1u8; 32][..]));

        // Part 3 clause 23.2.2 refuses a second assertion that names a
        // different command, and the check runs before anything changes.
        assert_eq!(check_cp_hash(&s, &[2u8; 32]).unwrap_err(), TpmRc(rc::CPHASH));
        assert_eq!(s.policy.cp_hash.as_deref(), Some(&[1u8; 32][..]));

        // Repeating the same one is allowed.
        check_cp_hash(&s, &[1u8; 32]).unwrap();

        // A value that is not the size of the policy digest is refused.
        let fresh = empty_policy_session();
        assert_eq!(
            check_cp_hash(&fresh, &[3u8; 20]).unwrap_err(),
            TpmRc(rc::SIZE).with_parameter(2)
        );
    }

    #[test]
    fn an_expiry_may_only_be_lowered() {
        let mut s = empty_policy_session();

        record_expiration(&mut s, &5000u64.to_be_bytes());
        assert_eq!(s.policy.expiration, Some(5000));

        // Part 3 clause 23.2.4 lets a later authorization shorten the limit.
        record_expiration(&mut s, &3000u64.to_be_bytes());
        assert_eq!(s.policy.expiration, Some(3000));

        // It may not extend it.
        record_expiration(&mut s, &9000u64.to_be_bytes());
        assert_eq!(s.policy.expiration, Some(3000));

        // An authorization that does not expire leaves the limit alone.
        record_expiration(&mut s, &[]);
        assert_eq!(s.policy.expiration, Some(3000));
    }

    #[test]
    fn every_startup_begins_a_new_time_epoch() {
        let mut state = TpmState::manufacture().unwrap();
        let start = state.clock.time_epoch;
        state.on_startup_clear().unwrap();
        let after_reset = state.clock.time_epoch;
        assert_ne!(after_reset, start);

        state.shutdown_type = crate::tpm::constants::su::CLEAR;
        state.on_startup_clear().unwrap();
        assert_ne!(state.clock.time_epoch, after_reset);

        // A ticket made in one epoch cannot be recomputed in the next.
        let hmac = |s: &TpmState| {
            authorization_ticket_hmac(
                s,
                rh::OWNER,
                st::AUTH_SIGNED,
                b"cp",
                b"ref",
                b"name",
                &5000u64.to_be_bytes(),
                true,
            )
            .unwrap()
        };
        let before = hmac(&state);
        state.on_startup_clear().unwrap();
        assert_ne!(hmac(&state), before);
    }

    #[test]
    fn a_ticket_leaves_out_the_counters_it_should() {
        let mut state = TpmState::manufacture().unwrap();
        state.on_startup_clear().unwrap();
        state.clock.time = 1000;

        let hmac = |timeout: &[u8], with_nonce: bool| {
            authorization_ticket_hmac(
                &state,
                rh::OWNER,
                st::AUTH_SIGNED,
                b"cp",
                b"ref",
                b"name",
                timeout,
                with_nonce,
            )
            .unwrap()
        };

        // With no timeout neither counter is covered, so the nonce makes no
        // difference.
        assert_eq!(hmac(&[], true), hmac(&[], false));

        // With a timeout the reset count goes in only when no nonceTPM was
        // used, so the two differ.
        let timeout = 5000u64.to_be_bytes();
        assert_ne!(hmac(&timeout, true), hmac(&timeout, false));
    }

    #[test]
    fn a_ticket_uses_the_hierarchy_of_the_authorizing_entity() {
        use crate::tpm::structures::attributes::NvAttributes;
        use crate::tpm::structures::nv::NvPublic;

        let mut state = TpmState::manufacture().unwrap();
        let mut define = |handle: u32, attributes: u32| {
            state
                .nv
                .define(crate::tpm::core::nv::NvIndex {
                    public: NvPublic {
                        nv_index: handle,
                        name_alg: alg::SHA256,
                        attributes: NvAttributes(attributes),
                        auth_policy: Tpm2bDigest::empty(),
                        data_size: 8,
                    },
                    auth: Vec::new(),
                    data: Vec::new(),
                    read_locked: false,
                    write_locked: false,
                })
                .unwrap();
        };
        define(hc::NV_INDEX_FIRST, NvAttributes::AUTHREAD);
        define(
            hc::NV_INDEX_FIRST + 1,
            NvAttributes::AUTHREAD | NvAttributes::PLATFORMCREATE,
        );

        assert_eq!(ticket_hierarchy(&state, hc::NV_INDEX_FIRST), rh::OWNER);
        assert_eq!(
            ticket_hierarchy(&state, hc::NV_INDEX_FIRST + 1),
            rh::PLATFORM,
            "an Index the platform created keys with the platform proof"
        );
        assert_eq!(ticket_hierarchy(&state, rh::LOCKOUT), rh::PLATFORM);
        assert_eq!(ticket_hierarchy(&state, rh::ENDORSEMENT), rh::ENDORSEMENT);
    }

    #[test]
    fn a_timeout_carries_the_reset_flag_in_its_top_bit() {
        let mut state = TpmState::manufacture().unwrap();
        state.clock.time = 2000;

        // A non-negative expiration does not expire at all.
        assert!(authorization_timeout(state.clock.time, 0, true).is_empty());

        // With a nonceTPM the limit is measured from when the session started,
        // not from when the authorization arrived.
        let bound = authorization_timeout(500, -1, false);
        assert_eq!(timeout_value(&bound), Some(1500));
        assert_eq!(bound[0] & 0x80, 0);

        // Without one the expiration is the absolute limit and the ticket also
        // expires on a TPM Reset.
        let unbound = authorization_timeout(500, -1, true);
        assert_eq!(timeout_value(&unbound), Some(1000));
        assert_eq!(unbound[0] & 0x80, 0x80);
    }

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
