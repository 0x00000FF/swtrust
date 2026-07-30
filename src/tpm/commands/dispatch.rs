//! Command dispatch and authorization, Part 1 clauses 18 to 21.
//!
//! The order here follows Part 3 clause 5: the header is checked, the handles
//! are read and resolved, the session area is parsed, the first parameter is
//! decrypted if a session asks for it, each authorization is checked, the
//! command runs, and the response is built with the session nonces rolled
//! forward and the first response parameter encrypted if asked.

use crate::tpm::config;
use crate::tpm::constants::{alg, cc, hc, rc, rh, se, st};
use crate::tpm::core::names;
use crate::tpm::core::object::ObjectSlots;
use crate::tpm::core::protect::constant_time_eq;
use crate::tpm::core::session::{self, Session};
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::rand::Rng;
use crate::tpm::crypto::sym;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::SessionAttributes;
use crate::tpm::structures::base::{Tpm2bAuth, Tpm2bNonce};
use crate::tpm::structures::capability::{AuthCommand, AuthResponse};

use super::table::{self, CommandInfo};

/// Length of a command or response header.
pub const HEADER_SIZE: usize = 10;

/// One authorization taken from the command.
#[derive(Debug, Clone)]
pub struct SessionInput {
    pub handle: u32,
    pub nonce_caller: Vec<u8>,
    pub attributes: SessionAttributes,
    pub hmac: Vec<u8>,
}

/// A parsed command, ready to run.
#[derive(Debug)]
pub struct Request {
    pub info: &'static CommandInfo,
    pub tag: u16,
    pub code: u32,
    pub handles: Vec<u32>,
    pub sessions: Vec<SessionInput>,
    /// The parameter area, decrypted if a session asked for it.
    pub parameters: Vec<u8>,
    pub locality: u8,
}

impl Request {
    /// A reader over the parameter area.
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.parameters)
    }

    /// The handle at `index`, or TPM_RC_VALUE when there are fewer.
    pub fn handle(&self, index: usize) -> TpmResult<u32> {
        self.handles.get(index).copied().ok_or(TpmRc(rc::VALUE))
    }
}

/// What a command produces.
#[derive(Debug, Default)]
pub struct Response {
    /// The handle that leads the response, when the command returns one.
    pub handle: Option<u32>,
    /// The marshalled response parameters.
    pub parameters: Vec<u8>,
}

impl Response {
    pub fn empty() -> Response {
        Response::default()
    }

    /// Build a response from a writer.
    pub fn from_writer(w: Writer) -> TpmResult<Response> {
        Ok(Response {
            handle: None,
            parameters: w.finish()?,
        })
    }

    /// Build a response that leads with a handle.
    pub fn with_handle(handle: u32, w: Writer) -> TpmResult<Response> {
        Ok(Response {
            handle: Some(handle),
            parameters: w.finish()?,
        })
    }
}

/// The entity an authorization applies to.
pub struct Entity {
    pub name: Vec<u8>,
    pub auth: Vec<u8>,
    pub policy: Option<(u16, Vec<u8>)>,
    /// True when authorization failures count against the lockout.
    pub uses_lockout: bool,
    /// True when the entity accepts its authValue for user role actions.
    pub user_with_auth: bool,
}

/// Resolve the Name of a handle for the cpHash.
pub fn handle_name(state: &TpmState, handle: u32) -> TpmResult<Vec<u8>> {
    if names::name_is_handle(handle) {
        return Ok(names::handle_name(handle));
    }
    if ObjectSlots::is_transient(handle) {
        return Ok(state.objects.get(handle)?.name().to_vec());
    }
    if (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&handle) {
        let object = state
            .persistent
            .get(&handle)
            .ok_or(TpmRc(rc::HANDLE))?;
        return Ok(object.name.clone());
    }
    if crate::tpm::core::nv::NvStore::is_nv_handle(handle) {
        return state.nv.get(handle)?.name();
    }
    Ok(names::handle_name(handle))
}

/// Resolve the authorization values of a handle.
pub fn entity(state: &TpmState, handle: u32) -> TpmResult<Entity> {
    use crate::tpm::structures::attributes::{NvAttributes, ObjectAttributes};

    let name = handle_name(state, handle)?;

    // The four hierarchies, the lockout authority and the platform NV control.
    //
    // Part 1 clause 19.8.2 exempts platformAuth from dictionary attack
    // protection, because the platform is trusted to rate limit itself. The
    // storage and endorsement hierarchies are protected, and the NULL hierarchy
    // has no authorization value to guess.
    if crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(handle) {
        let h = state.hierarchies.get(handle)?;
        return Ok(Entity {
            name,
            auth: h.auth.clone(),
            policy: policy_of(&h.policy),
            uses_lockout: matches!(handle, rh::OWNER | rh::ENDORSEMENT),
            user_with_auth: true,
        });
    }
    if handle == rh::LOCKOUT {
        // Lockout authorization is held with the platform hierarchy values in
        // the permanent state; it has its own authValue and policy.
        return Ok(Entity {
            name,
            auth: state.lockout_auth.clone(),
            policy: policy_of(&state.lockout_policy),
            uses_lockout: true,
            user_with_auth: true,
        });
    }
    if handle == rh::PLATFORM_NV {
        let h = state.hierarchies.get(rh::PLATFORM)?;
        return Ok(Entity {
            name,
            auth: h.auth.clone(),
            policy: policy_of(&h.policy),
            uses_lockout: false,
            user_with_auth: true,
        });
    }
    if (hc::PCR_FIRST..=hc::PCR_LAST).contains(&handle) {
        return Ok(Entity {
            name,
            auth: state.pcr_auth.clone(),
            policy: policy_of(&state.pcr_policy),
            uses_lockout: false,
            user_with_auth: true,
        });
    }
    if ObjectSlots::is_transient(handle) {
        let slot = state.objects.get(handle)?;
        let (policy, user_with_auth, no_da) = match slot {
            crate::tpm::core::object::Slot::Object(o) => (
                object_policy(&o.public),
                o.public
                    .object_attributes
                    .has(ObjectAttributes::USER_WITH_AUTH),
                o.public.object_attributes.has(ObjectAttributes::NO_DA),
            ),
            crate::tpm::core::object::Slot::Sequence(_) => (None, true, true),
        };
        return Ok(Entity {
            name,
            auth: slot.auth_value().to_vec(),
            policy,
            uses_lockout: !no_da,
            user_with_auth,
        });
    }
    if (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&handle) {
        let object = state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))?;
        return Ok(Entity {
            name,
            auth: object.auth_value().to_vec(),
            policy: object_policy(&object.public),
            uses_lockout: !object
                .public
                .object_attributes
                .has(ObjectAttributes::NO_DA),
            user_with_auth: object
                .public
                .object_attributes
                .has(ObjectAttributes::USER_WITH_AUTH),
        });
    }
    if crate::tpm::core::nv::NvStore::is_nv_handle(handle) {
        let index = state.nv.get(handle)?;
        let policy = if index.public.auth_policy.is_empty() {
            None
        } else {
            Some((
                index.public.name_alg,
                index.public.auth_policy.as_slice().to_vec(),
            ))
        };
        return Ok(Entity {
            name,
            auth: index.auth.clone(),
            policy,
            uses_lockout: !index.public.attributes.has(NvAttributes::NO_DA),
            user_with_auth: true,
        });
    }
    Err(TpmRc(rc::HANDLE))
}

fn policy_of(policy: &crate::tpm::structures::base::TpmtHa) -> Option<(u16, Vec<u8>)> {
    if policy.hash_alg == alg::NULL || policy.digest.is_empty() {
        None
    } else {
        Some((policy.hash_alg, policy.digest.clone()))
    }
}

fn object_policy(
    public: &crate::tpm::structures::keys::TpmtPublic,
) -> Option<(u16, Vec<u8>)> {
    if public.auth_policy.is_empty() {
        None
    } else {
        Some((public.name_alg, public.auth_policy.as_slice().to_vec()))
    }
}

/// Parse a command buffer into a request.
///
/// The parameter area is returned as received; decryption happens once the
/// sessions are known.
pub fn parse(state: &TpmState, buf: &[u8], locality: u8) -> TpmResult<Request> {
    let header = crate::tpm::device::parse_header(buf)?;
    let info = table::lookup(header.code).ok_or(TpmRc(rc::COMMAND_CODE))?;

    let mut r = Reader::new(&buf[HEADER_SIZE..]);
    let mut handles = Vec::with_capacity(info.handles as usize);
    for _ in 0..info.handles {
        handles.push(r.u32()?);
    }

    let mut sessions = Vec::new();
    if header.tag == st::SESSIONS {
        let auth_size = r.u32()? as usize;
        if auth_size < 9 {
            return Err(TpmRc(rc::AUTHSIZE));
        }
        let mut area = r.sub(auth_size)?;
        while !area.is_empty() {
            if sessions.len() >= config::MAX_SESSION_NUM {
                return Err(TpmRc(rc::AUTHSIZE));
            }
            let a = AuthCommand::unmarshal(&mut area)?;
            sessions.push(SessionInput {
                handle: a.session_handle,
                nonce_caller: a.nonce.as_slice().to_vec(),
                attributes: a.session_attributes,
                hmac: a.hmac.as_slice().to_vec(),
            });
        }
        if sessions.is_empty() {
            return Err(TpmRc(rc::AUTHSIZE));
        }
    } else if info.auth_handles > 0 {
        // A command whose handles need authorization must carry sessions.
        return Err(TpmRc(rc::AUTH_MISSING));
    }

    let parameters = r.take_rest().to_vec();
    let _ = state;
    Ok(Request {
        info,
        tag: header.tag,
        code: header.code,
        handles,
        sessions,
        parameters,
        locality,
    })
}

/// Undo the parameter encryption a session applied to the first parameter.
///
/// Part 1 clause 21.3 encrypts only the first parameter of the command, and
/// only when it is a sized buffer.
pub fn decrypt_parameters(state: &TpmState, request: &mut Request) -> TpmResult<()> {
    let Some((index, input)) = request
        .sessions
        .iter()
        .enumerate()
        .find(|(_, s)| s.attributes.has(SessionAttributes::DECRYPT))
    else {
        return Ok(());
    };
    if input.handle == rh::RS_PW {
        return Err(TpmRc(rc::ATTRIBUTES).with_session(index + 1));
    }
    let s = state
        .sessions
        .get(input.handle)
        .map_err(|e| e.with_session(index + 1))?;
    let body = first_sized_parameter(&request.parameters)
        .ok_or_else(|| TpmRc(rc::SIZE).with_parameter(1))?;
    let plain = transform_parameter(state, s, input, body, false)?;
    splice_first_parameter(&mut request.parameters, &plain);
    Ok(())
}

/// Encrypt the first response parameter for the session that asked.
pub fn encrypt_parameters(
    state: &TpmState,
    request: &Request,
    parameters: &mut Vec<u8>,
) -> TpmResult<()> {
    let Some((index, input)) = request
        .sessions
        .iter()
        .enumerate()
        .find(|(_, s)| s.attributes.has(SessionAttributes::ENCRYPT))
    else {
        return Ok(());
    };
    if input.handle == rh::RS_PW {
        return Err(TpmRc(rc::ATTRIBUTES).with_session(index + 1));
    }
    let s = state.sessions.get(input.handle)?;
    let Some(body) = first_sized_parameter(parameters) else {
        return Ok(());
    };
    let cipher = transform_parameter(state, s, input, body, true)?;
    splice_first_parameter(parameters, &cipher);
    Ok(())
}

/// The body of the sized parameter at position `index`, counting from zero.
///
/// Only the leading parameters that are themselves TPM2B can be located this
/// way, which is all a policy assertion needs.
fn first_sized_parameter_at(parameters: &[u8], index: usize) -> Option<&[u8]> {
    let mut rest = parameters;
    for _ in 0..index {
        if rest.len() < 2 {
            return None;
        }
        let size = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() < 2 + size {
            return None;
        }
        rest = &rest[2 + size..];
    }
    first_sized_parameter(rest)
}

/// The body of the leading TPM2B in a parameter area.
fn first_sized_parameter(parameters: &[u8]) -> Option<&[u8]> {
    if parameters.len() < 2 {
        return None;
    }
    let size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
    if parameters.len() < 2 + size {
        return None;
    }
    Some(&parameters[2..2 + size])
}

/// Replace the body of the leading TPM2B, which keeps its length.
fn splice_first_parameter(parameters: &mut [u8], body: &[u8]) {
    parameters[2..2 + body.len()].copy_from_slice(body);
}

/// Apply the session's parameter encryption to `body`.
///
/// The nonce order differs between the two directions: a command uses
/// nonceCaller as the newer nonce, a response uses nonceTPM.
fn transform_parameter(
    state: &TpmState,
    s: &Session,
    input: &SessionInput,
    body: &[u8],
    response: bool,
) -> TpmResult<Vec<u8>> {
    let (newer, older) = if response {
        (s.nonce_tpm.clone(), input.nonce_caller.clone())
    } else {
        (input.nonce_caller.clone(), s.nonce_tpm.clone())
    };
    // The key material is the session key followed by the authValue of the
    // first handle, when that handle is one the session authorizes.
    let extra = first_handle_auth(state, s, input)?;

    match s.symmetric.algorithm {
        alg::XOR => {
            let mut out = body.to_vec();
            let mut key = s.session_key.clone();
            key.extend_from_slice(session::trim_auth(&extra));
            sym::xor_obfuscate(s.symmetric.key_bits, &key, &newer, &older, &mut out)?;
            Ok(out)
        }
        alg::AES => {
            let block = sym::block_size(alg::AES)?;
            let (key, iv) = session::parameter_encryption_key(
                s.auth_hash,
                &s.session_key,
                &extra,
                &newer,
                &older,
                s.symmetric.key_bits,
                block,
            )?;
            if response {
                sym::cfb_encrypt(&key, &iv, body)
            } else {
                sym::cfb_decrypt(&key, &iv, body)
            }
        }
        _ => Err(TpmRc(rc::SYMMETRIC)),
    }
}

/// The authorization value folded into a parameter encryption key.
fn first_handle_auth(
    state: &TpmState,
    s: &Session,
    _input: &SessionInput,
) -> TpmResult<Vec<u8>> {
    // Part 1 clause 21.3 uses the authValue of the entity the session
    // authorizes, and nothing when the session is bound to that entity.
    if s.bind != rh::NULL {
        return Ok(Vec::new());
    }
    let _ = state;
    Ok(Vec::new())
}

/// Check one authorization.
///
/// `index` is the position of the session, counting from one, so a failure can
/// name it.
#[allow(clippy::too_many_arguments)]
pub fn check_authorization(
    state: &mut TpmState,
    request: &Request,
    index: usize,
    entity: &Entity,
    cp_hash: &[u8],
) -> TpmResult<()> {
    let input = &request.sessions[index];
    let position = index + 1;

    // A password session carries the authorization value in the clear.
    if input.handle == rh::RS_PW {
        if !entity.user_with_auth {
            return Err(TpmRc(rc::AUTH_TYPE).with_session(position));
        }
        return compare_auth(state, &input.hmac, &entity.auth, entity.uses_lockout)
            .map_err(|e| e.with_session(position));
    }

    let s = state
        .sessions
        .get(input.handle)
        .map_err(|_| TpmRc(rc::VALUE).with_session(position))?
        .clone();

    if s.is_trial() {
        return Err(TpmRc(rc::AUTH_TYPE).with_session(position));
    }

    if s.is_policy() {
        check_policy(state, request, index, entity, cp_hash, &s)?;
    } else {
        if !entity.user_with_auth {
            return Err(TpmRc(rc::AUTH_TYPE).with_session(position));
        }
        let key = s.hmac_key(&entity.name, &entity.auth);
        let expected = session::auth_hmac(
            s.auth_hash,
            &key,
            cp_hash,
            &input.nonce_caller,
            &s.nonce_tpm,
            input.attributes,
        )?;
        if !constant_time_eq(&expected, &input.hmac) {
            return record_failure(state, entity.uses_lockout)
                .and(Err(TpmRc(rc::AUTH_FAIL).with_session(position)));
        }
        if entity.uses_lockout {
            clear_failures(state);
        }
    }
    Ok(())
}

/// Check a session that carries no authorization but asks to encrypt, decrypt
/// or audit.
///
/// Such a session must still prove that it holds the session key, so its HMAC
/// is computed over the cpHash with the session key alone as the key.
pub fn check_unauthorized_session(
    state: &TpmState,
    request: &Request,
    index: usize,
    names: &[&[u8]],
) -> TpmResult<()> {
    let input = &request.sessions[index];
    let position = index + 1;
    let s = state
        .sessions
        .get(input.handle)
        .map_err(|_| TpmRc(rc::VALUE).with_session(position))?;

    // A session that asks for nothing needs to prove nothing.
    if !input.attributes.any(
        SessionAttributes::DECRYPT | SessionAttributes::ENCRYPT | SessionAttributes::AUDIT,
    ) {
        return Ok(());
    }
    // An unbound, unsalted session has no key to prove, so there is nothing to
    // check. Such a session provides no confidentiality anyway.
    if s.session_key.is_empty() {
        return Ok(());
    }
    let cp = session::cp_hash(s.auth_hash, request.code, names, &request.parameters)?;
    let expected = session::auth_hmac(
        s.auth_hash,
        &s.session_key,
        &cp,
        &input.nonce_caller,
        &s.nonce_tpm,
        input.attributes,
    )?;
    if !constant_time_eq(&expected, &input.hmac) {
        return Err(TpmRc(rc::AUTH_FAIL).with_session(position));
    }
    Ok(())
}

/// Compare a password authorization.
fn compare_auth(
    state: &mut TpmState,
    given: &[u8],
    expected: &[u8],
    uses_lockout: bool,
) -> TpmResult<()> {
    if constant_time_eq(session::trim_auth(given), session::trim_auth(expected)) {
        // Only a success against a protected entity clears the counter. A
        // success against an exempt entity, such as an object with noDA or the
        // platform hierarchy, must not let a guessing attack reset it.
        if uses_lockout {
            clear_failures(state);
        }
        Ok(())
    } else {
        record_failure(state, uses_lockout)?;
        Err(TpmRc(rc::AUTH_FAIL))
    }
}

/// Note a failed authorization against the dictionary attack counter.
pub fn record_failure(state: &mut TpmState, uses_lockout: bool) -> TpmResult<()> {
    if !uses_lockout {
        return Ok(());
    }
    state.lockout.failed_tries = state.lockout.failed_tries.saturating_add(1);
    if state.lockout.failed_tries >= state.lockout.max_tries {
        state.lockout.in_lockout = true;
    }
    Ok(())
}

/// Note a successful authorization.
pub fn clear_failures(state: &mut TpmState) {
    state.lockout.failed_tries = 0;
}

/// Check that a policy session satisfies the entity's policy.
fn check_policy(
    state: &mut TpmState,
    request: &Request,
    index: usize,
    entity: &Entity,
    cp_hash: &[u8],
    s: &Session,
) -> TpmResult<()> {
    let position = index + 1;
    let input = &request.sessions[index];

    let Some((policy_alg, policy_digest)) = entity.policy.clone() else {
        return Err(TpmRc(rc::AUTH_UNAVAILABLE).with_session(position));
    };
    if policy_alg != s.auth_hash {
        return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
    }
    if !constant_time_eq(&s.policy.digest, &policy_digest) {
        return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
    }

    // Assertions the policy recorded must still hold.
    if let Some(code) = s.policy.command_code {
        if code != request.code {
            return Err(TpmRc(rc::POLICY_CC).with_session(position));
        }
    }
    if let Some(expected) = &s.policy.cp_hash {
        if !constant_time_eq(expected, cp_hash) {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
    }
    if let Some(mask) = s.policy.locality {
        let bit = if request.locality < 5 {
            1u8 << request.locality
        } else {
            0
        };
        if mask & bit == 0 {
            return Err(TpmRc(rc::LOCALITY));
        }
    }
    if let Some(counter) = s.policy.pcr_update_counter {
        if counter != state.pcr.update_counter() {
            return Err(TpmRc(rc::PCR_CHANGED).with_session(position));
        }
    }
    if let Some(expiration) = s.policy.expiration {
        if state.clock.time > expiration {
            return Err(TpmRc(rc::EXPIRED).with_session(position));
        }
    }
    // TPM2_PolicyPhysicalPresence requires the signal to still be asserted.
    if s.policy.physical_presence_required && !state.physical_presence {
        return Err(TpmRc(rc::PP));
    }
    // TPM2_PolicyNvWritten fixes what the written bit of the Index must be.
    if let Some(expected) = s.policy.nv_written {
        let written = match state.nv.get(request.handles.first().copied().unwrap_or(0)) {
            Ok(index) => index.written(),
            Err(_) => return Err(TpmRc(rc::POLICY_FAIL).with_session(position)),
        };
        if written != expected {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
    }
    // TPM2_PolicyNameHash and TPM2_PolicyDuplicationSelect fix the Names the
    // command may be used with, in place of a cpHash.
    if let Some(expected) = &s.policy.name_hash {
        let mut h = crate::tpm::crypto::hash::Hasher::new(s.auth_hash)?;
        for handle in &request.handles {
            h.update(&handle_name(state, *handle)?);
        }
        if !constant_time_eq(expected, &h.finish()) {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
    }
    // TPM2_PolicyTemplate fixes the template a creation command may use.
    if let Some(expected) = &s.policy.template_hash {
        let template = first_sized_parameter_at(&request.parameters, 1)
            .ok_or_else(|| TpmRc(rc::POLICY_FAIL).with_session(position))?;
        let got = crate::tpm::crypto::hash::digest(s.auth_hash, template)?;
        if !constant_time_eq(expected, &got) {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
    }
    // TPM2_PolicyParameters fixes the digest of the whole parameter area.
    if let Some(expected) = &s.policy.parameters_hash {
        let got = crate::tpm::crypto::hash::digest(s.auth_hash, &request.parameters)?;
        if !constant_time_eq(expected, &got) {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
    }

    // TPM2_PolicyAuthValue and TPM2_PolicyPassword both require the caller to
    // prove the authorization value as well as the policy.
    if s.policy.password_needed {
        return compare_auth(state, &input.hmac, &entity.auth, entity.uses_lockout)
            .map_err(|e| e.with_session(position));
    }
    if s.policy.auth_value_needed {
        let key = {
            let mut k = s.session_key.clone();
            k.extend_from_slice(session::trim_auth(&entity.auth));
            k
        };
        let expected = session::auth_hmac(
            s.auth_hash,
            &key,
            cp_hash,
            &input.nonce_caller,
            &s.nonce_tpm,
            input.attributes,
        )?;
        if !constant_time_eq(&expected, &input.hmac) {
            record_failure(state, entity.uses_lockout)?;
            return Err(TpmRc(rc::AUTH_FAIL).with_session(position));
        }
        if entity.uses_lockout {
            clear_failures(state);
        }
    }
    Ok(())
}

/// Roll every session nonce forward and return the new values.
///
/// This runs before the response parameter is encrypted because Part 1 clause
/// 21.3 keys that encryption with the new nonceTPM.
pub fn roll_response_nonces(state: &mut TpmState, request: &Request) -> TpmResult<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(request.sessions.len());
    for input in &request.sessions {
        if input.handle == rh::RS_PW {
            out.push(Vec::new());
            continue;
        }
        let nonce_len = match state.sessions.get(input.handle) {
            Ok(s) => s.nonce_tpm.len(),
            Err(_) => {
                // The command may have flushed the session it was given.
                out.push(Vec::new());
                continue;
            }
        };
        let new_nonce = state.rng.bytes(nonce_len)?;
        if let Ok(s) = state.sessions.get_mut(input.handle) {
            s.nonce_tpm = new_nonce.clone();
            s.nonce_caller = input.nonce_caller.clone();
        }
        out.push(new_nonce);
    }
    Ok(out)
}

/// Build the response authorization area.
///
/// `nonces` holds the values [`roll_response_nonces`] produced and
/// `auth_values` the authorization value of each authorized entity, which the
/// response HMAC key needs just as the command HMAC key did.
pub fn build_response_sessions(
    state: &mut TpmState,
    request: &Request,
    response_code: u32,
    parameters: &[u8],
    nonces: &[Vec<u8>],
    auth_values: &[Vec<u8>],
) -> TpmResult<Vec<u8>> {
    let mut w = Writer::new();
    for (index, input) in request.sessions.iter().enumerate() {
        if input.handle == rh::RS_PW {
            AuthResponse {
                nonce: Tpm2bNonce::empty(),
                session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
                hmac: Tpm2bAuth::empty(),
            }
            .marshal(&mut w);
            continue;
        }
        let new_nonce = nonces.get(index).cloned().unwrap_or_default();
        let Ok(s) = state.sessions.get(input.handle) else {
            // The session went away, so there is nothing to answer with.
            AuthResponse {
                nonce: Tpm2bNonce::new(new_nonce)?,
                session_attributes: input.attributes,
                hmac: Tpm2bAuth::empty(),
            }
            .marshal(&mut w);
            continue;
        };

        let auth_hash = s.auth_hash;
        let rp = session::rp_hash(auth_hash, response_code, request.code, parameters)?;
        // The response HMAC uses the same key as the command HMAC. A policy
        // session that proved nothing but its policy answers with none.
        let carries_hmac = !s.is_policy()
            || s.policy.auth_value_needed
            || s.policy.password_needed
            || !s.session_key.is_empty();
        let hmac = if carries_hmac {
            let entity_name = request
                .handles
                .get(index)
                .map(|h| handle_name(state, *h))
                .transpose()?
                .unwrap_or_default();
            let auth = auth_values.get(index).cloned().unwrap_or_default();
            let s = state.sessions.get(input.handle)?;
            let key = s.hmac_key(&entity_name, &auth);
            session::auth_hmac(
                auth_hash,
                &key,
                &rp,
                &new_nonce,
                &input.nonce_caller,
                input.attributes,
            )?
        } else {
            Vec::new()
        };

        AuthResponse {
            nonce: Tpm2bNonce::new(new_nonce)?,
            session_attributes: input.attributes,
            hmac: Tpm2bAuth::new(hmac)?,
        }
        .marshal(&mut w);
    }
    w.finish()
}

/// Close every session the caller did not ask to keep.
///
/// A policy session that is kept has its policy reset, because Part 1 clause
/// 19.7.4 spends the satisfied assertions when the session authorizes a
/// command. Without that a single satisfied policy would authorize an
/// unlimited number of later commands.
pub fn close_sessions(state: &mut TpmState, request: &Request) {
    for (index, input) in request.sessions.iter().enumerate() {
        if input.handle == rh::RS_PW {
            continue;
        }
        if !input.attributes.has(SessionAttributes::CONTINUE_SESSION) {
            let _ = state.sessions.remove(input.handle);
            continue;
        }
        // Only a session that actually authorized a handle is spent.
        if index >= request.info.auth_handles as usize {
            continue;
        }
        if let Ok(s) = state.sessions.get_mut(input.handle) {
            if s.is_policy() {
                let _ = s.restart_policy();
            }
        }
    }
}

/// True when the command is one of the two allowed before TPM2_Startup.
pub fn allowed_before_startup(code: u32) -> bool {
    matches!(code, cc::Startup)
}

/// True when the command is allowed while the TPM is in failure mode.
///
/// Part 1 clause 12.3 keeps only the two commands that let a caller learn why.
pub fn allowed_in_failure_mode(code: u32) -> bool {
    matches!(code, cc::GetTestResult | cc::GetCapability)
}

/// True when `session_type` may authorize an entity.
pub fn session_can_authorize(session_type: u8) -> bool {
    session_type == se::HMAC || session_type == se::POLICY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::marshal::Writer;

    fn command(tag: u16, code: u32, handles: &[u32], auth: &[u8], params: &[u8]) -> Vec<u8> {
        let mut body = Writer::new();
        for h in handles {
            body.u32(*h);
        }
        if tag == st::SESSIONS {
            body.u32(auth.len() as u32);
            body.bytes(auth);
        }
        body.bytes(params);
        let body = body.finish().unwrap();

        let mut w = Writer::new();
        w.u16(tag);
        w.u32((HEADER_SIZE + body.len()) as u32);
        w.u32(code);
        w.bytes(&body);
        w.finish().unwrap()
    }

    fn password_auth(password: &[u8]) -> Vec<u8> {
        AuthCommand {
            session_handle: rh::RS_PW,
            nonce: Tpm2bNonce::empty(),
            session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
            hmac: Tpm2bAuth::from_slice(password).unwrap(),
        }
        .to_bytes()
    }

    #[test]
    fn a_command_with_no_sessions_parses() {
        let state = TpmState::manufacture().unwrap();
        let buf = command(st::NO_SESSIONS, cc::GetRandom, &[], &[], &[0x00, 0x20]);
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(req.code, cc::GetRandom);
        assert!(req.handles.is_empty());
        assert!(req.sessions.is_empty());
        assert_eq!(req.parameters, vec![0x00, 0x20]);
    }

    #[test]
    fn handles_are_read_from_the_handle_area() {
        let state = TpmState::manufacture().unwrap();
        let auth = password_auth(b"");
        let buf = command(
            st::SESSIONS,
            cc::NV_Read,
            &[rh::OWNER, hc::NV_INDEX_FIRST],
            &auth,
            &[0x00, 0x08, 0x00, 0x00],
        );
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(req.handles, vec![rh::OWNER, hc::NV_INDEX_FIRST]);
        assert_eq!(req.sessions.len(), 1);
        assert_eq!(req.sessions[0].handle, rh::RS_PW);
        assert_eq!(req.parameters, vec![0x00, 0x08, 0x00, 0x00]);
    }

    #[test]
    fn an_unknown_command_code_is_refused() {
        let state = TpmState::manufacture().unwrap();
        let buf = command(st::NO_SESSIONS, 0x0000_0123, &[], &[], &[]);
        assert_eq!(
            parse(&state, &buf, 0).unwrap_err(),
            TpmRc(rc::COMMAND_CODE)
        );
    }

    #[test]
    fn a_command_needing_authorization_must_carry_a_session() {
        let state = TpmState::manufacture().unwrap();
        let buf = command(st::NO_SESSIONS, cc::Clear, &[rh::LOCKOUT], &[], &[]);
        assert_eq!(
            parse(&state, &buf, 0).unwrap_err(),
            TpmRc(rc::AUTH_MISSING)
        );
    }

    #[test]
    fn a_truncated_handle_area_is_insufficient() {
        let state = TpmState::manufacture().unwrap();
        let mut buf = command(st::NO_SESSIONS, cc::ReadPublic, &[hc::TRANSIENT_FIRST], &[], &[]);
        // Drop two octets from the handle and fix the size so the header check
        // passes but the handle area does not.
        buf.truncate(buf.len() - 2);
        let n = buf.len() as u32;
        buf[2..6].copy_from_slice(&n.to_be_bytes());
        assert_eq!(
            parse(&state, &buf, 0).unwrap_err(),
            TpmRc(rc::INSUFFICIENT)
        );
    }

    #[test]
    fn an_authorization_area_that_is_too_small_is_refused() {
        let state = TpmState::manufacture().unwrap();
        let buf = command(st::SESSIONS, cc::Clear, &[rh::LOCKOUT], &[0u8; 4], &[]);
        assert_eq!(parse(&state, &buf, 0).unwrap_err(), TpmRc(rc::AUTHSIZE));
    }

    #[test]
    fn more_than_three_sessions_are_refused() {
        let state = TpmState::manufacture().unwrap();
        let mut auth = Vec::new();
        for _ in 0..4 {
            auth.extend_from_slice(&password_auth(b""));
        }
        let buf = command(st::SESSIONS, cc::Clear, &[rh::LOCKOUT], &auth, &[]);
        assert_eq!(parse(&state, &buf, 0).unwrap_err(), TpmRc(rc::AUTHSIZE));
    }

    #[test]
    fn a_password_authorization_is_compared_against_the_entity() {
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"secret".to_vec();
        let auth = password_auth(b"secret");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        assert!(check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).is_ok());

        let auth = password_auth(b"wrong");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        let err = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap_err();
        assert_eq!(err.0 & 0x03F, rc::AUTH_FAIL & 0x03F);
        assert_eq!(state.lockout.failed_tries, 1);
    }

    #[test]
    fn a_padded_password_matches_the_unpadded_value() {
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"pw".to_vec();
        let auth = password_auth(b"pw\0\0");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        assert!(check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).is_ok());
    }

    #[test]
    fn repeated_failures_enter_lockout() {
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"secret".to_vec();
        state.lockout.max_tries = 3;
        let auth = password_auth(b"wrong");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        for _ in 0..3 {
            let req = parse(&state, &buf, 0).unwrap();
            let e = entity(&state, rh::OWNER).unwrap();
            let _ = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]);
        }
        assert!(state.lockout.in_lockout);
        // A success clears the counter.
        let auth = password_auth(b"secret");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap();
        assert_eq!(state.lockout.failed_tries, 0);
    }

    #[test]
    fn a_success_against_an_exempt_entity_does_not_reset_the_counter() {
        // Guessing against a protected entity, then succeeding against an
        // exempt one, must not clear the dictionary attack counter.
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"secret".to_vec();
        state.hierarchies.platform.auth = b"known".to_vec();

        let auth = password_auth(b"wrong");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        let _ = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]);
        assert_eq!(state.lockout.failed_tries, 1);

        // The platform hierarchy is exempt from the counter.
        let auth = password_auth(b"known");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::PLATFORM], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::PLATFORM).unwrap();
        assert!(!e.uses_lockout);
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap();
        assert_eq!(
            state.lockout.failed_tries, 1,
            "an exempt success cleared the counter"
        );

        // A success against the protected entity does clear it.
        let auth = password_auth(b"secret");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap();
        assert_eq!(state.lockout.failed_tries, 0);
    }

    #[test]
    fn a_sized_parameter_can_be_located_by_position() {
        // Two TPM2B values followed by trailing octets.
        let params = [0x00u8, 0x02, 1, 2, 0x00, 0x03, 3, 4, 5, 9, 9];
        assert_eq!(
            first_sized_parameter_at(&params, 0),
            Some([1u8, 2].as_slice())
        );
        assert_eq!(
            first_sized_parameter_at(&params, 1),
            Some([3u8, 4, 5].as_slice())
        );
        assert_eq!(first_sized_parameter_at(&params, 5), None);
    }

    #[test]
    fn a_no_da_entity_does_not_count_against_the_lockout() {
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"secret".to_vec();
        let auth = password_auth(b"wrong");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let mut e = entity(&state, rh::OWNER).unwrap();
        e.uses_lockout = false;
        let _ = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]);
        assert_eq!(state.lockout.failed_tries, 0);
    }

    #[test]
    fn the_response_session_area_carries_a_fresh_nonce() {
        let mut state = TpmState::manufacture().unwrap();
        let auth = password_auth(b"");
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let nonces = roll_response_nonces(&mut state, &req).unwrap();
        let area =
            build_response_sessions(&mut state, &req, rc::SUCCESS, &[], &nonces, &[]).unwrap();
        // A password session answers with empty nonce and HMAC.
        assert_eq!(area, vec![0x00, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn sessions_without_continue_are_closed() {
        let mut state = TpmState::manufacture().unwrap();
        let handle = state.sessions.allocate_handle(se::HMAC).unwrap();
        let s = Session::new(
            handle,
            se::HMAC,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            Vec::new(),
            rh::NULL,
            Vec::new(),
            crate::tpm::structures::schemes::SymDef::null(),
        )
        .unwrap();
        state.sessions.insert(s).unwrap();

        let auth = AuthCommand {
            session_handle: handle,
            nonce: Tpm2bNonce::from_slice(&[0u8; 32]).unwrap(),
            session_attributes: SessionAttributes(0),
            hmac: Tpm2bAuth::empty(),
        }
        .to_bytes();
        let buf = command(st::SESSIONS, cc::Clear, &[rh::OWNER], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        close_sessions(&mut state, &req);
        assert!(!state.sessions.contains(handle));
    }

    #[test]
    fn the_first_sized_parameter_is_located() {
        assert_eq!(
            first_sized_parameter(&[0x00, 0x03, 1, 2, 3, 9, 9]),
            Some([1u8, 2, 3].as_slice())
        );
        assert_eq!(first_sized_parameter(&[0x00, 0x03, 1, 2]), None);
        assert_eq!(first_sized_parameter(&[0x00]), None);
        assert_eq!(first_sized_parameter(&[0x00, 0x00]), Some([].as_slice()));
    }

    #[test]
    fn commands_allowed_before_startup_and_in_failure_mode() {
        assert!(allowed_before_startup(cc::Startup));
        assert!(!allowed_before_startup(cc::GetRandom));
        assert!(allowed_in_failure_mode(cc::GetTestResult));
        assert!(allowed_in_failure_mode(cc::GetCapability));
        assert!(!allowed_in_failure_mode(cc::Create));
    }
}
