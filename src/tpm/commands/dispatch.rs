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

pub use super::handles::{allows as handle_allows, kind as handle_kind};

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
    /// How far into the parameter area the command has read.
    ///
    /// A command builds its own reader, so this records what that reader
    /// reached and lets the dispatcher check that nothing was left over.
    pub consumed: std::cell::Cell<usize>,
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
    pub fn reader(&self) -> TrackedReader<'_> {
        TrackedReader {
            inner: Reader::new(&self.parameters),
            consumed: &self.consumed,
        }
    }

    /// True when the command read every octet of its parameter area.
    pub fn parameters_fully_read(&self) -> bool {
        self.consumed.get() >= self.parameters.len()
    }

    /// Refuse a parameter area that holds more than the command reads.
    ///
    /// Part 3 clause 5.8.2 answers TPM_RC_SIZE for surplus octets, and clause
    /// 5.6 leaves the TPM unchanged when a command fails, so every command
    /// calls this once it has read its parameters and before it changes
    /// anything.
    pub fn end_of_parameters(&self) -> TpmResult<()> {
        if self.parameters_fully_read() {
            Ok(())
        } else {
            Err(TpmRc(rc::SIZE))
        }
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
    /// The handle of the Index, when this entity is a PIN Index.
    ///
    /// Part 1 clause 34.2.6 gives such an Index a counter of its own: an
    /// authorization "will fail if the pinCount field of the Index is not less
    /// than the pinLimit field or if the TPMA_NV_WRITTEN attribute of the Index
    /// is CLEAR", and a success or a failure moves that counter depending on
    /// which of the two kinds it is.
    pub pin: Option<u32>,
    /// True when an ADMIN role action needs a policy session.
    ///
    /// Part 3 clause 5.6.5 always requires one for an NV Index and for a
    /// hierarchy, and for an object only when TPMA_OBJECT.adminWithPolicy is
    /// SET.
    pub admin_with_policy: bool,
}

/// A reader over a command parameter area that records how far it got.
///
/// It behaves as a [`Reader`] in every way, so a command reads through it
/// without knowing it is being watched.
pub struct TrackedReader<'a> {
    inner: Reader<'a>,
    consumed: &'a std::cell::Cell<usize>,
}

impl<'a> std::ops::Deref for TrackedReader<'a> {
    type Target = Reader<'a>;

    fn deref(&self) -> &Reader<'a> {
        &self.inner
    }
}

impl<'a> std::ops::DerefMut for TrackedReader<'a> {
    fn deref_mut(&mut self) -> &mut Reader<'a> {
        &mut self.inner
    }
}

impl Drop for TrackedReader<'_> {
    fn drop(&mut self) {
        let reached = self.inner.position();
        if reached > self.consumed.get() {
            self.consumed.set(reached);
        }
    }
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

/// Refuse a handle whose hierarchy has been turned off.
///
/// Part 3 clause 24.3.1: clearing an enable "will disable use of any persistent
/// entity associated with the disabled hierarchy", clearing shEnable disables
/// the NV Indices the owner defined and clearing phEnableNV those the platform
/// defined. Part 1 clause 9.4 bars the authValue and authPolicy of a hierarchy
/// whose enable is CLEAR. This runs over the handle area before the command
/// does, so a command that takes no authorization is stopped as well.
/// Check every session handle the way Part 3 clause 5.5 item 4 does.
///
/// Item 4.1: "if the session handle is not a handle for an HMAC session, a
/// handle for a policy session, or, TPM_RS_PW then the TPM shall return
/// TPM_RC_HANDLE." Item 4.2: "if the session is not loaded, the TPM will return
/// the warning TPM_RC_REFERENCE_S0 + N where N is the number of the session."
///
/// The two answers are told apart by whether the handle names a session at all.
/// A handle outside both session ranges cannot be loaded by anyone, so the
/// warning would send a resource manager looking for a context that never
/// existed; a handle inside them may simply be swapped out, which is what the
/// warning is for. The check covers every session in the area, not only the
/// ones that carry an authorization, because clause 5.5 runs while the area is
/// unmarshaled and before any session is used.
pub fn check_session_handles(state: &TpmState, request: &Request) -> TpmResult<()> {
    for (index, input) in request.sessions.iter().enumerate() {
        if input.handle == rh::RS_PW {
            continue;
        }
        if !crate::tpm::core::session::is_session_handle(input.handle) {
            return Err(TpmRc(rc::HANDLE).with_session(index + 1));
        }
        if state.sessions.get(input.handle).is_err() {
            return Err(TpmRc(rc::REFERENCE_S0 + index as u32));
        }
    }
    Ok(())
}

/// Whether a handle that must name a loaded context names one.
///
/// Part 3 clause 5.3 answers TPM_RC_REFERENCE_H0 + N for a transient object or
/// a session that is not in TPM memory, which is a warning rather than an
/// error: the caller is being told to load the context and send the command
/// again. Every other kind of handle is judged by the checks that follow.
pub fn handle_is_present(state: &TpmState, handle: u32) -> bool {
    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        return state.objects.get(handle).is_ok();
    }
    if crate::tpm::core::session::is_session_handle(handle) {
        return state.sessions.get(handle).is_ok();
    }
    true
}

pub fn check_handle_available(state: &TpmState, handle: u32) -> TpmResult<()> {
    // A limited hierarchy is there while its base is, so a caller cannot tell
    // a right authorization from a wrong one against a hierarchy that is off.
    if crate::tpm::core::hierarchy::Hierarchies::is_limited(handle) {
        if !state.hierarchies.is_enabled(handle) {
            return Err(TpmRc(rc::HIERARCHY));
        }
        return Ok(());
    }
    if crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(handle) {
        if !state.hierarchies.is_enabled(handle) {
            return Err(TpmRc(rc::HIERARCHY));
        }
        return Ok(());
    }
    if (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&handle) {
        if let Some(object) = state.persistent.get(&handle) {
            if !state.hierarchies.is_enabled(object.hierarchy) {
                return Err(TpmRc(rc::HIERARCHY));
            }
        }
        return Ok(());
    }
    // Part 2 Table 45 says of each enable that objects in the hierarchy it
    // names "may not be used", which is as true of one that is loaded as of
    // one that is persistent.
    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        if let Ok(crate::tpm::core::object::Slot::Object(object)) = state.objects.get(handle) {
            if !state.hierarchies.is_enabled(object.hierarchy) {
                return Err(TpmRc(rc::HIERARCHY));
            }
        }
        return Ok(());
    }
    if crate::tpm::core::nv::NvStore::is_nv_handle(handle) {
        if let Ok(index) = state.nv.get(handle) {
            let platform_created = index.public.attributes.has(
                crate::tpm::structures::attributes::NvAttributes::PLATFORMCREATE,
            );
            let reachable = if platform_created {
                state.hierarchies.platform_nv_enabled
            } else {
                state.hierarchies.owner.enabled
            };
            if !reachable {
                return Err(TpmRc(rc::HANDLE));
            }
        }
    }
    Ok(())
}

/// Resolve the authorization values of a handle.
pub fn entity(state: &TpmState, handle: u32) -> TpmResult<Entity> {
    use crate::tpm::structures::attributes::{NvAttributes, ObjectAttributes};

    let name = handle_name(state, handle)?;

    // The four hierarchies, the lockout authority and the platform NV control.
    //
    // Part 1 clause 16.8.1 leaves every permanent entity other than
    // TPM_RH_LOCKOUT out of dictionary attack protection, because their
    // authorization values are expected to be high entropy or well known.
    // A firmware-limited or SVN-limited hierarchy has no authorization of its
    // own: Part 2 Table 61 keeps TPMI_RH_HIERARCHY_AUTH to the base
    // hierarchies and lockout, so what authorizes the base authorizes the
    // derivation of it.
    let authorizing = crate::tpm::core::hierarchy::Hierarchies::is_limited(handle)
        .then(|| crate::tpm::core::hierarchy::Hierarchies::base_of(handle))
        .flatten()
        .unwrap_or(handle);
    if crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(authorizing) {
        let h = state.hierarchies.get(authorizing)?;
        return Ok(Entity {
            name,
            auth: h.auth.clone(),
            policy: policy_of(&h.policy),
            uses_lockout: false,
            user_with_auth: true,
            admin_with_policy: true,
            pin: None,
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
            admin_with_policy: true,
            pin: None,
        });
    }
    if (rh::ACT_0..=rh::ACT_F).contains(&handle) {
        // Part 1 clause 40.2: an ACT "has an authValue and an authPolicy. The
        // authValue is the same as the current platformAuth and can only be
        // used if phEnable is SET. The authPolicy is ACT-specific and is
        // neither enabled nor disabled by phEnable."
        let platform = state.hierarchies.get(rh::PLATFORM)?;
        let enabled = state
            .startup_clear
            .has(crate::tpm::structures::attributes::StartupClearAttributes::PH_ENABLE);
        return Ok(Entity {
            name,
            auth: if enabled {
                platform.auth.clone()
            } else {
                Vec::new()
            },
            policy: policy_of(&state.act.policy),
            uses_lockout: false,
            user_with_auth: enabled,
            admin_with_policy: true,
            pin: None,
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
            admin_with_policy: true,
            pin: None,
        });
    }
    if (hc::PCR_FIRST..=hc::PCR_LAST).contains(&handle) {
        return Ok(Entity {
            name,
            auth: state.pcr_auth.clone(),
            policy: policy_of(&state.pcr_policy),
            uses_lockout: false,
            user_with_auth: true,
            admin_with_policy: true,
            pin: None,
        });
    }
    if ObjectSlots::is_transient(handle) {
        let slot = state.objects.get(handle)?;
        let (policy, user_with_auth, no_da, admin_with_policy) = match slot {
            crate::tpm::core::object::Slot::Object(o) => {
                // Part 3 clause 5.6.1 needs both halves of the object to
                // authorize it, because the authValue lives in the sensitive
                // area.
                if o.is_public_only() {
                    return Err(TpmRc(rc::AUTH_UNAVAILABLE));
                }
                (
                    object_policy(&o.public),
                    o.public
                        .object_attributes
                        .has(ObjectAttributes::USER_WITH_AUTH),
                    o.public.object_attributes.has(ObjectAttributes::NO_DA),
                    o.public
                        .object_attributes
                        .has(ObjectAttributes::ADMIN_WITH_POLICY),
                )
            }
            crate::tpm::core::object::Slot::Sequence(_) => (None, true, true, false),
        };
        return Ok(Entity {
            name,
            auth: slot.auth_value().to_vec(),
            policy,
            uses_lockout: !no_da,
            user_with_auth,
            admin_with_policy,
            pin: None,
        });
    }
    if (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&handle) {
        let object = state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))?;
        // Part 3 clause 24.3.1: clearing an enable "will disable use of any
        // persistent entity associated with the disabled hierarchy".
        if !state.hierarchies.is_enabled(object.hierarchy) {
            return Err(TpmRc(rc::HIERARCHY));
        }
        // The same rule as for a transient object: clause 5.6.1 needs both
        // halves to authorize, because the authValue lives in the sensitive
        // area. TPM2_EvictControl can make a public area persistent.
        if object.is_public_only() {
            return Err(TpmRc(rc::AUTH_UNAVAILABLE));
        }
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
            admin_with_policy: object
                .public
                .object_attributes
                .has(ObjectAttributes::ADMIN_WITH_POLICY),
            pin: None,
        });
    }
    if crate::tpm::core::nv::NvStore::is_nv_handle(handle) {
        let index = state.nv.get(handle)?;
        // The same clause: clearing shEnable "will disable access to any NV
        // index that has TPMA_NV_PLATFORMCREATE CLEAR", and clearing
        // phEnableNV does the same for one that has it SET.
        let platform_created = index
            .public
            .attributes
            .has(NvAttributes::PLATFORMCREATE);
        let reachable = if platform_created {
            state.hierarchies.platform_nv_enabled
        } else {
            state.hierarchies.owner.enabled
        };
        if !reachable {
            return Err(TpmRc(rc::HANDLE));
        }
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
            // Part 3 clause 5.6.5 always requires a policy session for an
            // ADMIN role action on an NV Index.
            admin_with_policy: true,
            pin: matches!(
                index.public.attributes.index_type(),
                crate::tpm::structures::attributes::nt::PIN_FAIL
                    | crate::tpm::structures::attributes::nt::PIN_PASS
            )
            .then_some(index.public.nv_index),
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
        // Part 3 clause 5.5 refuses a session area for the four commands whose
        // tag is required to be TPM_ST_NO_SESSIONS.
        if requires_no_sessions(header.code) {
            return Err(TpmRc(rc::AUTH_CONTEXT));
        }
        // Part 3 clause 5.5 sets the smallest session area at one session with
        // empty nonce and HMAC, and the largest at what the command buffer
        // still holds. Either way out of range is TPM_RC_AUTHSIZE.
        let auth_size = r.u32()? as usize;
        if auth_size < 9 || auth_size > r.remaining() {
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
        consumed: std::cell::Cell::new(0),
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
pub fn decrypt_parameters(
    state: &TpmState,
    request: &mut Request,
    auth_values: &[Vec<u8>],
) -> TpmResult<()> {
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
    let extra = auth_values.get(index).cloned().unwrap_or_default();
    let plain = transform_parameter(s, input, &extra, body, false)?;
    splice_first_parameter(&mut request.parameters, &plain);
    Ok(())
}

/// Encrypt the first response parameter for the session that asked.
pub fn encrypt_parameters(
    state: &TpmState,
    request: &Request,
    parameters: &mut Vec<u8>,
    auth_values: &[Vec<u8>],
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
    let extra = auth_values.get(index).cloned().unwrap_or_default();
    let cipher = transform_parameter(s, input, &extra, body, true)?;
    splice_first_parameter(parameters, &cipher);
    Ok(())
}

/// The nonceTPM of the decrypt and encrypt sessions.
///
/// Part 1 clause 16.6.3.4 folds these into the HMAC of the first session only,
/// so an attacker cannot strip an encryption session and receive plaintext.
/// The decrypt nonce goes in even when that session is the first one itself,
/// and the encrypt nonce is left out when one session does both, so the same
/// value is never added twice.
pub fn auxiliary_nonces(
    state: &TpmState,
    request: &Request,
    for_index: usize,
) -> (Vec<u8>, Vec<u8>) {
    if for_index != 0 {
        return (Vec::new(), Vec::new());
    }
    let position = |attribute: u8| {
        request
            .sessions
            .iter()
            .position(|s| s.attributes.has(attribute))
    };
    let nonce_at = |index: Option<usize>| -> Vec<u8> {
        index
            .and_then(|i| state.sessions.get(request.sessions[i].handle).ok())
            .map(|s| s.nonce_tpm.clone())
            .unwrap_or_default()
    };
    let decrypt_index = position(SessionAttributes::DECRYPT);
    let encrypt_index = position(SessionAttributes::ENCRYPT);
    let encrypt = if encrypt_index.is_some() && encrypt_index != decrypt_index {
        nonce_at(encrypt_index)
    } else {
        Vec::new()
    };
    (nonce_at(decrypt_index), encrypt)
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
    s: &Session,
    input: &SessionInput,
    auth_value: &[u8],
    body: &[u8],
    response: bool,
) -> TpmResult<Vec<u8>> {
    let (newer, older) = if response {
        (s.nonce_tpm.clone(), input.nonce_caller.clone())
    } else {
        (input.nonce_caller.clone(), s.nonce_tpm.clone())
    };
    // Part 1 clause 18.1 keys the encryption with sessionKey followed by the
    // authValue of the entity the session authorizes, whether or not the
    // session is bound to that entity. `auth_value` is empty for a session
    // that authorizes nothing.
    let session_value = s.session_value(auth_value);

    match s.symmetric.algorithm {
        alg::XOR => {
            let mut out = body.to_vec();
            sym::xor_obfuscate(
                s.symmetric.key_bits,
                &session_value,
                &newer,
                &older,
                &mut out,
            )?;
            Ok(out)
        }
        alg::AES => {
            let block = sym::block_size(alg::AES)?;
            let (key, iv) = session::parameter_encryption_key(
                s.auth_hash,
                &session_value,
                &[],
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

/// Check one authorization.
///
/// `index` is the position of the session, counting from one, so a failure can
/// name it.
#[allow(clippy::too_many_arguments)]
/// Check that the Index-specific authorization the caller chose is available.
///
/// Part 3 clause 5.6 item 7.2: when the entity being authorized is an NV Index
/// and the command requires USER role, a policy session needs
/// TPMA_NV_POLICYWRITE to modify the data or TPMA_NV_POLICYREAD to read it, and
/// an HMAC session or a password needs TPMA_NV_AUTHWRITE or TPMA_NV_AUTHREAD.
/// The answer for an attribute that is CLEAR is TPM_RC_AUTH_UNAVAILABLE.
///
/// Item 7 comes before items 9 and 10, which check the HMAC and the password,
/// and the clause closes with "if the TPM returns an error other than
/// TPM_RC_AUTH_FAIL, then the TPM shall not alter any TPM state". Checking here
/// rather than inside the command is what keeps a wrong authorization value
/// against an unavailable method from reaching the comparison that would answer
/// TPM_RC_AUTH_FAIL and step failedTries.
fn check_nv_authorization_available(
    state: &TpmState,
    request: &Request,
    index: usize,
    role: super::handles::Role,
) -> TpmResult<()> {
    use super::handles::NvAccess;
    use crate::tpm::structures::attributes::NvAttributes;

    if role != super::handles::Role::User {
        return Ok(());
    }
    let Some(access) = super::handles::nv_access(request.code) else {
        return Ok(());
    };
    let handle = request.handle(index)?;
    if !crate::tpm::core::nv::NvStore::is_nv_handle(handle) {
        return Ok(());
    }
    let attributes = state.nv.get(handle)?.public.attributes;
    let is_policy = super::nv::auth_is_policy(state, request, index);
    let needed = match (access, is_policy) {
        (NvAccess::Write, true) => NvAttributes::POLICYWRITE,
        (NvAccess::Write, false) => NvAttributes::AUTHWRITE,
        (NvAccess::Read, true) => NvAttributes::POLICYREAD,
        (NvAccess::Read, false) => NvAttributes::AUTHREAD,
    };
    if attributes.has(needed) {
        Ok(())
    } else {
        Err(TpmRc(rc::AUTH_UNAVAILABLE).with_session(index + 1))
    }
}

pub fn check_authorization(
    state: &mut TpmState,
    request: &Request,
    index: usize,
    entity: &Entity,
    cp_hash: &[u8],
) -> TpmResult<()> {
    let input = &request.sessions[index];
    let position = index + 1;
    let protected = da_protected(state, request, index, entity);
    let role = super::handles::role(request.code, index);

    check_lockout(state, request, index, protected)?;
    check_nv_authorization_available(state, request, index, role)?;

    // A password session carries the authorization value in the clear.
    if input.handle == rh::RS_PW {
        check_role_allows_auth_value(role, entity, position)?;
        if !entity.user_with_auth {
            return Err(TpmRc(rc::AUTH_TYPE).with_session(position));
        }
        let is_lockout = request.handle(index).ok() == Some(rh::LOCKOUT);
        check_pin_available(state, entity).map_err(|e| e.with_session(position))?;
        let outcome = compare_auth(state, &input.hmac, &entity.auth, protected, is_lockout);
        record_pin_attempt(state, entity, outcome.is_ok())?;
        return outcome.map_err(|e| e.with_session(position));
    }

    let s = state
        .sessions
        .get(input.handle)
?
        .clone();

    if s.is_trial() {
        return Err(TpmRc(rc::AUTH_TYPE).with_session(position));
    }

    if s.is_policy() {
        // Part 3 clause 5.6.6 requires an ADMIN or DUP role policy to name the
        // command it authorizes, so authority to use an entity is not also
        // authority to duplicate or administer it.
        if matches!(role, super::handles::Role::Admin | super::handles::Role::Dup)
            && s.policy.command_code != Some(request.code)
        {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
        check_policy(state, request, index, entity, cp_hash, &s, protected)?;
    } else {
        check_role_allows_auth_value(role, entity, position)?;
        if !entity.user_with_auth {
            return Err(TpmRc(rc::AUTH_TYPE).with_session(position));
        }
        let key = s.hmac_key(&entity.name, &entity.auth);
        let (nonce_decrypt, nonce_encrypt) = auxiliary_nonces(state, request, index);
        let expected = session::auth_hmac_with_nonces(
            s.auth_hash,
            &key,
            cp_hash,
            &input.nonce_caller,
            &s.nonce_tpm,
            &nonce_decrypt,
            &nonce_encrypt,
            input.attributes,
        )?;
        check_pin_available(state, entity).map_err(|e| e.with_session(position))?;
        let accepted = session::auth_hmac_accepted(&key, &expected, &input.hmac);
        record_pin_attempt(state, entity, accepted)?;
        if !accepted {
            // Part 1 clause 16.8.5: a failure against lockoutAuth enters the
            // special lockout "regardless of the setting of failedTries and
            // maxTries".
            if request.handle(index).ok() == Some(rh::LOCKOUT) {
                record_lockout_failure(state);
            }
            // Clause 16.6.8 changes the code when the entity is exempt.
            let code = if protected { rc::AUTH_FAIL } else { rc::BAD_AUTH };
            return record_failure(state, protected)
                .and(Err(TpmRc(code).with_session(position)));
        }
    }
    Ok(())
}

/// Refuse a password or HMAC authorization where the role needs a policy.
///
/// Part 3 clause 5.6.4 gives the DUP role to policy sessions only. Clause
/// 5.6.5 does the same for the ADMIN role when the entity is an NV Index, a
/// hierarchy, or an object with adminWithPolicy SET.
fn check_role_allows_auth_value(
    role: super::handles::Role,
    entity: &Entity,
    position: usize,
) -> TpmResult<()> {
    match role {
        super::handles::Role::Dup => Err(TpmRc(rc::AUTH_TYPE).with_session(position)),
        super::handles::Role::Admin if entity.admin_with_policy => {
            Err(TpmRc(rc::AUTH_TYPE).with_session(position))
        }
        _ => Ok(()),
    }
}

/// True when a failed authorization here has to count against the lockout.
///
/// Part 1 clause 16.8.7 counts a failure when either the entity being
/// authorized or the entity the session is bound to is protected. Without the
/// second half, an attacker could guess the value of a protected entity by
/// binding a session to it and using that session against an exempt one.
fn da_protected(
    state: &TpmState,
    request: &Request,
    index: usize,
    entity: &Entity,
) -> bool {
    if entity.uses_lockout {
        return true;
    }
    let input = &request.sessions[index];
    if input.handle == rh::RS_PW {
        return false;
    }
    state
        .sessions
        .get(input.handle)
        .map(|s| s.bind_uses_lockout)
        .unwrap_or(false)
}

/// Refuse an authorization that Lockout mode blocks.
///
/// Part 1 clause 16.8.1 names the three ways an authValue is used: as a
/// password, as the authValue in the authorization HMAC, and as the authValue
/// in the sessionKey of a bound session. Part 1 clause 16.8.3 blocks all three
/// while the TPM is in Lockout mode. A policy that never calls for the
/// authValue uses none of them, so it still authorizes.
fn check_lockout(
    state: &TpmState,
    request: &Request,
    index: usize,
    protected: bool,
) -> TpmResult<()> {
    // Lockout mode stops any use of a DA protected authValue, clause 16.8.3,
    // and the special lockout of clause 16.8.5 stops the use of lockoutAuth
    // alone.
    let barred = if protected {
        state.lockout.locked_out()
    } else {
        false
    } || (state.lockout.in_lockout && request.handle(index).ok() == Some(rh::LOCKOUT));
    if !barred {
        return Ok(());
    }
    // TPM2_DictionaryAttackLockReset is how a caller leaves Lockout mode, so
    // Part 1 clause 16.8.3 lets it run even though it takes lockoutAuth.
    if request.code == cc::DictionaryAttackLockReset {
        return Ok(());
    }
    let input = &request.sessions[index];
    let uses_auth_value = if input.handle == rh::RS_PW {
        true
    } else {
        match state.sessions.get(input.handle) {
            Ok(s) => {
                // Part 1 clause 16.8.7 keeps the protection of the bound
                // entity on every use of the session, whatever it authorizes,
                // because the session key already carries that value.
                s.bind_uses_lockout
                    || !s.is_policy()
                    || s.policy.auth_value_needed
                    || s.policy.password_needed
            }
            // The session is unknown, so treat it as one that would use the
            // value and let the authorization itself report the handle.
            Err(_) => true,
        }
    };
    if uses_auth_value {
        return Err(TpmRc(rc::LOCKOUT));
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
?;

    // An unbound, unsalted session has no key, so Part 1 clause 19.6.16 lets
    // it send an empty HMAC. It may not send a wrong one, so anything present
    // is still checked.
    if s.session_key.is_empty() && input.hmac.is_empty() {
        return Ok(());
    }
    let cp = session::cp_hash(s.auth_hash, request.code, names, &request.parameters)?;
    let (nonce_decrypt, nonce_encrypt) = auxiliary_nonces(state, request, index);
    let expected = session::auth_hmac_with_nonces(
        s.auth_hash,
        &s.session_key,
        &cp,
        &input.nonce_caller,
        &s.nonce_tpm,
        &nonce_decrypt,
        &nonce_encrypt,
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
    is_lockout_auth: bool,
) -> TpmResult<()> {
    if constant_time_eq(session::trim_auth(given), session::trim_auth(expected)) {
        Ok(())
    } else {
        if is_lockout_auth {
            record_lockout_failure(state);
        }
        record_failure(state, uses_lockout)?;
        // Part 1 clause 16.6.8: "when an authorization failure occurs, the TPM
        // will check to see if the use of the object is exempt from dictionary
        // attack protection. If it is exempt, the response code is changed from
        // TPM_RC_AUTH_FAIL to TPM_RC_BAD_AUTH and no increment of the failed
        // authorization counter occurs." A caller can tell from the answer
        // whether the guess cost it anything.
        Err(TpmRc(if uses_lockout {
            rc::AUTH_FAIL
        } else {
            rc::BAD_AUTH
        }))
    }
}

/// Refuse a PIN Index that has nothing to authorize with yet, or has run out.
///
/// Part 1 clause 34.2.6: "if the authValue of a PIN Index is used for
/// authorization, then the authorization will fail if the pinCount field of the
/// Index is not less than the pinLimit field or if the TPMA_NV_WRITTEN
/// attribute of the Index is CLEAR."
fn check_pin_available(state: &TpmState, entity: &Entity) -> TpmResult<()> {
    let Some(handle) = entity.pin else {
        return Ok(());
    };
    let index = state.nv.get(handle)?;
    if !index.written() {
        return Err(TpmRc(rc::AUTH_UNAVAILABLE));
    }
    let counters = index.pin_counters()?;
    if counters.pin_count >= counters.pin_limit {
        return Err(TpmRc(rc::AUTH_FAIL));
    }
    Ok(())
}

/// Move the counter of a PIN Index after an authorization was judged.
///
/// The same clause: "when the authValue of a PIN Index is used for
/// authorization and the authorization succeeds, the pinCount field is set to
/// zero if the Index is PIN Fail and incremented if the Index is PIN Pass. If
/// the authorization fails, pinCount is incremented for a PIN Fail Index and
/// left unchanged for a PIN Pass Index."
fn record_pin_attempt(state: &mut TpmState, entity: &Entity, succeeded: bool) -> TpmResult<()> {
    let Some(handle) = entity.pin else {
        return Ok(());
    };
    let index = state.nv.get_mut(handle)?;
    let fail_index = index.index_type()
        == crate::tpm::structures::attributes::nt::PIN_FAIL;
    let mut counters = index.pin_counters()?;
    match (fail_index, succeeded) {
        (true, true) => counters.pin_count = 0,
        (true, false) => counters.pin_count = counters.pin_count.saturating_add(1),
        (false, true) => counters.pin_count = counters.pin_count.saturating_add(1),
        (false, false) => {}
    }
    index.set_pin_counters(counters)
}

/// Note a failed authorization against the dictionary attack counter.
///
/// Part 1 clause 16.8.2 increments failedTries whenever the TPM answers
/// TPM_RC_AUTH_FAIL for a protected entity, and clause 16.8.3 puts the TPM in
/// Lockout mode "while failedTries is equal to maxTries".
pub fn record_failure(state: &mut TpmState, uses_lockout: bool) -> TpmResult<()> {
    if !uses_lockout {
        return Ok(());
    }
    // Part 3 clause 25.3.1: with a recovery time of zero "DA protection is
    // disabled. Authorizations are checked but authorization failures will not
    // cause the TPM to enter lockout."
    if state.lockout.protection_off() {
        return Ok(());
    }
    state.lockout.failed_tries = state.lockout.failed_tries.saturating_add(1);
    // Clause 16.8.2 takes the counter down one recoveryTime after a failure,
    // and clause 25.3.1 measures that against Time rather than Clock.
    state.lockout.next_recovery = state
        .clock
        .time
        .saturating_add(state.lockout.recovery_time as u64 * 1000);
    Ok(())
}

/// Note a failed authorization that used lockoutAuth.
///
/// Part 1 clause 16.8.5: such a failure "causes the TPM to enter this special
/// lockout state regardless of the setting of failedTries and maxTries". The
/// TPM leaves it after lockoutRecovery seconds of power, or, when that is zero,
/// at the next TPM2_Startup.
pub fn record_lockout_failure(state: &mut TpmState) {
    state.lockout.in_lockout = true;
    state.lockout.lockout_until = if state.lockout.lockout_recovery == 0 {
        0
    } else {
        state
            .clock
            .time
            .saturating_add(state.lockout.lockout_recovery as u64 * 1000)
    };
}

/// Note a successful authorization.
///
/// Only TPM2_DictionaryAttackLockReset, a change of owner and TPM2_Clear put
/// the counter back, which clause 16.8.4 lists; an ordinary success does not.
pub fn clear_failures(state: &mut TpmState) {
    state.lockout.failed_tries = 0;
    state.lockout.next_recovery = 0;
    state.lockout.in_lockout = false;
    state.lockout.lockout_until = 0;
}

/// Check that a policy session satisfies the entity's policy.
fn check_policy(
    state: &mut TpmState,
    request: &Request,
    index: usize,
    entity: &Entity,
    cp_hash: &[u8],
    s: &Session,
    protected: bool,
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
    // Part 3 clause 23.2.2 refuses a time limited policy once its limit has
    // gone by, and once the run of Time it was measured against has ended,
    // because Time restarts from zero at every _TPM_Init.
    if let Some(expiration) = s.policy.expiration {
        if s.time_epoch != state.clock.time_epoch || state.clock.time > expiration {
            return Err(TpmRc(rc::EXPIRED).with_session(position));
        }
    }
    // TPM2_PolicyTransportSPDM is a deferred assertion: the channel and the
    // keys that carried it are checked when the policy authorizes, not when
    // the assertion is made. This TPM has no secure transport layer, so no
    // channel is ever present and Part 3 clause 23.25.1 answers
    // TPM_RC_CHANNEL.
    if s.policy.secure_channel_required {
        return Err(TpmRc(rc::CHANNEL));
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
    // TPM2_PolicyParameters fixes the digest of the parameter area. Part 3
    // clause 23.24.1 defines pHash as H(commandCode || parameters): the same
    // input as a cpHash with the handle Names left out.
    if let Some(expected) = &s.policy.parameters_hash {
        let got = crate::tpm::crypto::hash::digest_parts(
            s.auth_hash,
            &[&request.code.to_be_bytes(), &request.parameters],
        )?;
        if !constant_time_eq(expected, &got) {
            return Err(TpmRc(rc::POLICY_FAIL).with_session(position));
        }
    }

    // TPM2_PolicyAuthValue and TPM2_PolicyPassword both require the caller to
    // prove the authorization value as well as the policy, which Part 1 clause
    // 16.8.1 counts as a use of that value and clause 34.2.6 therefore puts
    // through the PIN counters. A policy that proves only the authPolicy does
    // not, and the note under clause 34.2.6 says the Reference Code was wrong
    // to move the counter for one that did.
    if s.policy.password_needed {
        let is_lockout = request.handle(index).ok() == Some(rh::LOCKOUT);
        check_pin_available(state, entity).map_err(|e| e.with_session(position))?;
        let outcome = compare_auth(state, &input.hmac, &entity.auth, protected, is_lockout);
        record_pin_attempt(state, entity, outcome.is_ok())?;
        return outcome.map_err(|e| e.with_session(position));
    }
    // Part 1 clause 16.6.9 gives the key for a policy session:
    // TPM2_PolicyAuthValue folds the entity value in, and without it the key is
    // the session key alone. Clause 16.6.16 then says when the caller may leave
    // the HMAC out: only when that key is empty, and even then a value that was
    // supplied is checked. Skipping the check whenever the key came out empty
    // would take any octets at all as authorization.
    let key = s.hmac_key(&entity.name, &entity.auth);
    let (nonce_decrypt, nonce_encrypt) = auxiliary_nonces(state, request, index);
    let expected = session::auth_hmac_with_nonces(
        s.auth_hash,
        &key,
        cp_hash,
        &input.nonce_caller,
        &s.nonce_tpm,
        &nonce_decrypt,
        &nonce_encrypt,
        input.attributes,
    )?;
    // TPM2_PolicyAuthValue folds the entity value into this key, which Part 1
    // clause 16.8.1 counts as a use of that value, so a PIN Index answers for
    // it here as well.
    let uses_auth_value = s.policy.auth_value_needed;
    if uses_auth_value {
        check_pin_available(state, entity).map_err(|e| e.with_session(position))?;
    }
    let accepted = session::auth_hmac_accepted(&key, &expected, &input.hmac);
    if uses_auth_value {
        record_pin_attempt(state, entity, accepted)?;
    }
    if !accepted {
        record_failure(state, protected)?;
        let code = if protected { rc::AUTH_FAIL } else { rc::BAD_AUTH };
        return Err(TpmRc(code).with_session(position));
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

/// Check that the session attributes are consistent, Part 3 clause 5.5.4.
///
/// One session may audit, one may decrypt and one may encrypt. The audit
/// session may not be one of the sessions that authorize a handle, and a
/// session that authorizes nothing has to do at least one of the three.
pub fn check_session_attributes(request: &Request) -> TpmResult<()> {
    let auth_handles = request.info.auth_handles as usize;
    let mut audit = None;
    let mut decrypt = None;
    let mut encrypt = None;

    for (index, input) in request.sessions.iter().enumerate() {
        let position = index + 1;
        let attributes = input.attributes;
        let attributes_error = || TpmRc(rc::ATTRIBUTES).with_session(position);

        // Part 1 clause 16.4 gives a password no session context, so it can
        // carry none of the three.
        if input.handle == rh::RS_PW
            && attributes.any(
                SessionAttributes::DECRYPT
                    | SessionAttributes::ENCRYPT
                    | SessionAttributes::AUDIT,
            )
        {
            return Err(attributes_error());
        }
        // Part 1 clause 17.3 allows auditExclusive and auditReset only in a
        // session that is also auditing.
        if !attributes.has(SessionAttributes::AUDIT)
            && attributes
                .any(SessionAttributes::AUDIT_EXCLUSIVE | SessionAttributes::AUDIT_RESET)
        {
            return Err(attributes_error());
        }
        if attributes.has(SessionAttributes::AUDIT) {
            if audit.is_some() || index < auth_handles {
                return Err(attributes_error());
            }
            audit = Some(index);
        }
        if attributes.has(SessionAttributes::DECRYPT) {
            if decrypt.is_some() {
                return Err(attributes_error());
            }
            decrypt = Some(index);
        }
        if attributes.has(SessionAttributes::ENCRYPT) {
            if encrypt.is_some() {
                return Err(attributes_error());
            }
            encrypt = Some(index);
        }
        // A session that authorizes no handle has to have a reason to be here.
        if index >= auth_handles
            && !attributes.any(
                SessionAttributes::DECRYPT
                    | SessionAttributes::ENCRYPT
                    | SessionAttributes::AUDIT,
            )
        {
            return Err(attributes_error());
        }
    }
    Ok(())
}

/// The position of the session that asked to audit the command.
pub fn audit_session_index(request: &Request) -> Option<usize> {
    request
        .sessions
        .iter()
        .position(|s| s.attributes.has(SessionAttributes::AUDIT))
}

/// Check the audit session before the command runs.
///
/// Part 1 clause 17.1 restricts audit to HMAC sessions, and clause 17.3 gates
/// the command on exclusivity as it stands at the start of the command.
pub fn check_audit_session(state: &TpmState, request: &Request) -> TpmResult<()> {
    let Some(index) = audit_session_index(request) else {
        return Ok(());
    };
    let input = &request.sessions[index];
    let position = index + 1;
    let s = state
        .sessions
        .get(input.handle)
?;
    if !s.is_hmac() {
        return Err(TpmRc(rc::ATTRIBUTES).with_session(position));
    }
    if input.attributes.has(SessionAttributes::AUDIT_EXCLUSIVE)
        && state.audit.exclusive_session != input.handle
    {
        return Err(TpmRc(rc::EXCLUSIVE));
    }
    Ok(())
}

/// Update the audit digests after the command has succeeded.
///
/// `command_parameters` are the parameters as they arrived, before any were
/// decrypted, and `response_parameters` are the ones being returned, after any
/// were encrypted. Part 1 clause 15.7 and clause 15.8 compute the two hashes
/// over exactly those octets.
pub fn update_audit(
    state: &mut TpmState,
    request: &Request,
    names: &[Vec<u8>],
    command_parameters: &[u8],
    response_parameters: &[u8],
) -> TpmResult<()> {
    let name_refs: Vec<&[u8]> = names.iter().map(|n| n.as_slice()).collect();
    let audit_index = audit_session_index(request);

    if let Some(index) = audit_index {
        let input = &request.sessions[index];
        // A command may have flushed the session it audited with.
        if let Ok(s) = state.sessions.get(input.handle) {
            let hash_alg = s.auth_hash;
            let was_audit = s.audit.is_audit;
            let old = if input.attributes.has(SessionAttributes::AUDIT_RESET) || !was_audit {
                Vec::new()
            } else {
                s.audit.digest.clone()
            };
            let cp = session::cp_hash(hash_alg, request.code, &name_refs, command_parameters)?;
            let rp = session::rp_hash(hash_alg, rc::SUCCESS, request.code, response_parameters)?;
            let digest = session::extend_audit(hash_alg, &old, &cp, &rp)?;
            let s = state.sessions.get_mut(input.handle)?;
            s.audit.is_audit = true;
            s.audit.digest = digest;
        }
    }

    // Part 1 clause 17.2 hands exclusivity to whichever session audited the
    // command, and takes it away when any other auditable command runs. A
    // command that is allowed no session at all is not auditable and so
    // leaves the exclusive session alone.
    if !requires_no_sessions(request.code) {
        state.audit.exclusive_session = match audit_index {
            Some(index) => request.sessions[index].handle,
            None => rh::UNASSIGNED,
        };
    }

    if command_audit_applies(state, request.code) {
        let hash_alg = state.audit.alg;
        let cp = session::cp_hash(hash_alg, request.code, &name_refs, command_parameters)?;
        let rp = session::rp_hash(hash_alg, rc::SUCCESS, request.code, response_parameters)?;
        // Part 1 clause 32 counts a new log when the digest register is empty,
        // so the counter moves on the first audited command of a sequence.
        if state.audit.digest.len() != crate::tpm::crypto::hash::digest_size(hash_alg)? {
            state.audit.counter = state.audit.counter.wrapping_add(1);
        }
        state.audit.digest = session::extend_audit(hash_alg, &state.audit.digest, &cp, &rp)?;
    }
    Ok(())
}

/// True for the four commands whose tag Part 3 requires to be
/// TPM_ST_NO_SESSIONS.
///
/// They can carry no audit session, so Part 1 clause 17.2 also leaves the
/// current exclusive audit session alone when one of them runs.
pub fn requires_no_sessions(code: u32) -> bool {
    matches!(
        code,
        cc::ContextSave | cc::ContextLoad | cc::FlushContext | cc::Startup
    )
}

/// True when the command code is one the TPM records in the command audit.
///
/// Part 3 clause 21.1 always audits TPM2_SetCommandCodeAuditStatus and never
/// audits TPM2_Shutdown, whatever the selected list says.
pub fn command_audit_applies(state: &TpmState, code: u32) -> bool {
    if code == cc::Shutdown || state.failure_mode || state.command_audit_suppressed {
        return false;
    }
    if code == cc::SetCommandCodeAuditStatus {
        return true;
    }
    state.audit.commands.contains(&code)
}

/// The exclusive status a session has, for the response session area.
fn is_exclusive(state: &TpmState, handle: u32) -> bool {
    handle != rh::RS_PW && state.audit.exclusive_session == handle
}

/// What an authorization used, captured before the command ran.
///
/// Part 1 clause 19.6.10 builds the response HMAC key the same way as the
/// command HMAC key, so the Name and authorization value have to be the ones
/// the command was authorized against. A command may change the Name, as the
/// first write to an NV Index does, or remove the entity outright, as
/// TPM2_NV_UndefineSpaceSpecial does.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    pub name: Vec<u8>,
    pub auth: Vec<u8>,
}

/// Build the response authorization area.
///
/// `nonces` holds the values [`roll_response_nonces`] produced and `contexts`
/// what each authorization used before the command ran.
pub fn build_response_sessions(
    state: &mut TpmState,
    request: &Request,
    response_code: u32,
    parameters: &[u8],
    nonces: &[Vec<u8>],
    contexts: &[AuthContext],
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
        // Part 1 clause 17.2 reports the exclusive status the session holds
        // now, whatever the command asked for.
        let attributes = response_attributes(state, input);
        let new_nonce = nonces.get(index).cloned().unwrap_or_default();
        let Ok(s) = state.sessions.get(input.handle) else {
            // The session went away, so there is nothing to answer with.
            AuthResponse {
                nonce: Tpm2bNonce::new(new_nonce)?,
                session_attributes: attributes,
                hmac: Tpm2bAuth::empty(),
            }
            .marshal(&mut w);
            continue;
        };

        let auth_hash = s.auth_hash;
        let rp = session::rp_hash(auth_hash, response_code, request.code, parameters)?;
        // The response HMAC uses the same key as the command HMAC, and Part 1
        // clause 16.6.16 says which shape it takes: "The TPM will use the same
        // formulation in the response as was in the command. This is, if hmac
        // was non-zero in the command, the TPM will compute authHMAC as shown
        // in Equation 17 and use the result as hmac. If hmac was an Empty
        // Buffer in the command, it will be an Empty Buffer in the response."
        // So it follows what the caller sent rather than being worked out again
        // from the session, which could differ from what the caller chose.
        let carries_hmac = !input.hmac.is_empty();
        let hmac = if carries_hmac {
            let context = contexts.get(index).cloned().unwrap_or_default();
            let s = state.sessions.get(input.handle)?;
            let key = if index < request.info.auth_handles as usize {
                s.hmac_key(&context.name, &context.auth)
            } else {
                // A session that authorized nothing keys with the session key
                // alone, just as its command HMAC did.
                s.session_key.clone()
            };
            session::auth_hmac(
                auth_hash,
                &key,
                &rp,
                &new_nonce,
                &input.nonce_caller,
                attributes,
            )?
        } else {
            Vec::new()
        };

        AuthResponse {
            nonce: Tpm2bNonce::new(new_nonce)?,
            session_attributes: attributes,
            hmac: Tpm2bAuth::new(hmac)?,
        }
        .marshal(&mut w);
    }
    w.finish()
}

/// The attributes echoed back for one session.
///
/// Only auditExclusive differs from what the command sent: Part 1 clause 17.2
/// makes it report whether the session holds exclusive status now.
fn response_attributes(state: &TpmState, input: &SessionInput) -> SessionAttributes {
    let mut attributes = input.attributes;
    attributes.set(
        SessionAttributes::AUDIT_EXCLUSIVE,
        input.attributes.has(SessionAttributes::AUDIT) && is_exclusive(state, input.handle),
    );
    attributes
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
            // Part 1 clause 17.7: a session "is no longer the current
            // exclusive audit session if it is flushed", and clause 19.6 has a
            // session with continueSession CLEAR closed at the end of the
            // command just as TPM2_FlushContext would.
            if state.audit.exclusive_session == input.handle {
                state.audit.exclusive_session = rh::UNASSIGNED;
            }
            continue;
        }
        // Part 1 clause 17.1 drops the binding of a session that audits, from
        // the next command onwards. The response of this command still uses
        // the bound key, because that is the key the caller computed with.
        // The dictionary attack protection of the bound entity stays, because
        // the session key still carries that entity's authorization value.
        if input.attributes.has(SessionAttributes::AUDIT) {
            if let Ok(s) = state.sessions.get_mut(input.handle) {
                s.bind = rh::NULL;
                s.bind_name.clear();
            }
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
    use crate::tpm::structures::attributes::{nt, NvAttributes};

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

    /// A command authorized by lockoutAuth, which Part 1 clause 16.8.1 makes
    /// the one permanent entity the dictionary attack counter protects.
    fn lockout_command(password: &[u8]) -> Vec<u8> {
        command(
            st::SESSIONS,
            cc::DictionaryAttackParameters,
            &[rh::LOCKOUT],
            &password_auth(password),
            &[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0],
        )
    }

    fn owner_command(password: &[u8]) -> Vec<u8> {
        command(
            st::SESSIONS,
            cc::Clear,
            &[rh::OWNER],
            &password_auth(password),
            &[],
        )
    }

    /// An entity that carries dictionary attack protection without being
    /// lockoutAuth. Part 1 clause 16.8.1 leaves every permanent entity but
    /// TPM_RH_LOCKOUT out of it, so an ordinary object stands in here.
    fn protected_entity(auth: &[u8]) -> Entity {
        Entity {
            name: rh::OWNER.to_be_bytes().to_vec(),
            auth: auth.to_vec(),
            policy: None,
            uses_lockout: true,
            user_with_auth: true,
            admin_with_policy: true,
            pin: None,
        }
    }

    #[test]
    fn a_password_authorization_is_compared_against_the_entity() {
        let mut state = TpmState::manufacture().unwrap();
        state.lockout_auth = b"secret".to_vec();
        let buf = lockout_command(b"secret");
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::LOCKOUT).unwrap();
        assert!(check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).is_ok());

        let buf = lockout_command(b"wrong");
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::LOCKOUT).unwrap();
        let err = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap_err();
        assert_eq!(err.0 & 0x03F, rc::AUTH_FAIL & 0x03F);
        assert_eq!(state.lockout.failed_tries, 1);
    }

    #[test]
    fn a_permanent_entity_other_than_lockout_is_not_protected() {
        // Part 1 clause 16.8.1 leaves every permanent entity except
        // TPM_RH_LOCKOUT out of dictionary attack protection.
        let state = TpmState::manufacture().unwrap();
        for handle in [rh::OWNER, rh::ENDORSEMENT, rh::PLATFORM, rh::NULL] {
            assert!(!entity(&state, handle).unwrap().uses_lockout, "{handle:#x}");
        }
        assert!(entity(&state, rh::LOCKOUT).unwrap().uses_lockout);
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

    /// A session area holding the given attributes, all on loaded handles.
    fn session_area(entries: &[(u32, u8)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (handle, attributes) in entries {
            out.extend_from_slice(
                &AuthCommand {
                    session_handle: *handle,
                    nonce: Tpm2bNonce::empty(),
                    session_attributes: SessionAttributes(*attributes),
                    hmac: Tpm2bAuth::empty(),
                }
                .to_bytes(),
            );
        }
        out
    }

    #[test]
    fn a_public_only_object_cannot_be_authorized() {
        use crate::tpm::core::object::{Object, Slot};
        use crate::tpm::structures::attributes::ObjectAttributes;
        use crate::tpm::structures::base::Tpm2bDigest;
        use crate::tpm::structures::keys::{PublicId, PublicParms, TpmtPublic};
        use crate::tpm::structures::schemes::Scheme;

        let mut state = TpmState::manufacture().unwrap();
        let public = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::USER_WITH_AUTH),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme::null(),
            },
            unique: PublicId::KeyedHash(Tpm2bDigest::empty()),
        };
        // Part 3 clause 5.6.1 needs the sensitive area, which is absent here.
        let object = Object::new(public, None, rh::NULL, &[], false).unwrap();
        let handle = state.objects.insert(Slot::Object(Box::new(object))).unwrap();
        assert_eq!(
            entity(&state, handle).map(|_| ()).unwrap_err(),
            TpmRc(rc::AUTH_UNAVAILABLE)
        );
    }

    #[test]
    fn the_session_attributes_have_to_be_consistent() {
        let state = TpmState::manufacture().unwrap();
        let hmac = hc::HMAC_SESSION_FIRST;
        let other = hc::HMAC_SESSION_FIRST + 1;
        let cont = SessionAttributes::CONTINUE_SESSION;

        // TPM2_NV_Read has one handle that needs authorization.
        let read = |area: Vec<u8>| {
            command(
                st::SESSIONS,
                cc::NV_Read,
                &[rh::OWNER, hc::NV_INDEX_FIRST],
                &area,
                &[0x00, 0x08, 0x00, 0x00],
            )
        };

        // An authorization session may not also audit.
        let buf = read(session_area(&[(hmac, cont | SessionAttributes::AUDIT)]));
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(
            check_session_attributes(&req).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_session(1)
        );

        // Two sessions may not both audit.
        let buf = read(session_area(&[
            (rh::RS_PW, cont),
            (hmac, cont | SessionAttributes::AUDIT),
            (other, cont | SessionAttributes::AUDIT),
        ]));
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(
            check_session_attributes(&req).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_session(3)
        );

        // Two sessions may not both decrypt.
        let buf = read(session_area(&[
            (rh::RS_PW, cont),
            (hmac, cont | SessionAttributes::DECRYPT),
            (other, cont | SessionAttributes::DECRYPT),
        ]));
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(
            check_session_attributes(&req).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_session(3)
        );

        // A session that authorizes nothing has to ask for something.
        let buf = read(session_area(&[(rh::RS_PW, cont), (hmac, cont)]));
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(
            check_session_attributes(&req).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_session(2)
        );

        // A password may not encrypt, decrypt or audit.
        let buf = read(session_area(&[(
            rh::RS_PW,
            cont | SessionAttributes::ENCRYPT,
        )]));
        let req = parse(&state, &buf, 0).unwrap();
        assert_eq!(
            check_session_attributes(&req).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_session(1)
        );

        // One authorization and one session that encrypts the response is the
        // ordinary arrangement.
        let buf = read(session_area(&[
            (rh::RS_PW, cont),
            (hmac, cont | SessionAttributes::ENCRYPT),
        ]));
        let req = parse(&state, &buf, 0).unwrap();
        check_session_attributes(&req).unwrap();
    }

    #[test]
    fn a_session_area_is_refused_where_the_tag_must_be_no_sessions() {
        let state = TpmState::manufacture().unwrap();
        let auth = password_auth(b"");
        for code in [
            cc::Startup,
            cc::ContextSave,
            cc::ContextLoad,
            cc::FlushContext,
        ] {
            let buf = command(st::SESSIONS, code, &[], &auth, &[]);
            assert_eq!(parse(&state, &buf, 0).unwrap_err(), TpmRc(rc::AUTH_CONTEXT));
        }
        // TPM2_ReadClock does take an audit session, so it is not refused.
        let buf = command(st::SESSIONS, cc::ReadClock, &[], &auth, &[]);
        assert!(parse(&state, &buf, 0).is_ok());
    }

    #[test]
    fn repeated_failures_enter_lockout() {
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"secret".to_vec();
        state.lockout.max_tries = 3;
        let buf = owner_command(b"wrong");
        for _ in 0..3 {
            let req = parse(&state, &buf, 0).unwrap();
            let e = protected_entity(b"secret");
            let _ = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]);
        }
        // Part 1 clause 16.8.3: "the TPM is in Lockout mode while failedTries
        // is equal to maxTries."
        assert!(state.lockout.locked_out());

        // The clause refuses the protected value while the TPM is in Lockout
        // mode, even when the caller has it right.
        let buf = owner_command(b"secret");
        let req = parse(&state, &buf, 0).unwrap();
        let e = protected_entity(b"secret");
        assert_eq!(
            check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap_err(),
            TpmRc(rc::LOCKOUT)
        );

        // Clause 16.8.4 item 1: TPM2_DictionaryAttackLockReset is what puts
        // the counter back, and a success on its own does not.
        state.lockout.failed_tries = 0;
        let req = parse(&state, &buf, 0).unwrap();
        let e = protected_entity(b"secret");
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap();
        assert_eq!(state.lockout.failed_tries, 0);
    }

    fn pin_index(kind: u8, count: u32, limit: u32) -> crate::tpm::core::nv::NvIndex {
        use crate::tpm::structures::nv::{NvPinCounterParameters, NvPublic};
        let mut index = crate::tpm::core::nv::NvIndex {
            public: NvPublic {
                nv_index: hc::NV_INDEX_FIRST,
                name_alg: alg::SHA256,
                attributes: NvAttributes(NvAttributes::AUTHREAD | NvAttributes::OWNERWRITE)
                    .with_index_type(kind),
                auth_policy: crate::tpm::structures::base::Tpm2bDigest::empty(),
                data_size: 8,
            },
            auth: b"pin".to_vec(),
            data: Vec::new(),
            read_locked: false,
            write_locked: false,
        };
        index
            .set_pin_counters(NvPinCounterParameters {
                pin_count: count,
                pin_limit: limit,
            })
            .unwrap();
        index
    }

    fn pin_attempt(state: &mut TpmState, password: &[u8]) -> TpmResult<()> {
        let auth = password_auth(password);
        let buf = command(
            st::SESSIONS,
            cc::PolicySecret,
            &[hc::NV_INDEX_FIRST, hc::POLICY_SESSION_FIRST],
            &auth,
            &[],
        );
        let req = parse(state, &buf, 0).unwrap();
        let e = entity(state, hc::NV_INDEX_FIRST).unwrap();
        check_authorization(state, &req, 0, &e, &[0u8; 32])
    }

    #[test]
    fn a_pin_pass_index_counts_its_successes() {
        // Part 1 clause 34.2.6: on success "the pinCount field is set to zero
        // if the Index is PIN Fail and incremented if the Index is PIN Pass",
        // and the authorization fails once pinCount is not less than pinLimit.
        let mut state = TpmState::manufacture().unwrap();
        state
            .nv
            .define(pin_index(nt::PIN_PASS, 0, 2))
            .unwrap();
        pin_attempt(&mut state, b"pin").expect("the first use was refused");
        pin_attempt(&mut state, b"pin").expect("the second use was refused");
        assert_eq!(
            state
                .nv
                .get(hc::NV_INDEX_FIRST)
                .unwrap()
                .pin_counters()
                .unwrap()
                .pin_count,
            2
        );
        assert!(
            pin_attempt(&mut state, b"pin").is_err(),
            "a third use was allowed past the limit"
        );
    }

    #[test]
    fn a_pin_fail_index_counts_its_failures_and_forgets_them_on_success() {
        let mut state = TpmState::manufacture().unwrap();
        state
            .nv
            .define(pin_index(nt::PIN_FAIL, 0, 2))
            .unwrap();
        assert!(pin_attempt(&mut state, b"wrong").is_err());
        assert_eq!(
            state
                .nv
                .get(hc::NV_INDEX_FIRST)
                .unwrap()
                .pin_counters()
                .unwrap()
                .pin_count,
            1,
            "a failure was not counted"
        );
        pin_attempt(&mut state, b"pin").expect("the right value was refused");
        assert_eq!(
            state
                .nv
                .get(hc::NV_INDEX_FIRST)
                .unwrap()
                .pin_counters()
                .unwrap()
                .pin_count,
            0,
            "a success did not clear the count"
        );
    }

    #[test]
    fn a_pin_index_may_not_be_a_bind_entity() {
        // Part 1 clause 34.2.9: "if a PIN Pass or PIN Fail Index is referenced
        // as a bind entity, the TPM must return TPM_RC_HANDLE. Otherwise, the
        // sequence in which the TPM processes authorizations would enable a
        // hammering attack on the Index."
        let mut state = TpmState::manufacture().unwrap();
        state.on_startup_clear(0).unwrap();
        state.nv.define(pin_index(nt::PIN_PASS, 0, 5)).unwrap();

        let mut p = Writer::new();
        p.u16(32);
        p.bytes(&[0u8; 32]);
        p.u16(0);
        p.u8(se::HMAC);
        p.u16(alg::NULL);
        p.u16(alg::SHA256);
        let buf = command(
            st::NO_SESSIONS,
            cc::StartAuthSession,
            &[rh::NULL, hc::NV_INDEX_FIRST],
            &[],
            &p.finish().unwrap(),
        );
        let r = crate::tpm::commands::execute::run(&mut state, 0, &buf);
        let code = u32::from_be_bytes([r[6], r[7], r[8], r[9]]);
        assert_eq!(
            code & 0x03f,
            rc::HANDLE & 0x03f,
            "a PIN Index was bound to a session -> {code:08x}"
        );
    }

    #[test]
    fn a_pin_index_that_was_never_written_authorizes_nothing() {
        // The same clause: the authorization fails "if the TPMA_NV_WRITTEN
        // attribute of the Index is CLEAR".
        use crate::tpm::structures::nv::NvPublic;
        let mut state = TpmState::manufacture().unwrap();
        state
            .nv
            .define(crate::tpm::core::nv::NvIndex {
                public: NvPublic {
                    nv_index: hc::NV_INDEX_FIRST,
                    name_alg: alg::SHA256,
                    attributes: NvAttributes(NvAttributes::AUTHREAD | NvAttributes::OWNERWRITE)
                        .with_index_type(nt::PIN_PASS),
                    auth_policy: crate::tpm::structures::base::Tpm2bDigest::empty(),
                    data_size: 8,
                },
                auth: b"pin".to_vec(),
                data: Vec::new(),
                read_locked: false,
                write_locked: false,
            })
            .unwrap();
        assert!(
            pin_attempt(&mut state, b"pin").is_err(),
            "an Index with nothing written authorized something"
        );
    }

    #[test]
    fn a_failure_against_lockout_auth_bars_it_by_itself() {
        // Part 1 clause 16.8.5: such a failure "causes the TPM to enter this
        // special lockout state regardless of the setting of failedTries and
        // maxTries", and "when in this special lockout state, the TPM will not
        // allow use of lockoutAuth".
        let mut state = TpmState::manufacture().unwrap();
        state.lockout_auth = b"secret".to_vec();
        state.lockout.max_tries = 100;
        let buf = lockout_command(b"wrong");
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::LOCKOUT).unwrap();
        let _ = check_authorization(&mut state, &req, 0, &e, &[0u8; 32]);
        assert!(state.lockout.in_lockout, "the special lockout was not entered");
        assert!(!state.lockout.locked_out(), "lockout mode was entered as well");

        let buf = lockout_command(b"secret");
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::LOCKOUT).unwrap();
        assert_eq!(
            check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap_err(),
            TpmRc(rc::LOCKOUT)
        );

        // Another entity is not barred by it.
        state.hierarchies.owner.auth = b"other".to_vec();
        let buf = owner_command(b"other");
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::OWNER).unwrap();
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32])
            .expect("the special lockout barred another entity");
    }

    #[test]
    fn lockout_stops_a_policy_that_calls_for_the_auth_value() {
        let mut state = TpmState::manufacture().unwrap();
        state.lockout_auth = b"secret".to_vec();
        state.lockout_policy = crate::tpm::structures::base::TpmtHa {
            hash_alg: alg::SHA256,
            digest: vec![0u8; 32],
        };
        state.lockout.in_lockout = true;

        let handle = state.sessions.allocate_handle(se::POLICY).unwrap();
        let s = Session::new(
            handle,
            se::POLICY,
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
            nonce: Tpm2bNonce::new(vec![0u8; 32]).unwrap(),
            session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
            hmac: Tpm2bAuth::empty(),
        }
        .to_bytes();
        let buf = command(
            st::SESSIONS,
            cc::DictionaryAttackParameters,
            &[rh::LOCKOUT],
            &auth,
            &[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // A policy that never calls for the authValue uses no protected value,
        // so Lockout mode does not reach it. The satisfied policy authorizes.
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::LOCKOUT).unwrap();
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap();

        // A policy that called TPM2_PolicyAuthValue does use it.
        state
            .sessions
            .get_mut(handle)
            .unwrap()
            .policy
            .auth_value_needed = true;
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::LOCKOUT).unwrap();
        assert_eq!(
            check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap_err(),
            TpmRc(rc::LOCKOUT)
        );
    }

    #[test]
    fn lockout_follows_a_session_bound_to_a_protected_entity() {
        let mut state = TpmState::manufacture().unwrap();
        state.lockout.in_lockout = true;

        let handle = state.sessions.allocate_handle(se::HMAC).unwrap();
        let mut s = Session::new(
            handle,
            se::HMAC,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            Vec::new(),
            hc::TRANSIENT_FIRST,
            b"bound".to_vec(),
            crate::tpm::structures::schemes::SymDef::null(),
        )
        .unwrap();
        s.bind_uses_lockout = true;
        state.sessions.insert(s).unwrap();
        // The TPM has to be in Lockout mode for the bound session to be
        // stopped by it, which clause 16.8.3 words as failedTries equalling
        // maxTries.
        state.lockout.failed_tries = state.lockout.max_tries;

        let auth = AuthCommand {
            session_handle: handle,
            nonce: Tpm2bNonce::new(vec![0u8; 32]).unwrap(),
            session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
            hmac: Tpm2bAuth::empty(),
        }
        .to_bytes();
        // TPM_RH_PLATFORM is exempt, but Part 1 clause 16.8.7 still blocks the
        // session because its key holds the bound entity's authValue.
        let buf = command(st::SESSIONS, cc::Clear, &[rh::PLATFORM], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::PLATFORM).unwrap();
        assert!(!e.uses_lockout);
        assert_eq!(
            check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap_err(),
            TpmRc(rc::LOCKOUT)
        );
    }

    #[test]
    fn a_successful_authorization_does_not_reset_the_counter() {
        // Guessing against a protected entity, then succeeding against an
        // exempt one, must not clear the dictionary attack counter.
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.owner.auth = b"secret".to_vec();
        state.hierarchies.platform.auth = b"known".to_vec();

        let buf = owner_command(b"wrong");
        let req = parse(&state, &buf, 0).unwrap();
        let e = protected_entity(b"secret");
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

        // Nor does a success against the protected entity. Part 1 clause
        // 16.8.4 gives three ways the counter goes down, and an ordinary
        // success is not one: otherwise a guess could be followed by a success
        // on an entity the attacker owns, and lockout would never arrive.
        let buf = owner_command(b"secret");
        let req = parse(&state, &buf, 0).unwrap();
        let e = protected_entity(b"secret");
        check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).unwrap();
        assert_eq!(
            state.lockout.failed_tries, 1,
            "a success put the counter back"
        );
    }

    #[test]
    fn a_bound_session_carries_the_protection_of_its_bind_entity() {
        // Part 1 clause 16.8.7: guessing the value of a protected entity by
        // binding to it and using the session against an exempt one has to
        // count against the lockout.
        let mut state = TpmState::manufacture().unwrap();
        state.hierarchies.platform.auth = b"known".to_vec();

        let handle = state.sessions.allocate_handle(se::HMAC).unwrap();
        let mut s = Session::new(
            handle,
            se::HMAC,
            alg::SHA256,
            vec![0u8; 32],
            vec![0u8; 32],
            vec![9u8; 32],
            hc::TRANSIENT_FIRST,
            b"bound".to_vec(),
            crate::tpm::structures::schemes::SymDef::null(),
        )
        .unwrap();
        s.bind_uses_lockout = true;
        state.sessions.insert(s).unwrap();

        let auth = AuthCommand {
            session_handle: handle,
            nonce: Tpm2bNonce::new(vec![0u8; 32]).unwrap(),
            session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
            hmac: Tpm2bAuth::new(vec![0u8; 32]).unwrap(),
        }
        .to_bytes();
        let buf = command(st::SESSIONS, cc::Clear, &[rh::PLATFORM], &auth, &[]);
        let req = parse(&state, &buf, 0).unwrap();
        let e = entity(&state, rh::PLATFORM).unwrap();
        assert!(!e.uses_lockout);
        assert!(check_authorization(&mut state, &req, 0, &e, &[0u8; 32]).is_err());
        assert_eq!(state.lockout.failed_tries, 1);
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
