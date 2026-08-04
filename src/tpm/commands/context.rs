//! Context management, Part 3 clause 28, and persistent objects, clause 28.5.

use crate::tpm::config;
use crate::tpm::constants::{alg, hc, rc, rh};
use crate::tpm::core::object::{Object, Sequence, SequenceKind, Slot};
use crate::tpm::structures::context::saved;
use crate::tpm::core::session::Session;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{hash, hmac as mac, sym};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::base::{Tpm2bContextData, Tpm2bDigest};
use crate::tpm::structures::context::{Context, ContextData};

use super::dispatch::{Request, Response};
use super::execute::{respond, respond_with_handle};

/// The label of the key that encrypts a saved context.
const LABEL_CONTEXT: &str = "CONTEXT";
/// The label of the key that covers a saved context with an HMAC.
const LABEL_INTEGRITY: &str = "INTEGRITY";

/// The keys that protect a context saved under `hierarchy`.
fn context_keys(state: &TpmState, hierarchy: u32, sequence: u64) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    let proof = state.hierarchy_proof(hierarchy)?.to_vec();
    let alg_id = config::CONTEXT_INTEGRITY_HASH_ALG;
    let sym_key = mac::kdfa(
        alg_id,
        &proof,
        LABEL_CONTEXT,
        &sequence.to_be_bytes(),
        &[],
        config::CONTEXT_ENCRYPT_KEY_BITS as u32,
    )?;
    let hmac_key = mac::kdfa(
        alg_id,
        &proof,
        LABEL_INTEGRITY,
        &sequence.to_be_bytes(),
        &[],
        (hash::digest_size(alg_id)? * 8) as u32,
    )?;
    Ok((sym_key, hmac_key))
}

/// Encrypt and authenticate a marshalled context.
/// The values Part 1 Equation 52 puts in front of the context.
///
///   data := resetValue {||clearCount} || sequence || handle || encContext
///
/// resetValue "increments on each TPM Reset and is not reset over the lifetime
/// of the TPM", which is what invalidates every saved context on a Reset.
/// clearCount "is incremented on each TPM Restart" and "is only included if the
/// handle value is 80 00 00 02", which is the value a saved object carries when
/// it has the stateClear property.
fn context_counters(state: &TpmState, saved_handle: u32) -> Vec<u8> {
    let mut out = state.clock.total_reset_count.to_be_bytes().to_vec();
    if saved_handle == saved::TRANSIENT_STCLEAR {
        out.extend_from_slice(&state.clock.clear_count.to_be_bytes());
    }
    out
}

fn seal_context(
    state: &TpmState,
    hierarchy: u32,
    sequence: u64,
    saved_handle: u32,
    body: &[u8],
) -> TpmResult<Tpm2bContextData> {
    let (sym_key, hmac_key) = context_keys(state, hierarchy, sequence)?;
    let iv = vec![0u8; sym::block_size(config::CONTEXT_ENCRYPT_ALG)?];
    let encrypted = sym::cfb_encrypt(&sym_key, &iv, body)?;
    // The hierarchy is not among them: Equation 52 takes hProof "as selected by
    // the hierarchy parameter of the TPMS_CONTEXT" as the HMAC key, so the
    // hierarchy is already what the key is.
    let integrity = mac::hmac_parts(
        config::CONTEXT_INTEGRITY_HASH_ALG,
        &hmac_key,
        &[
            &context_counters(state, saved_handle),
            &sequence.to_be_bytes(),
            &saved_handle.to_be_bytes(),
            &encrypted,
        ],
    )?;
    let data = ContextData {
        integrity: Tpm2bDigest::new(integrity)?,
        encrypted: crate::tpm::structures::base::Tpm2bContextSensitive::new(encrypted)?,
    };
    Tpm2bContextData::new(data.to_bytes())
}

/// Check and decrypt a saved context.
fn open_context(state: &TpmState, context: &Context) -> TpmResult<Vec<u8>> {
    let (sym_key, hmac_key) = context_keys(state, context.hierarchy, context.sequence)?;
    let data = ContextData::from_bytes(context.context_blob.as_slice())
        .map_err(|_| TpmRc(rc::BAD_CONTEXT).with_parameter(1))?;
    let expected = mac::hmac_parts(
        config::CONTEXT_INTEGRITY_HASH_ALG,
        &hmac_key,
        &[
            &context_counters(state, context.saved_handle),
            &context.sequence.to_be_bytes(),
            &context.saved_handle.to_be_bytes(),
            data.encrypted.as_slice(),
        ],
    )?;
    if !crate::tpm::core::protect::constant_time_eq(&expected, data.integrity.as_slice()) {
        return Err(TpmRc(rc::INTEGRITY).with_parameter(1));
    }
    let iv = vec![0u8; sym::block_size(config::CONTEXT_ENCRYPT_ALG)?];
    sym::cfb_decrypt(&sym_key, &iv, data.encrypted.as_slice())
}

/// Marshal a loaded object into a context body.
fn marshal_object(object: &Object) -> TpmResult<Vec<u8>> {
    let mut w = Writer::new();
    w.u32(object.hierarchy);
    w.u8(u8::from(object.tpm_generated));
    object.public.marshal(&mut w);
    match &object.sensitive {
        Some(s) => {
            w.u8(1);
            s.marshal(&mut w);
        }
        None => w.u8(0),
    }
    w.sized16(&object.qualified_name);
    w.finish()
}

/// Rebuild an object from a context body.
fn unmarshal_object(body: &[u8], state_clear: bool) -> TpmResult<Object> {
    let mut r = Reader::new(body);
    let hierarchy = r.u32()?;
    let tpm_generated = r.u8()? != 0;
    let public = crate::tpm::structures::keys::TpmtPublic::unmarshal(&mut r)?;
    let sensitive = if r.u8()? != 0 {
        Some(crate::tpm::structures::keys::TpmtSensitive::unmarshal(
            &mut r,
        )?)
    } else {
        None
    };
    let qn_size = r.u16()? as usize;
    let qualified_name = r.take(qn_size)?.to_vec();
    // The integrity check says the blob is this TPM's, not that a build with
    // the same seeds was right to save what is in it, so the object has to
    // pass what TPM2_Load would apply to it today.
    crate::tpm::core::object::validate_restored(&public, sensitive.as_ref())?;
    let name = crate::tpm::core::names::object_name(&public)?;
    Ok(Object {
        public,
        sensitive,
        name,
        qualified_name,
        hierarchy,
        tpm_generated,
        state_clear,
    })
}

/// Marshal a sequence into a context body.
fn marshal_sequence(sequence: &Sequence) -> TpmResult<Vec<u8>> {
    let mut w = Writer::new();
    match &sequence.kind {
        SequenceKind::Hash { hash_alg } => {
            w.u8(0);
            w.u16(*hash_alg);
        }
        SequenceKind::Hmac { hash_alg, key } => {
            w.u8(1);
            w.u16(*hash_alg);
            w.sized16(key);
        }
        SequenceKind::Event => w.u8(2),
    }
    w.sized16(&sequence.auth);
    w.u32(sequence.buffer.len() as u32);
    w.bytes(&sequence.buffer);
    w.finish()
}

/// Rebuild a sequence from a context body.
fn unmarshal_sequence(body: &[u8]) -> TpmResult<Sequence> {
    let mut r = Reader::new(body);
    let kind = match r.u8()? {
        0 => SequenceKind::Hash {
            hash_alg: r.u16()?,
        },
        1 => {
            let hash_alg = r.u16()?;
            let size = r.u16()? as usize;
            SequenceKind::Hmac {
                hash_alg,
                key: r.take(size)?.to_vec(),
            }
        }
        2 => SequenceKind::Event,
        _ => return Err(TpmRc(rc::BAD_CONTEXT)),
    };
    let auth_size = r.u16()? as usize;
    let auth = r.take(auth_size)?.to_vec();
    let len = r.u32()? as usize;
    if len > crate::tpm::core::object::MAX_SEQUENCE_BYTES {
        return Err(TpmRc(rc::BAD_CONTEXT));
    }
    let buffer = r.take(len)?.to_vec();
    Ok(Sequence {
        kind,
        auth,
        buffer,
    })
}

/// Marshal a session into a context body.
fn marshal_session(session: &Session) -> TpmResult<Vec<u8>> {
    let mut w = Writer::new();
    w.u32(session.handle);
    w.u8(session.session_type);
    w.u16(session.auth_hash);
    w.sized16(&session.nonce_tpm);
    w.sized16(&session.nonce_caller);
    w.sized16(&session.session_key);
    w.u32(session.bind);
    w.sized16(&session.bind_name);
    w.u8(u8::from(session.bind_uses_lockout));
    w.u64(session.start_time);
    w.u64(session.time_epoch);
    session.symmetric.marshal(&mut w);
    // Part 1 clause 27.2.1 carries the whole policy state, not just the
    // digest, so a reloaded session keeps every restriction it recorded.
    session.policy.marshal(&mut w);
    // A saved audit session keeps auditing when it comes back, so its digest
    // travels with it.
    w.u8(u8::from(session.audit.is_audit));
    w.sized16(&session.audit.digest);
    w.finish()
}

/// Rebuild a session from a context body.
fn unmarshal_session(body: &[u8]) -> TpmResult<Session> {
    let mut r = Reader::new(body);
    let handle = r.u32()?;
    let session_type = r.u8()?;
    let auth_hash = r.u16()?;
    let read = |r: &mut Reader<'_>| -> TpmResult<Vec<u8>> {
        let n = r.u16()? as usize;
        Ok(r.take(n)?.to_vec())
    };
    let nonce_tpm = read(&mut r)?;
    let nonce_caller = read(&mut r)?;
    let session_key = read(&mut r)?;
    let bind = r.u32()?;
    let bind_name = read(&mut r)?;
    let bind_uses_lockout = r.u8()? != 0;
    let start_time = r.u64()?;
    let time_epoch = r.u64()?;
    let symmetric = crate::tpm::structures::schemes::SymDef::unmarshal_sym_def(&mut r)?;
    let policy = crate::tpm::core::session::PolicyState::unmarshal(&mut r)?;
    let is_audit = r.u8()? != 0;
    let audit_digest = read(&mut r)?;

    let mut session = Session::new(
        handle,
        session_type,
        auth_hash,
        nonce_tpm,
        nonce_caller,
        session_key,
        bind,
        bind_name,
        symmetric,
    )?;
    session.bind_uses_lockout = bind_uses_lockout;
    session.start_time = start_time;
    session.time_epoch = time_epoch;
    session.policy = policy;
    session.audit.is_audit = is_audit;
    session.audit.digest = audit_digest;
    Ok(session)
}

/// TPM2_ContextSave, Part 3 clause 28.2.
pub fn context_save(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;

    let (hierarchy, saved_handle, body, sequence) =
        if crate::tpm::core::session::is_session_handle(handle) {
            let (session, id) = state.sessions.save(handle).map_err(|e| e.with_handle(1))?;
            // A session context is protected by the storage hierarchy proof so
            // that TPM2_Clear invalidates it.
            (rh::NULL, handle, marshal_session(&session)?, id)
        } else {
            let slot = state.objects.get(handle).map_err(|e| e.with_handle(1))?;
            let sequence_id = state.sessions.next_context_id();
            match slot {
                Slot::Object(o) => {
                    // An object that may not be duplicated may still be saved,
                    // because a context never leaves this TPM.
                    let saved_handle = if o.state_clear {
                        saved::TRANSIENT_STCLEAR
                    } else {
                        saved::TRANSIENT_OBJECT
                    };
                    (o.hierarchy, saved_handle, marshal_object(o)?, sequence_id)
                }
                Slot::Sequence(s) => (
                    rh::NULL,
                    saved::SEQUENCE_OBJECT,
                    marshal_sequence(s)?,
                    sequence_id,
                ),
            }
        };

    let blob = seal_context(state, hierarchy, sequence, saved_handle, &body)?;
    let context = Context {
        sequence,
        saved_handle,
        hierarchy,
        context_blob: blob,
    };
    respond(move |w| {
        context.marshal(w);
        Ok(())
    })
}

/// TPM2_ContextLoad, Part 3 clause 28.3.
pub fn context_load(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let context = Context::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;

    if context.sequence > state.sessions.context_counter() {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    let body = open_context(state, &context)?;

    match context.saved_handle {
        h if crate::tpm::core::session::is_session_handle(h) => {
            let session = unmarshal_session(&body).map_err(|_| TpmRc(rc::BAD_CONTEXT))?;
            if session.handle != h {
                return Err(TpmRc(rc::BAD_CONTEXT).with_parameter(1));
            }
            state.sessions.restore(session)?;
            respond_with_handle(h, |_| Ok(()))
        }
        saved::SEQUENCE_OBJECT => {
            let sequence = unmarshal_sequence(&body).map_err(|_| TpmRc(rc::BAD_CONTEXT))?;
            let handle = state.objects.insert(Slot::Sequence(Box::new(sequence)))?;
            respond_with_handle(handle, |_| Ok(()))
        }
        saved::TRANSIENT_OBJECT | saved::TRANSIENT_STCLEAR => {
            // Part 1 clause 30.4.2 gives the two savedHandle values their
            // meaning: one "indicates a Transient Object that does not have the
            // stateClear property" and the other one that does.
            let state_clear = context.saved_handle == saved::TRANSIENT_STCLEAR;
            let object =
                unmarshal_object(&body, state_clear).map_err(|_| TpmRc(rc::BAD_CONTEXT))?;
            let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
            respond_with_handle(handle, |_| Ok(()))
        }
        _ => Err(TpmRc(rc::VALUE).with_parameter(1)),
    }
}

/// TPM2_EvictControl, Part 3 clause 28.5.
pub fn evict_control(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let auth = request.handle(0)?;
    let object_handle = request.handle(1)?;
    let mut r = request.reader();
    let persistent_handle = r.u32().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;

    if !(hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&persistent_handle) {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    // The platform owns the upper half of the persistent range.
    let is_platform_range = persistent_handle >= hc::PLATFORM_PERSISTENT;
    if !matches!(auth, rh::PLATFORM | rh::OWNER) {
        return Err(TpmRc(rc::AUTH_TYPE).with_handle(1));
    }

    // Naming a persistent object removes it, and the clause gives a removal its
    // own rules. Rule 8: "if auth is TPM_RH_OWNER, objectHandle shall be in the
    // inclusive range of 81 00 00 00 to 81 7F FF FF. If auth is
    // TPM_RH_PLATFORM, objectHandle may be any valid persistent object handle."
    // So the platform may remove one the owner made, which the range rule for
    // making an object persistent would not allow. Rule 9: "if objectHandle is
    // not the same value as persistentHandle, return TPM_RC_HANDLE."
    if (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&object_handle) {
        if auth == rh::OWNER && object_handle >= hc::PLATFORM_PERSISTENT {
            return Err(TpmRc(rc::RANGE).with_handle(2));
        }
        if object_handle != persistent_handle {
            return Err(TpmRc(rc::HANDLE).with_handle(2));
        }
        state
            .persistent
            .remove(&persistent_handle)
            .ok_or(TpmRc(rc::HANDLE).with_handle(2))?;
        return respond(|_| Ok(()));
    }

    // Rule 3 is about where a new persistent object may go, so it applies to
    // making one and not to removing one.
    match auth {
        rh::PLATFORM => {
            if !is_platform_range {
                return Err(TpmRc(rc::RANGE).with_parameter(1));
            }
        }
        _ => {
            if is_platform_range {
                return Err(TpmRc(rc::RANGE).with_parameter(1));
            }
        }
    }

    let object = state
        .objects
        .object(object_handle)
        .map_err(|e| e.with_handle(2))?
        .clone();

    // Part 3 clause 28.5.1 lists what a transient object may not be: it may not
    // be "in the hierarchy of TPM_RH_NULL or a firmware-limited or SVN-limited
    // hierarchy", and stClear may not be set in it or in an ancestor. The
    // clause says nothing of fixedTPM, and the note beside it says "older
    // versions of the specification did not allow an object to be persisted
    // when only the public portion of the object was loaded (for NV space
    // efficiency). Support for persisting public-only objects was added in
    // version 185."
    if object.hierarchy == rh::NULL {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    // Rule 2: "the TPM shall return TPM_RC_HIERARCHY if the object is not in
    // the proper hierarchy as determined by auth. If auth is TPM_RH_PLATFORM,
    // the proper hierarchy is the Platform hierarchy. If auth is
    // TPM_RH_OWNER, the proper hierarchy is either the Storage or the
    // Endorsement hierarchy."
    let proper = match auth {
        rh::PLATFORM => object.hierarchy == rh::PLATFORM,
        _ => object.hierarchy == rh::OWNER || object.hierarchy == rh::ENDORSEMENT,
    };
    if !proper {
        return Err(TpmRc(rc::HIERARCHY).with_handle(2));
    }
    // Rule 1.2 is "the stClear is SET in the object or in an ancestor key",
    // which is the stateClear property Part 1 clause 30.4.2 defines and the
    // object carries from when its parent was still known.
    if object.state_clear {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    if state.persistent.contains_key(&persistent_handle) {
        return Err(TpmRc(rc::NV_DEFINED).with_parameter(1));
    }
    if state.persistent.len() >= config::MIN_EVICT_OBJECTS as usize {
        return Err(TpmRc(rc::NV_SPACE));
    }
    state.persistent.insert(persistent_handle, object);
    respond(|_| Ok(()))
}

/// True when a handle names a saved transient object.
pub fn is_saved_object_handle(handle: u32) -> bool {
    matches!(
        handle,
        saved::TRANSIENT_OBJECT | saved::SEQUENCE_OBJECT | saved::TRANSIENT_STCLEAR
    )
}

/// The hash the context protection uses.
pub fn context_hash() -> u16 {
    let _ = alg::SHA256;
    config::CONTEXT_INTEGRITY_HASH_ALG
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::se;
    use crate::tpm::structures::schemes::SymDef;

    #[test]
    fn an_object_context_an_older_build_saved_is_refused() {
        use crate::tpm::structures::attributes::ObjectAttributes;
        use crate::tpm::structures::base::Tpm2bDigest;
        use crate::tpm::structures::keys::{PublicId, PublicParms, TpmtPublic};
        use crate::tpm::structures::schemes::Scheme;

        // Part 3 clause 18.1 forbids a restricted signing key whose scheme is
        // TPM_ALG_NULL. The integrity check on a context says the blob is this
        // TPM's, not that a build with the same seeds was right to save it.
        let public = TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::RESTRICTED,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::null(),
                curve_id: crate::tpm::constants::curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(Default::default()),
        };
        let object = Object::new(public, None, rh::OWNER, &rh::OWNER.to_be_bytes(), true).unwrap();
        let body = marshal_object(&object).unwrap();
        assert_eq!(
            unmarshal_object(&body, false).unwrap_err(),
            crate::tpm::error::TpmRc(crate::tpm::constants::rc::SCHEME)
        );
    }

    #[test]
    fn a_session_context_round_trips() {
        let session = Session::new(
            hc::HMAC_SESSION_FIRST,
            se::HMAC,
            alg::SHA256,
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            rh::NULL,
            Vec::new(),
            SymDef::new(alg::AES, 128, alg::CFB),
        )
        .unwrap();
        let body = marshal_session(&session).unwrap();
        let back = unmarshal_session(&body).unwrap();
        assert_eq!(back.handle, session.handle);
        assert_eq!(back.auth_hash, session.auth_hash);
        assert_eq!(back.nonce_tpm, session.nonce_tpm);
        assert_eq!(back.session_key, session.session_key);
        assert_eq!(back.symmetric, session.symmetric);
    }

    #[test]
    fn a_sequence_context_round_trips() {
        for kind in [
            SequenceKind::Hash {
                hash_alg: alg::SHA256,
            },
            SequenceKind::Hmac {
                hash_alg: alg::SHA384,
                key: vec![9u8; 48],
            },
            SequenceKind::Event,
        ] {
            let s = Sequence {
                kind: kind.clone(),
                auth: b"auth".to_vec(),
                buffer: b"buffered data".to_vec(),
            };
            let back = unmarshal_sequence(&marshal_sequence(&s).unwrap()).unwrap();
            assert_eq!(back.kind, kind);
            assert_eq!(back.auth, b"auth");
            assert_eq!(back.buffer, b"buffered data");
        }
    }

    #[test]
    fn a_context_is_protected_and_tamper_evident() {
        let state = TpmState::manufacture().unwrap();
        let body = b"the context body".to_vec();
        let blob = seal_context(&state, rh::OWNER, 1, saved::TRANSIENT_OBJECT, &body).unwrap();

        let context = Context {
            sequence: 1,
            saved_handle: saved::TRANSIENT_OBJECT,
            hierarchy: rh::OWNER,
            context_blob: blob.clone(),
        };
        assert_eq!(open_context(&state, &context).unwrap(), body);

        // A different sequence number, handle or hierarchy fails.
        let mut bad = Context {
            sequence: 2,
            ..context.clone()
        };
        assert!(open_context(&state, &bad).is_err());
        bad = Context {
            saved_handle: saved::SEQUENCE_OBJECT,
            ..context.clone()
        };
        assert!(open_context(&state, &bad).is_err());
        bad = Context {
            hierarchy: rh::PLATFORM,
            ..context.clone()
        };
        assert!(open_context(&state, &bad).is_err());
    }

    #[test]
    fn a_context_does_not_survive_a_seed_change() {
        let mut state = TpmState::manufacture().unwrap();
        let body = b"body".to_vec();
        let blob = seal_context(&state, rh::OWNER, 1, saved::TRANSIENT_OBJECT, &body).unwrap();
        let context = Context {
            sequence: 1,
            saved_handle: saved::TRANSIENT_OBJECT,
            hierarchy: rh::OWNER,
            context_blob: blob,
        };
        assert!(open_context(&state, &context).is_ok());
        state.on_clear().unwrap();
        assert_eq!(
            open_context(&state, &context).unwrap_err().0 & 0x03F,
            rc::INTEGRITY & 0x03F
        );
    }

    #[test]
    fn saved_handle_values_are_recognised() {
        assert!(is_saved_object_handle(saved::TRANSIENT_OBJECT));
        assert!(is_saved_object_handle(saved::SEQUENCE_OBJECT));
        assert!(is_saved_object_handle(saved::TRANSIENT_STCLEAR));
        assert!(!is_saved_object_handle(hc::HMAC_SESSION_FIRST));
        assert_eq!(context_hash(), config::CONTEXT_INTEGRITY_HASH_ALG);
    }
}

#[cfg(test)]
mod policy_context_tests {
    use super::*;
    use crate::tpm::constants::se;
    use crate::tpm::structures::schemes::SymDef;

    #[test]
    fn a_saved_session_keeps_every_policy_assertion() {
        let mut session = Session::new(
            hc::POLICY_SESSION_FIRST,
            se::POLICY,
            alg::SHA256,
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            rh::NULL,
            Vec::new(),
            SymDef::null(),
        )
        .unwrap();
        session.start_time = 1234;
        session.time_epoch = 7;
        session.policy.digest = vec![9u8; 32];
        session.policy.command_code = Some(crate::tpm::constants::cc::Unseal);
        session.policy.cp_hash = Some(vec![4u8; 32]);
        session.policy.name_hash = Some(vec![5u8; 32]);
        session.policy.locality = Some(0b0000_0100);
        session.policy.pcr_update_counter = Some(11);
        session.policy.auth_value_needed = true;
        session.policy.password_needed = true;
        session.policy.nv_written = Some(true);
        session.policy.template_hash = Some(vec![6u8; 32]);
        session.policy.parameters_hash = Some(vec![7u8; 32]);
        session.policy.physical_presence_required = true;
        session.policy.expiration = Some(5000);
        session.policy.timeout_nonce = vec![8u8; 16];

        // Part 1 clause 27.2.1 rebuilds the whole session from the context, so
        // a reloaded one carries every restriction it had.
        let body = marshal_session(&session).unwrap();
        let back = unmarshal_session(&body).unwrap();
        assert_eq!(back.policy, session.policy);
        assert_eq!(back.start_time, session.start_time);
        assert_eq!(back.time_epoch, session.time_epoch);
    }
}
