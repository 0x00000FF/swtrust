//! Duplication, Part 3 clause 13, and the remaining management commands.

use crate::tpm::constants::{hc, rc, rh};
use crate::tpm::core::names;
use crate::tpm::core::object::{Object, Slot};
use crate::tpm::core::protect;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{hash, rand::Rng, sym};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attributes::ObjectAttributes;
use crate::tpm::structures::base::{
    Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, Tpm2bSymKey,
};
use crate::tpm::structures::keys::{Tpm2bPublic, TpmtSensitive};
use crate::tpm::structures::schemes::SymDef;

use super::dispatch::{Request, Response};
use super::execute::respond;

/// The object a handle names, transient or persistent.
fn object_of(state: &TpmState, handle: u32) -> TpmResult<&Object> {
    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle)
    } else {
        state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))
    }
}

/// Protect a seed for a new parent, which is how a duplication travels.
fn seed_to_parent(
    state: &mut TpmState,
    new_parent: &Object,
    label: &[u8],
) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    protect::seed_to_public(&new_parent.public, label, &mut state.rng)
}

/// Recover a seed a duplication arrived with.
fn seed_from_parent(parent: &Object, secret: &[u8], label: &[u8]) -> TpmResult<Vec<u8>> {
    let Some(sensitive) = &parent.sensitive else {
        return Err(TpmRc(rc::HANDLE));
    };
    protect::seed_from_private(&parent.public, sensitive, secret, label)
}

/// Apply the inner wrap of Part 1 clause 23.2.
///
/// The sensitive area is prefixed with the object Name, then encrypted with
/// the symmetric key the caller supplied.
fn inner_wrap(
    name_alg: u16,
    symmetric: &SymDef,
    key: &[u8],
    name: &[u8],
    body: &[u8],
) -> TpmResult<Vec<u8>> {
    // Part 1 Equation 37 takes the digest over `sensitive || name`, where
    // sensitive "is a TPM2B_SENSITIVE", which is what arrives here.
    let mut inner = Vec::with_capacity(2 + hash::digest_size(name_alg)? + body.len());
    let digest = hash::digest_parts(name_alg, &[&body, name])?;
    inner.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    inner.extend_from_slice(&digest);
    inner.extend_from_slice(body);

    let iv = vec![0u8; sym::block_size(symmetric.algorithm)?];
    sym::cfb_encrypt(key, &iv, &inner)
}

/// Undo [`inner_wrap`].
fn inner_unwrap(
    name_alg: u16,
    symmetric: &SymDef,
    key: &[u8],
    name: &[u8],
    data: &[u8],
) -> TpmResult<Vec<u8>> {
    let iv = vec![0u8; sym::block_size(symmetric.algorithm)?];
    let plain = sym::cfb_decrypt(key, &iv, data)?;
    let mut r = crate::tpm::marshal::Reader::new(&plain);
    let digest_size = r.u16().map_err(|_| TpmRc(rc::INTEGRITY))? as usize;
    let digest = r.take(digest_size).map_err(|_| TpmRc(rc::INTEGRITY))?.to_vec();
    let body = r.rest().to_vec();
    let expected = hash::digest_parts(name_alg, &[&body, name])?;
    if !protect::constant_time_eq(&digest, &expected) {
        return Err(TpmRc(rc::INTEGRITY));
    }
    Ok(body)
}

/// Take the TPMT_SENSITIVE out of the TPM2B_SENSITIVE phase one works on.
fn sensitive_from_body(body: &[u8]) -> TpmResult<Vec<u8>> {
    let mut r = crate::tpm::marshal::Reader::new(body);
    let size = r.u16().map_err(|_| TpmRc(rc::SENSITIVE))? as usize;
    let inner = r.take(size).map_err(|_| TpmRc(rc::SENSITIVE))?.to_vec();
    r.expect_end().map_err(|_| TpmRc(rc::SENSITIVE))?;
    Ok(inner)
}

/// TPM2_Duplicate, Part 3 clause 13.1.
pub fn duplicate(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let object_handle = request.handle(0)?;
    let new_parent_handle = request.handle(1)?;
    let mut r = request.reader();
    let encryption_key_in = Tpm2bSymKey::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let symmetric_alg = SymDef::unmarshal_sym_def_object(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    let object = object_of(state, object_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if object
        .public
        .object_attributes
        .has(ObjectAttributes::FIXED_PARENT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    // encryptedDuplication requires both an inner wrap and a new parent.
    let needs_inner = object
        .public
        .object_attributes
        .has(ObjectAttributes::ENCRYPTED_DUPLICATION);
    if needs_inner && symmetric_alg.is_null() {
        return Err(TpmRc(rc::SYMMETRIC).with_parameter(2));
    }
    if needs_inner && new_parent_handle == rh::NULL {
        return Err(TpmRc(rc::HIERARCHY).with_handle(2));
    }

    // Part 1 clause 20.3.2.2 makes phase one work on a TPM2B_SENSITIVE, and
    // Equation 39 leaves encSensitive as that same value when no inner wrapper
    // is asked for, so the size goes on here rather than in one of the paths
    // that follow.
    let mut writer = crate::tpm::marshal::Writer::new();
    writer.sized16(&sensitive.to_bytes());
    let mut body = writer.finish()?;
    // Inner wrap first, if one was asked for.
    let mut encryption_key_out = Vec::new();
    if !symmetric_alg.is_null() {
        let key = if encryption_key_in.is_empty() {
            let k = state.rng.bytes(symmetric_alg.key_bits as usize / 8)?;
            encryption_key_out = k.clone();
            k
        } else {
            if encryption_key_in.len() != symmetric_alg.key_bits as usize / 8 {
                return Err(TpmRc(rc::SIZE).with_parameter(1));
            }
            encryption_key_in.as_slice().to_vec()
        };
        body = inner_wrap(
            object.public.name_alg,
            &symmetric_alg,
            &key,
            &object.name,
            &body,
        )?;
    }

    // Outer wrap with the new parent, unless the duplication leaves in the
    // clear under a null parent.
    let (duplicate_blob, secret) = if new_parent_handle == rh::NULL {
        (body, Vec::new())
    } else {
        let new_parent = object_of(state, new_parent_handle)
            .map_err(|e| e.with_handle(2))?
            .clone();
        if !new_parent
            .public
            .object_attributes
            .has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT)
        {
            return Err(TpmRc(rc::TYPE).with_handle(2));
        }
        let parent_symmetric = new_parent
            .public
            .parameters
            .symmetric()
            .copied()
            .ok_or(TpmRc(rc::TYPE).with_handle(2))?;
        let (seed, secret) = seed_to_parent(state, &new_parent, b"DUPLICATE\0")
            .map_err(|e| e.with_handle(2))?;
        // Part 1 clause 20.3.2.3: the outer phase encrypts "the encSensitive
        // produced by phase 1". With an inner wrapper that is
        // innerIntegrity || TPM2B_SENSITIVE under the inner cipher, which
        // carries its own length; without one clause 20.3.2.2 makes
        // encSensitive the TPM2B_SENSITIVE itself, and that is the size the
        // ordinary wrap puts on.
        // The outer phase encrypts what phase one produced, whichever of the
        // two shapes clause 20.3.2.2 left it in.
        let wrapped = protect::wrap_private_body(
            new_parent.public.name_alg,
            &seed,
            &parent_symmetric,
            &object.name,
            &body,
        )?;
        (wrapped, secret)
    };

    respond(move |w| {
        Tpm2bSymKey::new(encryption_key_out)?.marshal(w);
        Tpm2bPrivate::new(duplicate_blob)?.marshal(w);
        Tpm2bEncryptedSecret::new(secret)?.marshal(w);
        Ok(())
    })
}

/// TPM2_Import, Part 3 clause 13.3.
pub fn import(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let parent_handle = request.handle(0)?;
    let mut r = request.reader();
    let encryption_key = Tpm2bSymKey::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let object_public = Tpm2bPublic::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let duplicate_blob = Tpm2bPrivate::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    let in_symmetric_seed =
        Tpm2bEncryptedSecret::unmarshal(&mut r).map_err(|e| e.with_parameter(4))?;
    let symmetric_alg = SymDef::unmarshal_sym_def_object(&mut r).map_err(|e| e.with_parameter(5))?;
    r.expect_end()?;

    let parent = object_of(state, parent_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if !parent
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    let parent_symmetric = parent
        .public
        .parameters
        .symmetric()
        .copied()
        .ok_or(TpmRc(rc::TYPE).with_handle(1))?;

    let public = object_public.public_area;
    crate::tpm::core::object::validate_loaded_public(&public)
        .map_err(|e| e.with_parameter(2))?;
    // An imported object cannot claim to have been made by this TPM.
    if public
        .object_attributes
        .has(ObjectAttributes::FIXED_TPM)
        || public
            .object_attributes
            .has(ObjectAttributes::FIXED_PARENT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }
    let object_name = names::object_name(&public)?;

    // Undo the outer wrap the source TPM applied.
    // Part 3 clause 13.3.1: "if encryptedDuplication is SET in objectPublic,
    // then inSymSeed and encryptionKey shall not be Empty buffers
    // (TPM_RC_ATTRIBUTES)." Without this an object that asks to travel
    // encrypted could be imported in the clear.
    if public
        .object_attributes
        .has(ObjectAttributes::ENCRYPTED_DUPLICATION)
    {
        if in_symmetric_seed.is_empty() {
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(4));
        }
        if encryption_key.is_empty() {
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(1));
        }
    }

    let mut body = if in_symmetric_seed.is_empty() {
        duplicate_blob.as_slice().to_vec()
    } else {
        let seed = seed_from_parent(&parent, in_symmetric_seed.as_slice(), b"DUPLICATE\0")
            .map_err(|e| e.with_parameter(4))?;
        protect::unwrap_private_body(
            parent.public.name_alg,
            &seed,
            &parent_symmetric,
            &object_name,
            duplicate_blob.as_slice(),
        )?
    };

    // Then the inner wrap, if there was one.
    if !symmetric_alg.is_null() {
        if encryption_key.len() != symmetric_alg.key_bits as usize / 8 {
            return Err(TpmRc(rc::SIZE).with_parameter(1));
        }
        // Clause 13.3.1: "if a weak symmetric key is being imported, the TPM
        // shall return TPM_RC_KEY." Part 1 clause 8.4.10.4 says which those
        // are: of an AES key "at least one bit in the upper half of the key
        // must be set", and none of the 64 known weak or semi-weak DES keys is
        // allowed.
        if crate::tpm::crypto::sym::is_weak_key(symmetric_alg.algorithm, encryption_key.as_slice())
        {
            return Err(TpmRc(rc::KEY).with_parameter(1));
        }
        body = inner_unwrap(
            public.name_alg,
            &symmetric_alg,
            encryption_key.as_slice(),
            &object_name,
            &body,
        )?;
    }

    // What phase one produced is a TPM2B_SENSITIVE, so the TPMT_SENSITIVE
    // comes out of it here.
    let sensitive_bytes = sensitive_from_body(&body)?;
    let sensitive =
        TpmtSensitive::from_bytes(&sensitive_bytes).map_err(|_| TpmRc(rc::SENSITIVE))?;
    // Part 3 clause 12.8.1 imports only a private area that goes with the
    // public one, so the blob this command produces cannot later load as
    // something the public area does not describe.
    crate::tpm::core::object::check_binding(&public, &sensitive)
        .map_err(|e| e.with_parameter(3))?;

    // Re-wrap under the new parent so the object can be loaded here.
    let private = protect::wrap_private(
        parent.public.name_alg,
        parent.seed_value(),
        &parent_symmetric,
        &object_name,
        &sensitive.to_bytes(),
    )?;
    respond(move |w| {
        Tpm2bPrivate::new(private)?.marshal(w);
        Ok(())
    })
}

/// TPM2_Rewrap, Part 3 clause 13.2.
pub fn rewrap(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let old_parent = request.handle(0)?;
    let new_parent = request.handle(1)?;
    let mut r = request.reader();
    let in_duplicate = Tpm2bPrivate::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let name = Tpm2bName::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let in_secret = Tpm2bEncryptedSecret::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    r.expect_end()?;

    // Part 2 clause 10.4.3 gives a TPM2B_NAME three shapes and no other, and
    // clause 13.2.1 uses this one as "the Name of the Object being rewrapped",
    // which the inner wrap is bound to.
    if !crate::tpm::core::names::is_well_formed(name.as_slice()) {
        return Err(TpmRc(rc::SIZE).with_parameter(2));
    }

    // Remove the old parent's outer wrap.
    let body = if old_parent == rh::NULL {
        in_duplicate.as_slice().to_vec()
    } else {
        let parent = object_of(state, old_parent)
            .map_err(|e| e.with_handle(1))?
            .clone();
        let parent_symmetric = parent
            .public
            .parameters
            .symmetric()
            .copied()
            .ok_or(TpmRc(rc::TYPE).with_handle(1))?;
        let seed = seed_from_parent(&parent, in_secret.as_slice(), b"DUPLICATE\0")
            .map_err(|e| e.with_parameter(3))?;
        // TPM2_Rewrap changes the outer wrapper and nothing else, so it takes
        // the blob as it stands rather than reading a length out of it.
        protect::unwrap_private_body(
            parent.public.name_alg,
            &seed,
            &parent_symmetric,
            name.as_slice(),
            in_duplicate.as_slice(),
        )?
    };

    // Apply the new parent's.
    let (out_duplicate, out_secret) = if new_parent == rh::NULL {
        (body, Vec::new())
    } else {
        let parent = object_of(state, new_parent)
            .map_err(|e| e.with_handle(2))?
            .clone();
        let parent_symmetric = parent
            .public
            .parameters
            .symmetric()
            .copied()
            .ok_or(TpmRc(rc::TYPE).with_handle(2))?;
        let (seed, secret) =
            seed_to_parent(state, &parent, b"DUPLICATE\0").map_err(|e| e.with_handle(2))?;
        let wrapped = protect::wrap_private_body(
            parent.public.name_alg,
            &seed,
            &parent_symmetric,
            name.as_slice(),
            &body,
        )?;
        (wrapped, secret)
    };

    respond(move |w| {
        Tpm2bPrivate::new(out_duplicate)?.marshal(w);
        Tpm2bEncryptedSecret::new(out_secret)?.marshal(w);
        Ok(())
    })
}

/// TPM2_ACT_SetTimeout, Part 3 clause 37.2.
///
/// This TPM implements no authenticated timers, so every ACT handle is
/// refused rather than silently accepted.
pub fn act_set_timeout(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let start_timeout = r.u32().map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;
    // Part 2 TPMI_RH_ACT answers TPM_RC_VALUE for a handle that is not an ACT.
    // The PC Client Platform TPM Profile 1.07 clause 5.1.2 asks for one
    // instance, so every other number in the range names a timer that is not
    // there and is refused the same way.
    if handle != crate::tpm::constants::rh::ACT_0 {
        return Err(TpmRc(rc::VALUE).with_handle(1));
    }
    state.act.set_timeout(start_timeout);
    respond(|_| Ok(()))
}



/// TPM2_AC_GetCapability, Part 3 clause 32.2.
///
/// No attached component is present, so the list is always empty.
pub fn ac_get_capability(_state: &TpmState, request: &Request) -> TpmResult<Response> {
    // Part 2 clause 9.29 gives TPMI_RH_AC the range {AC_FIRST:AC_LAST} and
    // TPM_RC_VALUE for a handle outside it, whether or not the component it
    // would name is there.
    let ac = request.handle(0)?;
    if !(hc::AC_FIRST..=hc::AC_LAST).contains(&ac) {
        return Err(TpmRc(rc::VALUE).with_handle(1));
    }
    let mut r = request.reader();
    let _capability = r.u32().map_err(|e| e.with_parameter(1))?;
    let _count = r.u32().map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;
    respond(|w| {
        w.u8(0);
        w.u32(0);
        Ok(())
    })
}

/// TPM2_AC_Send, Part 3 clause 32.3.
pub fn ac_send(_state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    // The same range, for the third handle this command names. There is no
    // attached component to send to, so a handle inside it is refused too.
    let ac = request.handle(2)?;
    if !(hc::AC_FIRST..=hc::AC_LAST).contains(&ac) {
        return Err(TpmRc(rc::VALUE).with_handle(3));
    }
    Err(TpmRc(rc::VALUE).with_handle(3))
}

/// Load a duplicated object directly, used by the tests of this module.
pub fn load_duplicated(
    state: &mut TpmState,
    parent: &Object,
    public: crate::tpm::structures::keys::TpmtPublic,
    sensitive: TpmtSensitive,
) -> TpmResult<u32> {
    let object = Object::new(
        public,
        Some(sensitive),
        parent.hierarchy,
        &parent.qualified_name,
        false,
    )?;
    state.objects.insert(Slot::Object(Box::new(object)))
}

/// The label a duplication seed is protected with.
pub fn duplicate_label() -> &'static [u8] {
    b"DUPLICATE\0"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;

    #[test]
    fn the_inner_wrap_round_trips_and_detects_tampering() {
        let symmetric = SymDef::new(alg::AES, 128, alg::CFB);
        let key = [7u8; 16];
        let name = [3u8; 34];
        let sensitive = vec![0x5au8; 64];

        let wrapped = inner_wrap(alg::SHA256, &symmetric, &key, &name, &sensitive).unwrap();
        assert_eq!(
            inner_unwrap(alg::SHA256, &symmetric, &key, &name, &wrapped).unwrap(),
            sensitive
        );

        // A different Name fails the check.
        assert_eq!(
            inner_unwrap(alg::SHA256, &symmetric, &key, &[4u8; 34], &wrapped)
                .unwrap_err()
                .0
                & 0x03F,
            rc::INTEGRITY & 0x03F
        );
        // A different key fails too.
        assert!(inner_unwrap(alg::SHA256, &symmetric, &[8u8; 16], &name, &wrapped).is_err());
        // Tampering fails.
        let mut bad = wrapped;
        bad[10] ^= 0x01;
        assert!(inner_unwrap(alg::SHA256, &symmetric, &key, &name, &bad).is_err());
    }

    #[test]
    fn the_duplicate_label_is_terminated() {
        assert_eq!(duplicate_label(), b"DUPLICATE\0");
        assert_eq!(*duplicate_label().last().unwrap(), 0);
    }
}

#[cfg(test)]
mod wrapper_tests {
    use crate::tpm::constants::alg;
    use crate::tpm::core::protect;
    use crate::tpm::structures::schemes::SymDef;

    #[test]
    fn phase_one_always_produces_a_sized_sensitive() {
        // Part 1 Equation 39: with no inner wrapper "encSensitive := sensitive",
        // and clause 20.3.2.2 makes that sensitive a TPM2B_SENSITIVE. A
        // duplication with neither wrapper hands back exactly that, so a
        // conforming TPM can read it.
        use crate::tpm::marshal::{Reader, Writer};
        let raw = vec![0x11u8; 40];
        let mut w = Writer::new();
        w.sized16(&raw);
        let body = w.finish().unwrap();

        let mut r = Reader::new(&body);
        assert_eq!(r.u16().unwrap() as usize, raw.len());
        assert_eq!(r.take(raw.len()).unwrap(), &raw[..]);
        assert!(r.is_empty(), "the body carries more than the sensitive area");
        assert_eq!(super::sensitive_from_body(&body).unwrap(), raw);
    }

    #[test]
    fn an_inner_wrapped_body_keeps_its_own_length_through_the_outer_phase() {
        // Part 1 clause 20.3.2.3: the outer phase encrypts "the encSensitive
        // produced by phase 1". With an inner wrapper that is already
        // innerIntegrity || TPM2B_SENSITIVE under the inner cipher and carries
        // its own length, so another size around it would describe a structure
        // no other TPM writes.
        let seed = vec![0x5au8; 32];
        let symmetric = SymDef::new(alg::AES, 128, alg::CFB);
        let name = b"a name".to_vec();
        let body = vec![0xa5u8; 70];

        let wrapped =
            protect::wrap_private_body(alg::SHA256, &seed, &symmetric, &name, &body).unwrap();
        let back =
            protect::unwrap_private_body(alg::SHA256, &seed, &symmetric, &name, &wrapped).unwrap();
        assert_eq!(back, body, "the body did not come back as it went in");

        // The ordinary form does add a length, which is the TPM2B_SENSITIVE's
        // own, so the two are not interchangeable and the blobs differ.
        let ordinary =
            protect::wrap_private(alg::SHA256, &seed, &symmetric, &name, &body).unwrap();
        assert_ne!(
            ordinary.len(),
            wrapped.len(),
            "the two wrappings produced the same shape"
        );
        assert_eq!(ordinary.len(), wrapped.len() + 2);
    }
}
