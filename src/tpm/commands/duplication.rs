//! Duplication, Part 3 clause 13, and the remaining management commands.

use crate::tpm::constants::{rc, rh};
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
    sensitive: &[u8],
) -> TpmResult<Vec<u8>> {
    let mut body = crate::tpm::marshal::Writer::new();
    body.sized16(sensitive);
    let body = body.finish()?;

    let mut inner = Vec::with_capacity(2 + hash::digest_size(name_alg)? + body.len());
    let digest = hash::digest_parts(name_alg, &[&body, name])?;
    inner.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    inner.extend_from_slice(&digest);
    inner.extend_from_slice(&body);

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
    let mut r = crate::tpm::marshal::Reader::new(&body);
    let size = r.u16().map_err(|_| TpmRc(rc::SENSITIVE))? as usize;
    Ok(r.take(size).map_err(|_| TpmRc(rc::SENSITIVE))?.to_vec())
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

    let mut body = sensitive.to_bytes();
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
        let wrapped = protect::wrap_private(
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
    let mut body = if in_symmetric_seed.is_empty() {
        duplicate_blob.as_slice().to_vec()
    } else {
        let seed = seed_from_parent(&parent, in_symmetric_seed.as_slice(), b"DUPLICATE\0")
            .map_err(|e| e.with_parameter(4))?;
        protect::unwrap_private(
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
        body = inner_unwrap(
            public.name_alg,
            &symmetric_alg,
            encryption_key.as_slice(),
            &object_name,
            &body,
        )?;
    }

    let sensitive = TpmtSensitive::from_bytes(&body).map_err(|_| TpmRc(rc::SENSITIVE))?;
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
        protect::unwrap_private(
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
        let wrapped = protect::wrap_private(
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
    let ac = request.handle(2)?;
    let _ = ac;
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
