//! Object management, Part 3 clause 12, and Part 1 clauses 25 to 27.

use crate::tpm::constants::{alg, rc, rh, st};
use crate::tpm::core::names;
use crate::tpm::core::object::{self, Object, Slot};
use crate::tpm::core::protect;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::rand::{Rng, SeededRng};
use crate::tpm::crypto::{ecc, hash, rsa};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal, Writer};
use crate::tpm::structures::attest::{CreationData, Tpm2bCreationData};
use crate::tpm::structures::attributes::{LocalityAttributes, ObjectAttributes};
use crate::tpm::structures::base::{
    Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bName, Tpm2bPrivate, Tpm2bPrivateKeyRsa,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
};
use crate::tpm::structures::keys::{
    PublicId, PublicParms, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveCreate, TpmtPublic,
    TpmtSensitive, SensitiveComposite,
};
use crate::tpm::structures::lists::TpmlPcrSelection;
use crate::tpm::structures::schemes::EccPoint;
use crate::tpm::structures::signature::Ticket;

use super::dispatch::{Request, Response};
use super::execute::{respond, respond_with_handle};

/// The label the deterministic generator uses for a Primary Object.
const LABEL_PRIMARY: &str = "PRIMARY";

/// The context a Primary Object is derived from.
///
/// Part 1 clause 27.2 requires the same seed, template and sensitive input to
/// rebuild the same key, so the derivation covers all three.
///
/// The whole template goes in, unique included. Part 3 clause 24.1.1 says "all
/// of the bits of the template are used in the creation of the Primary Key",
/// and that two calls with "the same inPublic parameter, inSensitive.data, and
/// Primary Seed" give the same object. The field the caller sent is what those
/// sentences mean by the template, not the modulus or point the TPM is about to
/// put in its place, so leaving it out would let two templates the caller wrote
/// differently produce one key.
fn primary_context(
    template: &TpmtPublic,
    sensitive: &Tpm2bSensitiveCreate,
) -> TpmResult<Vec<u8>> {
    let mut w = Writer::new();
    template.marshal(&mut w);
    sensitive.marshal(&mut w);
    let body = w.finish()?;
    hash::digest(
        if template.name_alg == alg::NULL {
            alg::SHA256
        } else {
            template.name_alg
        },
        &body,
    )
}

/// Fill in the sensitive and unique areas of a new object.
///
/// `rng` supplies every octet, so a deterministic generator produces a
/// repeatable Primary Object and the system generator produces a fresh
/// ordinary object.
fn create_sensitive(
    rng: &mut dyn Rng,
    template: &TpmtPublic,
    supplied: &Tpm2bSensitiveCreate,
) -> TpmResult<(TpmtSensitive, PublicId)> {
    let attrs = template.object_attributes;
    let name_alg = if template.name_alg == alg::NULL {
        alg::SHA256
    } else {
        template.name_alg
    };
    let digest_size = hash::digest_size(name_alg)?;

    // A parent needs a seed to protect its children; anything else gets an
    // obfuscation value of the same size, except an object whose sensitive
    // data came from outside.
    let needs_seed = attrs.has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT);
    let seed_value = if needs_seed || matches!(template.object_type, alg::KEYEDHASH | alg::SYMCIPHER)
    {
        rng.bytes(digest_size)?
    } else {
        Vec::new()
    };

    let auth_value = supplied.sensitive.user_auth.as_slice().to_vec();
    if auth_value.len() > digest_size {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }

    let (composite, unique) = match template.object_type {
        alg::RSA => {
            if !supplied.sensitive.data.is_empty() {
                return Err(TpmRc(rc::VALUE).with_parameter(1));
            }
            let PublicParms::Rsa {
                key_bits, exponent, ..
            } = template.parameters
            else {
                return Err(TpmRc(rc::TYPE));
            };
            let key = rsa::generate(rng, key_bits, exponent)?;
            // FIPS 140-3 Table 40 asks for a pair-wise consistency test on
            // every generated key pair, before the key is used for anything.
            crate::tpm::fips::pairwise_rsa(
                &key,
                attrs.has(ObjectAttributes::SIGN_ENCRYPT),
                attrs.has(ObjectAttributes::DECRYPT),
            )?;
            (
                SensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::new(key.prime_bytes()?)?),
                PublicId::Rsa(Tpm2bPublicKeyRsa::new(key.modulus_bytes()?)?),
            )
        }
        alg::ECC => {
            if !supplied.sensitive.data.is_empty() {
                return Err(TpmRc(rc::VALUE).with_parameter(1));
            }
            let PublicParms::Ecc { curve_id, .. } = template.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let key = ecc::generate(curve_id, rng)?;
            let size = key.curve.coordinate_size();
            // The same pair-wise consistency test for an ECC key. The public
            // point is recomputed from the private scalar whatever the key is
            // for, and a signing key also signs and verifies.
            crate::tpm::fips::pairwise_ecc(
                curve_id,
                &key.private.to_bytes_padded(size)?,
                &key.public_x,
                &key.public_y,
                attrs.has(ObjectAttributes::SIGN_ENCRYPT),
            )?;
            (
                SensitiveComposite::Ecc(Tpm2bEccParameter::new(
                    key.private.to_bytes_padded(size)?,
                )?),
                PublicId::Ecc(EccPoint {
                    x: Tpm2bEccParameter::new(key.public_x)?,
                    y: Tpm2bEccParameter::new(key.public_y)?,
                }),
            )
        }
        alg::KEYEDHASH => {
            let data = if attrs.has(ObjectAttributes::SENSITIVE_DATA_ORIGIN) {
                if !supplied.sensitive.data.is_empty() {
                    return Err(TpmRc(rc::ATTRIBUTES).with_parameter(1));
                }
                rng.bytes(digest_size)?
            } else {
                if supplied.sensitive.data.is_empty() {
                    return Err(TpmRc(rc::ATTRIBUTES).with_parameter(1));
                }
                supplied.sensitive.data.as_slice().to_vec()
            };
            let unique = hash::digest_parts(name_alg, &[&seed_value, &data])?;
            (
                SensitiveComposite::Bits(Tpm2bSensitiveData::new(data)?),
                PublicId::KeyedHash(Tpm2bDigest::new(unique)?),
            )
        }
        alg::SYMCIPHER => {
            let PublicParms::SymCipher { sym } = &template.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let key = if attrs.has(ObjectAttributes::SENSITIVE_DATA_ORIGIN) {
                if !supplied.sensitive.data.is_empty() {
                    return Err(TpmRc(rc::ATTRIBUTES).with_parameter(1));
                }
                rng.bytes(sym.key_bits as usize / 8)?
            } else {
                supplied.sensitive.data.as_slice().to_vec()
            };
            if key.len() != sym.key_bits as usize / 8 {
                return Err(TpmRc(rc::KEY_SIZE).with_parameter(1));
            }
            let unique = hash::digest_parts(name_alg, &[&seed_value, &key])?;
            (
                SensitiveComposite::Sym(Tpm2bSymKey::new(key)?),
                PublicId::Sym(Tpm2bDigest::new(unique)?),
            )
        }
        _ => return Err(TpmRc(rc::TYPE)),
    };

    Ok((
        TpmtSensitive {
            sensitive_type: template.object_type,
            auth_value: Tpm2bDigest::new(auth_value)?,
            seed_value: Tpm2bDigest::new(seed_value)?,
            sensitive: composite,
        },
        unique,
    ))
}

/// The creation data and its digest for a newly created object.
fn creation_data(
    state: &TpmState,
    parent: u32,
    parent_name: &[u8],
    parent_qualified_name: &[u8],
    parent_name_alg: u16,
    name_alg: u16,
    outside_info: &Tpm2bData,
    pcr_select: &TpmlPcrSelection,
    locality: u8,
) -> TpmResult<(CreationData, Vec<u8>)> {
    let filtered = state.pcr.filter_selection(pcr_select);
    let pcr_digest = if filtered.items.iter().all(|s| s.select.is_empty_selection()) {
        Vec::new()
    } else {
        state.pcr.selection_digest(name_alg, &filtered)?
    };
    let _ = parent;
    let data = CreationData {
        pcr_select: filtered,
        pcr_digest: Tpm2bDigest::new(pcr_digest)?,
        locality: LocalityAttributes(if locality < 5 { 1 << locality } else { locality }),
        parent_name_alg,
        parent_name: Tpm2bName::from_slice(parent_name)?,
        parent_qualified_name: Tpm2bName::from_slice(parent_qualified_name)?,
        outside_info: outside_info.clone(),
    };
    let digest = hash::digest(name_alg, &data.to_bytes())?;
    Ok((data, digest))
}

/// TPM2_CreatePrimary, Part 3 clause 24.1.
pub fn create_primary(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let primary_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_sensitive = Tpm2bSensitiveCreate::unmarshal(&mut r)?;
    let in_public = Tpm2bPublic::unmarshal(&mut r)?;
    let outside_info = Tpm2bData::unmarshal(&mut r)?;
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut r)?;
    r.expect_end()?;

    if !crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(primary_handle) {
        return Err(TpmRc(rc::VALUE).with_handle(1));
    }
    if !state.hierarchies.is_enabled(primary_handle) {
        return Err(TpmRc(rc::HIERARCHY).with_handle(1));
    }
    let template = in_public.public_area;
    object::validate_public(&template).map_err(|e| e.with_parameter(2))?;

    let seed = state.hierarchies.get(primary_handle)?.seed.clone();
    let context = primary_context(&template, &in_sensitive)?;
    let name_alg = if template.name_alg == alg::NULL {
        alg::SHA256
    } else {
        template.name_alg
    };
    let mut rng = SeededRng::new(name_alg, &seed, LABEL_PRIMARY, &context);
    let (sensitive, unique) = create_sensitive(&mut rng, &template, &in_sensitive)?;

    let mut public = template;
    public.unique = unique;

    let parent_qn = names::handle_name(primary_handle);
    let object = Object::new(
        public.clone(),
        Some(sensitive),
        primary_handle,
        &parent_qn,
        true,
    )?;
    let object_name = object.name.clone();

    let (creation, creation_digest) = creation_data(
        state,
        primary_handle,
        &parent_qn,
        &parent_qn,
        alg::NULL,
        name_alg,
        &outside_info,
        &creation_pcr,
        request.locality,
    )?;
    let ticket = creation_ticket(state, primary_handle, &object_name, &creation_digest)?;

    let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
    respond_with_handle(handle, move |w| {
        Tpm2bPublic {
            public_area: public,
        }
        .marshal(w);
        Tpm2bCreationData {
            creation_data: creation,
        }
        .marshal(w);
        Tpm2bDigest::new(creation_digest)?.marshal(w);
        ticket.marshal(w);
        Tpm2bName::new(object_name)?.marshal(w);
        Ok(())
    })
}

/// The creation ticket of Part 1 clause 27.6.
fn creation_ticket(
    state: &TpmState,
    hierarchy: u32,
    object_name: &[u8],
    creation_digest: &[u8],
) -> TpmResult<Ticket> {
    if hierarchy == rh::NULL {
        return Ok(Ticket::null(st::CREATION));
    }
    let proof = state.hierarchy_proof(hierarchy)?.to_vec();
    let hmac = crate::tpm::crypto::hmac::hmac_parts(
        crate::tpm::config::CONTEXT_INTEGRITY_HASH_ALG,
        &proof,
        &[&st::CREATION.to_be_bytes(), object_name, creation_digest],
    )?;
    Ok(Ticket {
        tag: st::CREATION,
        hierarchy,
        digest: Tpm2bDigest::new(hmac)?,
    })
}

/// The parent an object is created under or loaded into.
struct Parent {
    name_alg: u16,
    seed: Vec<u8>,
    symmetric: crate::tpm::structures::schemes::SymDef,
    hierarchy: u32,
    qualified_name: Vec<u8>,
}

/// Resolve a parent handle to what protecting a child needs.
fn parent_of(state: &TpmState, handle: u32) -> TpmResult<Parent> {
    let object = if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle)?
    } else if (crate::tpm::constants::hc::PERSISTENT_FIRST
        ..=crate::tpm::constants::hc::PERSISTENT_LAST)
        .contains(&handle)
    {
        state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))?
    } else {
        return Err(TpmRc(rc::HANDLE));
    };
    if !object.is_storage_key() {
        return Err(TpmRc(rc::TYPE));
    }
    let symmetric = object
        .public
        .parameters
        .symmetric()
        .copied()
        .ok_or(TpmRc(rc::TYPE))?;
    if symmetric.is_null() {
        return Err(TpmRc(rc::SYMMETRIC));
    }
    Ok(Parent {
        name_alg: object.name_alg(),
        seed: object.seed_value().to_vec(),
        symmetric,
        hierarchy: object.hierarchy,
        qualified_name: object.qualified_name.clone(),
    })
}

/// TPM2_Create, Part 3 clause 12.1.
pub fn create(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let parent_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_sensitive = Tpm2bSensitiveCreate::unmarshal(&mut r)?;
    let in_public = Tpm2bPublic::unmarshal(&mut r)?;
    let outside_info = Tpm2bData::unmarshal(&mut r)?;
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut r)?;
    r.expect_end()?;

    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(1))?;
    let template = in_public.public_area;
    object::validate_public(&template).map_err(|e| e.with_parameter(2))?;
    // A child that is fixedTPM must be created by the TPM it will live in.
    if template
        .object_attributes
        .has(ObjectAttributes::FIXED_TPM)
        && !template
            .object_attributes
            .has(ObjectAttributes::FIXED_PARENT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }

    let (sensitive, unique) = create_sensitive(&mut state.rng, &template, &in_sensitive)?;
    let mut public = template;
    public.unique = unique;

    let object_name = names::object_name(&public)?;
    let private = protect::wrap_private(
        parent.name_alg,
        &parent.seed,
        &parent.symmetric,
        &object_name,
        &sensitive.to_bytes(),
    )?;

    let parent_name = super::dispatch::handle_name(state, parent_handle)?;
    let name_alg = if public.name_alg == alg::NULL {
        alg::SHA256
    } else {
        public.name_alg
    };
    let (creation, creation_digest) = creation_data(
        state,
        parent_handle,
        &parent_name,
        &parent.qualified_name,
        parent.name_alg,
        name_alg,
        &outside_info,
        &creation_pcr,
        request.locality,
    )?;
    let ticket = creation_ticket(state, parent.hierarchy, &object_name, &creation_digest)?;

    respond(move |w| {
        Tpm2bPrivate::new(private)?.marshal(w);
        Tpm2bPublic {
            public_area: public,
        }
        .marshal(w);
        Tpm2bCreationData {
            creation_data: creation,
        }
        .marshal(w);
        Tpm2bDigest::new(creation_digest)?.marshal(w);
        ticket.marshal(w);
        Ok(())
    })
}

/// TPM2_CreateLoaded, Part 3 clause 12.9.
pub fn create_loaded(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bTemplate;

    let parent_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_sensitive = Tpm2bSensitiveCreate::unmarshal(&mut r)?;
    let template_blob = Tpm2bTemplate::unmarshal(&mut r)?;
    r.expect_end()?;
    let template = TpmtPublic::from_bytes(template_blob.as_slice())
        .map_err(|e| e.with_parameter(2))?;
    object::validate_public(&template).map_err(|e| e.with_parameter(2))?;

    // A hierarchy handle makes this a Primary Object; anything else makes it
    // an ordinary child that is created and loaded in one step.
    if crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(parent_handle) {
        if !state.hierarchies.is_enabled(parent_handle) {
            return Err(TpmRc(rc::HIERARCHY).with_handle(1));
        }
        let seed = state.hierarchies.get(parent_handle)?.seed.clone();
        let context = primary_context(&template, &in_sensitive)?;
        let name_alg = if template.name_alg == alg::NULL {
            alg::SHA256
        } else {
            template.name_alg
        };
        let mut rng = SeededRng::new(name_alg, &seed, LABEL_PRIMARY, &context);
        let (sensitive, unique) = create_sensitive(&mut rng, &template, &in_sensitive)?;
        let mut public = template;
        public.unique = unique;
        let parent_qn = names::handle_name(parent_handle);
        let object = Object::new(
            public.clone(),
            Some(sensitive),
            parent_handle,
            &parent_qn,
            true,
        )?;
        let name = object.name.clone();
        let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
        return respond_with_handle(handle, move |w| {
            Tpm2bPrivate::empty().marshal(w);
            Tpm2bPublic {
                public_area: public,
            }
            .marshal(w);
            Tpm2bName::new(name)?.marshal(w);
            Ok(())
        });
    }

    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(1))?;
    let (sensitive, unique) = create_sensitive(&mut state.rng, &template, &in_sensitive)?;
    let mut public = template;
    public.unique = unique;
    let object_name = names::object_name(&public)?;
    let private = protect::wrap_private(
        parent.name_alg,
        &parent.seed,
        &parent.symmetric,
        &object_name,
        &sensitive.to_bytes(),
    )?;
    let object = Object::new(
        public.clone(),
        Some(sensitive),
        parent.hierarchy,
        &parent.qualified_name,
        true,
    )?;
    let name = object.name.clone();
    let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
    respond_with_handle(handle, move |w| {
        Tpm2bPrivate::new(private)?.marshal(w);
        Tpm2bPublic {
            public_area: public,
        }
        .marshal(w);
        Tpm2bName::new(name)?.marshal(w);
        Ok(())
    })
}

/// TPM2_Load, Part 3 clause 12.2.
pub fn load(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let parent_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_private = Tpm2bPrivate::unmarshal(&mut r)?;
    let in_public = Tpm2bPublic::unmarshal(&mut r)?;
    r.expect_end()?;

    if in_private.is_empty() {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(1))?;
    let public = in_public.public_area;
    object::validate_loaded_public(&public).map_err(|e| e.with_parameter(2))?;
    let object_name = names::object_name(&public)?;

    let plain = protect::unwrap_private(
        parent.name_alg,
        &parent.seed,
        &parent.symmetric,
        &object_name,
        in_private.as_slice(),
    )?;
    let sensitive = TpmtSensitive::from_bytes(&plain).map_err(|_| TpmRc(rc::SENSITIVE))?;
    // Part 3 clause 12.2.1 requires the two halves to belong together, which
    // is what makes the public area a description of this private key.
    object::check_binding(&public, &sensitive).map_err(|e| e.with_parameter(1))?;

    let object = Object::new(
        public,
        Some(sensitive),
        parent.hierarchy,
        &parent.qualified_name,
        false,
    )?;
    let name = object.name.clone();
    let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
    respond_with_handle(handle, move |w| {
        Tpm2bName::new(name)?.marshal(w);
        Ok(())
    })
}

/// TPM2_LoadExternal, Part 3 clause 12.3.
pub fn load_external(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    // The sensitive area is optional, which the specification writes as a
    // sized buffer of length zero. Part 3 clause 5.8.2 fails a malformed one
    // rather than reading it as absent.
    let in_private = {
        let size = r.u16()?;
        if size == 0 {
            None
        } else {
            let mut body = r.sub(size as usize).map_err(|e| e.with_parameter(1))?;
            let sensitive = crate::tpm::structures::keys::TpmtSensitive::unmarshal(&mut body)
                .map_err(|e| e.with_parameter(1))?;
            if !body.is_empty() {
                return Err(TpmRc(rc::SIZE).with_parameter(1));
            }
            Some(Tpm2bSensitive { sensitive_area: sensitive })
        }
    };
    let in_public = Tpm2bPublic::unmarshal(&mut r)?;
    let hierarchy = r.u32()?;
    r.expect_end()?;

    let public = in_public.public_area;
    object::validate_loaded_public(&public).map_err(|e| e.with_parameter(2))?;

    // The shared validator lets an asymmetric public area carry no key at all,
    // because a creation template is written that way. TPM2_LoadExternal is
    // not creating anything, so an empty modulus or an empty point is not a
    // key it can load. Part 2 Table 194 says of an RSA keyBits of zero that
    // "The value of zero is only valid for create", and an Empty Point is not
    // a point on any curve.
    match &public.unique {
        PublicId::Rsa(modulus) if modulus.is_empty() => {
            return Err(TpmRc(rc::KEY).with_parameter(2));
        }
        PublicId::Ecc(point) if point.x.is_empty() || point.y.is_empty() => {
            return Err(TpmRc(rc::KEY).with_parameter(2));
        }
        _ => {}
    }

    // An external object may not claim to be TPM resident.
    if public
        .object_attributes
        .has(ObjectAttributes::FIXED_TPM)
        || public
            .object_attributes
            .has(ObjectAttributes::FIXED_PARENT)
        || public
            .object_attributes
            .has(ObjectAttributes::SENSITIVE_DATA_ORIGIN)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }
    // A sensitive area may only be supplied under the NULL hierarchy. A
    // sensitive area that is present but holds nothing is still present, so it
    // is checked rather than read as absent.
    let sensitive = match in_private {
        Some(s) => {
            if hierarchy != rh::NULL {
                return Err(TpmRc(rc::HIERARCHY).with_parameter(3));
            }
            if s.sensitive_area.sensitive_type != public.object_type {
                return Err(TpmRc(rc::TYPE).with_parameter(1));
            }
            object::check_binding(&public, &s.sensitive_area)
                .map_err(|e| e.with_parameter(1))?;
            Some(s.sensitive_area)
        }
        None => None,
    };
    if hierarchy != rh::NULL && !crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(hierarchy)
    {
        return Err(TpmRc(rc::HIERARCHY).with_parameter(3));
    }

    let parent_qn = names::handle_name(hierarchy);
    let object = Object::new(public, sensitive, hierarchy, &parent_qn, false)?;
    let name = object.name.clone();
    let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
    respond_with_handle(handle, move |w| {
        Tpm2bName::new(name)?.marshal(w);
        Ok(())
    })
}

/// TPM2_ReadPublic, Part 3 clause 12.4.
pub fn read_public(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let object = if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle).map_err(|e| e.with_handle(1))?
    } else {
        state
            .persistent
            .get(&handle)
            .ok_or(TpmRc(rc::HANDLE).with_handle(1))?
    };
    let public = object.public.clone();
    let name = object.name.clone();
    let qualified_name = object.qualified_name.clone();
    respond(move |w| {
        Tpm2bPublic {
            public_area: public,
        }
        .marshal(w);
        Tpm2bName::new(name)?.marshal(w);
        Tpm2bName::new(qualified_name)?.marshal(w);
        Ok(())
    })
}

/// TPM2_Unseal, Part 3 clause 12.7.
pub fn unseal(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let object = state.objects.object(handle).map_err(|e| e.with_handle(1))?;
    if object.public.object_type != alg::KEYEDHASH {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    let attrs = object.public.object_attributes;
    // Only a data object may be unsealed: a signing or decrypting keyed hash
    // is a key, not sealed data.
    if attrs.any(ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::DECRYPT) {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let data = sensitive.sensitive.as_slice().to_vec();
    respond(move |w| {
        Tpm2bSensitiveData::new(data)?.marshal(w);
        Ok(())
    })
}

/// TPM2_ObjectChangeAuth, Part 3 clause 12.8.
pub fn object_change_auth(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let object_handle = request.handle(0)?;
    let parent_handle = request.handle(1)?;
    let mut r = request.reader();
    let new_auth = Tpm2bDigest::unmarshal(&mut r)?;
    r.expect_end()?;

    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(2))?;
    let object = state
        .objects
        .object(object_handle)
        .map_err(|e| e.with_handle(1))?;
    // The object must be a child of the named parent.
    if object.qualified_name
        != names::qualified_name(object.public.name_alg, &parent.qualified_name, &object.name)?
    {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let digest_size = hash::digest_size(object.public.name_alg)?;
    if new_auth.len() > digest_size {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }

    let mut updated = sensitive.clone();
    updated.auth_value = Tpm2bDigest::new(new_auth.as_slice().to_vec())?;
    let name = object.name.clone();
    let private = protect::wrap_private(
        parent.name_alg,
        &parent.seed,
        &parent.symmetric,
        &name,
        &updated.to_bytes(),
    )?;
    respond(move |w| {
        Tpm2bPrivate::new(private)?.marshal(w);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::curve;
    use crate::tpm::structures::schemes::{Scheme, SymDef};

    fn ecc_template(attrs: u32) -> TpmtPublic {
        TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(attrs),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                curve_id: curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(EccPoint::default()),
        }
    }

    fn storage_template() -> TpmtPublic {
        TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::FIXED_TPM
                    | ObjectAttributes::FIXED_PARENT
                    | ObjectAttributes::SENSITIVE_DATA_ORIGIN
                    | ObjectAttributes::USER_WITH_AUTH
                    | ObjectAttributes::RESTRICTED
                    | ObjectAttributes::DECRYPT,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::new(alg::AES, 128, alg::CFB),
                scheme: Scheme::null(),
                curve_id: curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(EccPoint::default()),
        }
    }

    #[test]
    fn primary_derivation_is_repeatable_and_template_dependent() {
        let seed = [0x42u8; 32];
        let template = ecc_template(ObjectAttributes::SIGN_ENCRYPT);
        let empty = Tpm2bSensitiveCreate::default();
        let context = primary_context(&template, &empty).unwrap();

        let mut a = SeededRng::new(alg::SHA256, &seed, LABEL_PRIMARY, &context);
        let mut b = SeededRng::new(alg::SHA256, &seed, LABEL_PRIMARY, &context);
        let (sa, ua) = create_sensitive(&mut a, &template, &empty).unwrap();
        let (sb, ub) = create_sensitive(&mut b, &template, &empty).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(ua, ub);

        // A different template gives a different key.
        let other = ecc_template(ObjectAttributes::DECRYPT);
        let other_context = primary_context(&other, &empty).unwrap();
        assert_ne!(context, other_context);
        let mut c = SeededRng::new(alg::SHA256, &seed, LABEL_PRIMARY, &other_context);
        let (sc, _) = create_sensitive(&mut c, &other, &empty).unwrap();
        assert_ne!(sa, sc);

        // Part 3 clause 24.1.1: "all of the bits of the template are used in
        // the creation of the Primary Key". The unique field is one of them,
        // even though nothing the caller puts there is used as a key.
        let mut with_unique = ecc_template(ObjectAttributes::SIGN_ENCRYPT);
        with_unique.unique = PublicId::Ecc(EccPoint {
            x: crate::tpm::structures::base::Tpm2bEccParameter::new(vec![0u8; 32]).unwrap(),
            y: crate::tpm::structures::base::Tpm2bEccParameter::new(vec![0u8; 32]).unwrap(),
        });
        let unique_context = primary_context(&with_unique, &empty).unwrap();
        assert_ne!(
            context, unique_context,
            "the unique field was left out of the derivation"
        );
    }

    #[test]
    fn a_storage_key_gets_a_seed_value() {
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[1u8; 48], b"t").unwrap();
        let (sensitive, _) =
            create_sensitive(&mut rng, &storage_template(), &Tpm2bSensitiveCreate::default())
                .unwrap();
        assert_eq!(sensitive.seed_value.len(), 32);

        // A plain signing key does not need one.
        let (sensitive, _) = create_sensitive(
            &mut rng,
            &ecc_template(ObjectAttributes::SIGN_ENCRYPT),
            &Tpm2bSensitiveCreate::default(),
        )
        .unwrap();
        assert!(sensitive.seed_value.is_empty());
    }

    #[test]
    fn a_sealed_data_object_takes_its_data_from_the_caller() {
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[2u8; 48], b"t").unwrap();
        let template = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::USER_WITH_AUTH),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme::null(),
            },
            unique: PublicId::KeyedHash(Tpm2bDigest::empty()),
        };
        let mut supplied = Tpm2bSensitiveCreate::default();
        supplied.sensitive.data = Tpm2bSensitiveData::from_slice(b"the secret").unwrap();
        let (sensitive, unique) = create_sensitive(&mut rng, &template, &supplied).unwrap();
        assert_eq!(sensitive.sensitive.as_slice(), b"the secret");
        // The unique value binds the seed to the data.
        if let PublicId::KeyedHash(d) = unique {
            let expected = hash::digest_parts(
                alg::SHA256,
                &[sensitive.seed_value.as_slice(), b"the secret"],
            )
            .unwrap();
            assert_eq!(d.as_slice(), &expected[..]);
        } else {
            panic!("wrong identifier");
        }
    }

    #[test]
    fn sensitive_data_origin_and_supplied_data_are_exclusive() {
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[3u8; 48], b"t").unwrap();
        let template = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::SENSITIVE_DATA_ORIGIN),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme::null(),
            },
            unique: PublicId::KeyedHash(Tpm2bDigest::empty()),
        };
        let mut supplied = Tpm2bSensitiveCreate::default();
        supplied.sensitive.data = Tpm2bSensitiveData::from_slice(b"x").unwrap();
        assert_eq!(
            create_sensitive(&mut rng, &template, &supplied)
                .unwrap_err()
                .0
                & 0x03F,
            rc::ATTRIBUTES & 0x03F
        );
        // With no data supplied the TPM generates it.
        let (sensitive, _) =
            create_sensitive(&mut rng, &template, &Tpm2bSensitiveCreate::default()).unwrap();
        assert_eq!(sensitive.sensitive.as_slice().len(), 32);
    }

    #[test]
    fn an_authorization_value_longer_than_the_digest_is_refused() {
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[4u8; 48], b"t").unwrap();
        let mut supplied = Tpm2bSensitiveCreate::default();
        supplied.sensitive.user_auth = Tpm2bDigest::from_slice(&[0u8; 33]).unwrap();
        assert_eq!(
            create_sensitive(
                &mut rng,
                &ecc_template(ObjectAttributes::SIGN_ENCRYPT),
                &supplied
            )
            .unwrap_err()
            .0
                & 0x03F,
            rc::SIZE & 0x03F
        );
    }
}
