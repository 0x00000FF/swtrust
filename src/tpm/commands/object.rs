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
    Derive, PublicId, PublicParms, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveCreate, TpmtPublic,
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
///
/// The same sentence names inSensitive.data and not the rest of inSensitive.
/// The authorization value is copied into the object afterwards, Part 1 clause
/// 24.7.3, so a caller that asks for the same key under a new authorization has
/// to get the same key.
fn primary_context(
    template: &TpmtPublic,
    sensitive: &Tpm2bSensitiveCreate,
) -> TpmResult<Vec<u8>> {
    let mut w = Writer::new();
    template.marshal(&mut w);
    sensitive.sensitive.data.marshal(&mut w);
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
    let in_sensitive =
        Tpm2bSensitiveCreate::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_public = Tpm2bPublic::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let outside_info = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut r).map_err(|e| e.with_parameter(4))?;
    r.expect_end()?;

    if !crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(primary_handle) {
        return Err(TpmRc(rc::VALUE).with_handle(1));
    }
    if !state.hierarchies.is_enabled(primary_handle) {
        return Err(TpmRc(rc::HIERARCHY).with_handle(1));
    }
    let template = in_public.public_area;
    object::validate_creation_template(&template).map_err(|e| e.with_parameter(2))?;

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
    /// The stateClear property of Part 1 clause 30.4.2, which a child inherits.
    state_clear: bool,
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
        state_clear: object.state_clear,
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
    let in_sensitive =
        Tpm2bSensitiveCreate::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_public = Tpm2bPublic::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let outside_info = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut r).map_err(|e| e.with_parameter(4))?;
    r.expect_end()?;

    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(1))?;
    let template = in_public.public_area;
    object::validate_creation_template(&template).map_err(|e| e.with_parameter(2))?;
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

/// What deriving a child from a Derivation Parent needs.
struct DerivationParent {
    /// The stateClear property of Part 1 clause 30.4.2, which a child inherits.
    state_clear: bool,
    /// The hash of the parent's KDF, Part 1 clause 25.2.
    hash_alg: u16,
    /// The parent's sensitive value, which is the entropy of the child.
    sensitive: Vec<u8>,
    hierarchy: u32,
    qualified_name: Vec<u8>,
}

/// Resolve a handle to a Derivation Parent, or nothing if it is not one.
///
/// A handle that names no object at all is left to the ordinary path, which
/// reports it, so that a bad handle keeps the error it would otherwise get.
fn derivation_parent(state: &TpmState, handle: u32) -> TpmResult<Option<DerivationParent>> {
    let object = if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        match state.objects.object(handle) {
            Ok(o) => o,
            Err(_) => return Ok(None),
        }
    } else if (crate::tpm::constants::hc::PERSISTENT_FIRST
        ..=crate::tpm::constants::hc::PERSISTENT_LAST)
        .contains(&handle)
    {
        match state.persistent.get(&handle) {
            Some(o) => o,
            None => return Ok(None),
        }
    } else {
        return Ok(None);
    };
    if !object.is_derivation_parent() {
        return Ok(None);
    }
    derivation_parent_of(object).map(Some)
}

/// Read what a loaded object offers as a Derivation Parent.
fn derivation_parent_of(object: &Object) -> TpmResult<DerivationParent> {
    // Part 1 clause 25.4.1 spells out the KDF parameters and says plainly that
    // hashAlg is "the nameAlg of the derivation parent". Clause 25.2 calls the
    // KDF a property of the parent, but it is this clause that says which of
    // the parent's properties, so the scheme is not consulted.
    let hash_alg = object.public.name_alg;
    if hash_alg == alg::NULL {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }

    let sensitive = match object.sensitive.as_ref().map(|s| &s.sensitive) {
        Some(SensitiveComposite::Bits(b)) => b.as_slice().to_vec(),
        _ => return Err(TpmRc(rc::TYPE).with_handle(1)),
    };

    Ok(DerivationParent {
        state_clear: object.state_clear,
        hash_alg,
        sensitive,
        hierarchy: object.hierarchy,
        qualified_name: object.qualified_name.clone(),
    })
}

/// Generate a Derived Object, Part 3 clause 12.9.1 and Part 1 clause 25.
fn derive_object(
    state: &mut TpmState,
    parent_handle: u32,
    parent: DerivationParent,
    in_sensitive: &Tpm2bSensitiveCreate,
    template_blob: &crate::tpm::structures::base::Tpm2bTemplate,
) -> TpmResult<Response> {
    // Part 2 clause 12.2.6: under a derivation parent the unique field is a
    // TPMS_DERIVE rather than an object identifier.
    let mut r = crate::tpm::marshal::Reader::new(template_blob.as_slice());
    let template = TpmtPublic::unmarshal_with(&mut r, true).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;
    object::validate_creation_template(&template).map_err(|e| e.with_parameter(2))?;

    // Clause 12.9.1 names the one input check that is specific to derivation:
    // "when parentHandle references a Derivation Parent, then
    // sensitiveDataOrigin in inPublic is required to be CLEAR." Part 1 clause
    // 25.3 gives the reason: the caller supplies values that steer the
    // derivation but never sets the sensitive value itself.
    //
    // Part 1 clause 5 says "the order in which checks are performed is not
    // normative", so a template that breaks this rule and the one below could
    // be answered with either code. This one goes first because the clause
    // requires it while only permitting the other, which makes it the more
    // useful of the two answers to give.
    if template
        .object_attributes
        .has(ObjectAttributes::SENSITIVE_DATA_ORIGIN)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
    }

    // Clause 12.9.1: "If parentHandle references a Derivation Parent, then the
    // TPM may return TPM_RC_TYPE if the key type to be generated is an RSA
    // key." Deriving an RSA key means searching for primes in the KDF stream,
    // which this TPM does not do.
    if template.object_type == alg::RSA {
        return Err(TpmRc(rc::TYPE).with_parameter(2));
    }

    let (label, context) = label_and_context(&template, in_sensitive).map_err(|e| {
        // A label and context that will not unmarshal came in the sensitive
        // area, which is the first parameter.
        e.with_parameter(1)
    })?;
    let mut octets = DerivedOctets::new(parent.hash_alg, &parent.sensitive, &label, &context)?;
    let (sensitive, unique) = derived_sensitive(&mut octets, &template, in_sensitive)?;

    let mut public = template;
    public.unique = unique;
    let mut object = Object::new(
        public.clone(),
        Some(sensitive),
        parent.hierarchy,
        &parent.qualified_name,
        true,
    )?;
    // Part 1 clause 30.4.2: the property comes from the object or from any of
    // its ancestors, and the parent carries what its own ancestors gave it.
    object.state_clear |= parent.state_clear;
    let name = object.name.clone();
    let handle = state.objects.insert(Slot::Object(Box::new(object)))?;
    let _ = parent_handle;
    respond_with_handle(handle, move |w| {
        // Clause 12.9.1: "If parentHandle references a Derivation Parent or a
        // Primary Seed, then outPrivate will be an Empty Buffer." A derived
        // object can only be derived again, never loaded.
        Tpm2bPrivate::empty().marshal(w);
        Tpm2bPublic {
            public_area: public,
        }
        .marshal(w);
        Tpm2bName::new(name)?.marshal(w);
        Ok(())
    })
}

/// The octets a Derived Object is built from, Part 1 clause 25.4.1.
///
/// One KDFa call fills a fixed buffer, and the derived values are taken from it
/// "from most significant byte to least significant byte with no bytes
/// skipped". The first digest is the most significant, which is the order KDFa
/// already produces, so the octets are handed out from the front. Running out
/// is not something the caller can retry differently, so it is reported as
/// TPM_RC_NO_RESULT rather than as a failure of the generator.
struct DerivedOctets {
    buffer: Vec<u8>,
    offset: usize,
}

impl DerivedOctets {
    /// KDFa(hashAlg, sensitive, label, context, 0, 8192) of clause 25.4.1.
    fn new(hash_alg: u16, sensitive: &[u8], label: &[u8], context: &[u8]) -> TpmResult<Self> {
        Ok(DerivedOctets {
            buffer: crate::tpm::crypto::hmac::kdfa_bytes(
                hash_alg, sensitive, label, context, &[], 8192,
            )?,
            offset: 0,
        })
    }
}

impl Rng for DerivedOctets {
    fn fill(&mut self, out: &mut [u8]) -> TpmResult<()> {
        let end = self
            .offset
            .checked_add(out.len())
            .filter(|e| *e <= self.buffer.len())
            .ok_or(TpmRc(rc::NO_RESULT))?;
        out.copy_from_slice(&self.buffer[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

/// Build the sensitive area of a Derived Object, Part 1 clause 25.4.1.
///
/// The ordinary creation path cannot serve here. It draws the obfuscation value
/// before the key, it takes the sensitive value from the caller or from the
/// system generator depending on sensitiveDataOrigin, and it draws an ECC
/// scalar by rejection. Clause 25.4.1 fixes all three: "Those derived values
/// are the sensitive and seedValues", in that order, taken "from most
/// significant byte to least significant byte with no bytes skipped", with the
/// scalar drawn by the extra random bits method so that no octet is rejected
/// and the seedValue starts where the key ends.
fn derived_sensitive(
    octets: &mut DerivedOctets,
    template: &TpmtPublic,
    supplied: &Tpm2bSensitiveCreate,
) -> TpmResult<(TpmtSensitive, PublicId)> {
    let name_alg = if template.name_alg == alg::NULL {
        alg::SHA256
    } else {
        template.name_alg
    };
    let digest_size = hash::digest_size(name_alg)?;
    let auth_value = supplied.sensitive.user_auth.as_slice().to_vec();
    if auth_value.len() > digest_size {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }

    let (composite, unique) = match template.object_type {
        alg::ECC => {
            let PublicParms::Ecc { curve_id, .. } = template.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let curve = ecc::Curve::new(curve_id)?;
            let size = curve.coordinate_size();
            let private = ecc::private_key_extra_bits(&curve, octets)?;
            let key = ecc::key_from_private(curve, private)?;
            crate::tpm::fips::pairwise_ecc(
                curve_id,
                &key.private.to_bytes_padded(size)?,
                &key.public_x,
                &key.public_y,
                template
                    .object_attributes
                    .has(ObjectAttributes::SIGN_ENCRYPT),
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
        alg::SYMCIPHER => {
            let PublicParms::SymCipher { sym } = &template.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let key = octets.bytes(sym.key_bits as usize / 8)?;
            (SensitiveComposite::Sym(Tpm2bSymKey::new(key)?), PublicId::Sym(Tpm2bDigest::empty()))
        }
        alg::KEYEDHASH => {
            // Part 3 clause 12.1 sizes a generated keyed hash value at "the
            // digest produced by the nameAlg in inPublic", and a derived object
            // never takes one from the caller.
            let bits = octets.bytes(digest_size)?;
            (
                SensitiveComposite::Bits(Tpm2bSensitiveData::new(bits)?),
                PublicId::KeyedHash(Tpm2bDigest::empty()),
            )
        }
        // RSA was refused before the octets were drawn.
        _ => return Err(TpmRc(rc::TYPE).with_parameter(2)),
    };

    // Part 3 clause 12.1 gives an asymmetric key a seedValue only when it is a
    // Storage Key, and gives every symmetric or keyed hash object one. The
    // octets come after the key, which is what clause 25.4.1's examples show.
    let is_parent = template
        .object_attributes
        .has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT);
    let seed_value = if is_parent || matches!(template.object_type, alg::KEYEDHASH | alg::SYMCIPHER)
    {
        octets.bytes(digest_size)?
    } else {
        Vec::new()
    };

    // Equation 1 of clause 12.1 computes the unique value of a symmetric or
    // keyed hash object from the two values that were just derived.
    let unique = match unique {
        PublicId::Sym(_) | PublicId::KeyedHash(_) => {
            let secret = match &composite {
                SensitiveComposite::Sym(s) => s.as_slice(),
                SensitiveComposite::Bits(b) => b.as_slice(),
                _ => unreachable!("the composite was built beside the identifier"),
            };
            let digest = hash::digest_parts(name_alg, &[&seed_value, secret])?;
            if template.object_type == alg::SYMCIPHER {
                PublicId::Sym(Tpm2bDigest::new(digest)?)
            } else {
                PublicId::KeyedHash(Tpm2bDigest::new(digest)?)
            }
        }
        other => other,
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

/// The label and context a Derived Object is derived with.
///
/// Part 2 clause 11.1.11 says "the values in the unique field of inPublic area
/// template take precedence over the values in the inSensitive parameter", and
/// the precedence is per field: a label given in the template is used even when
/// the sensitive area also carries a context, and the other way round.
fn label_and_context(
    template: &TpmtPublic,
    sensitive: &Tpm2bSensitiveCreate,
) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    let from_template = match &template.unique {
        PublicId::Derive(d) => d.clone(),
        // The template was unmarshalled with the derivation form, so this
        // cannot happen; an empty pair keeps the fallback below correct.
        _ => Derive::default(),
    };
    let mut label = from_template.label.as_slice().to_vec();
    let mut context = from_template.context.as_slice().to_vec();

    // The sensitive area of a Derived Object holds a TPMS_DERIVE too, and
    // supplies whichever of the two the template left empty. When the template
    // gave both there is nothing left to take, and Part 1 clause 25.2 says the
    // field "is ignored" rather than checked, so it is not even read.
    let data = sensitive.sensitive.data.as_slice();
    if !data.is_empty() && (label.is_empty() || context.is_empty()) {
        let mut r = crate::tpm::marshal::Reader::new(data);
        let from_sensitive = Derive::unmarshal(&mut r)?;
        r.expect_end()?;
        if label.is_empty() {
            label = from_sensitive.label.as_slice().to_vec();
        }
        if context.is_empty() {
            context = from_sensitive.context.as_slice().to_vec();
        }
    }
    Ok((label, context))
}

/// TPM2_CreateLoaded, Part 3 clause 12.9.
pub fn create_loaded(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bTemplate;

    let parent_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_sensitive =
        Tpm2bSensitiveCreate::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let template_blob = Tpm2bTemplate::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    // Part 1 clause 25.3: the template is a TPM2B_TEMPLATE rather than a
    // TPM2B_PUBLIC so that the unique field can be read "based on the type of
    // parent and type of inPublic". Only a Derivation Parent gives it the
    // derivation form, so the parent has to be known before it is read.
    if let Some(parent) = derivation_parent(state, parent_handle)? {
        return derive_object(state, parent_handle, parent, &in_sensitive, &template_blob);
    }

    let template = TpmtPublic::from_bytes(template_blob.as_slice())
        .map_err(|e| e.with_parameter(2))?;
    object::validate_creation_template(&template).map_err(|e| e.with_parameter(2))?;

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
    let mut object = Object::new(
        public.clone(),
        Some(sensitive),
        parent.hierarchy,
        &parent.qualified_name,
        true,
    )?;
    object.state_clear |= parent.state_clear;
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
    let in_private = Tpm2bPrivate::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_public = Tpm2bPublic::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    if in_private.is_empty() {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }
    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(1))?;
    let public = in_public.public_area;
    object::validate_loaded_public(&public).map_err(|e| e.with_parameter(2))?;
    // Clause 12.2.1 repeats the creation rule for this command alone, so an
    // object that can do nothing is refused here as well as when it was made.
    object::validate_action_attributes(&public).map_err(|e| e.with_parameter(2))?;
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

    let mut object = Object::new(
        public,
        Some(sensitive),
        parent.hierarchy,
        &parent.qualified_name,
        false,
    )?;
    // Part 1 clause 30.4.2: the property comes from the object or from any of
    // its ancestors, and the parent carries what its own ancestors gave it.
    object.state_clear |= parent.state_clear;
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
        let size = r.u16().map_err(|e| e.with_parameter(1))?;
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
    let in_public = Tpm2bPublic::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let hierarchy = r.u32().map_err(|e| e.with_parameter(3))?;
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

    // Part 2 clause 8.3.3.1 says the External column of the attribute table
    // "indicates settings that apply to the inPublic parameter in
    // TPM2_LoadExternal() if both the public and sensitive portions of the
    // object are loaded", and that when only the public portion is loaded
    // "the only attribute checks are the checks in the validation code
    // following Table 37 and the reserved attributes check". So the column is
    // read only when a sensitive area came with the public one. A public area
    // on its own may say fixedTPM, which is how the public half of a key that
    // does live on some TPM is loaded to compute its Name or make a credential
    // for it.
    if in_private.is_some() {
        // Clause 8.3.3.2 fixedTPM, 8.3.3.4 fixedParent and 8.3.3.12
        // restricted all read "shall be CLEAR" here, and Part 3 clause 12.3
        // repeats the three together: "fixedTPM, fixedParent, and restricted
        // shall be CLEAR if inPrivate is not the Empty Buffer."
        if public
            .object_attributes
            .has(ObjectAttributes::FIXED_TPM)
            || public
                .object_attributes
                .has(ObjectAttributes::FIXED_PARENT)
            || public
                .object_attributes
                .has(ObjectAttributes::RESTRICTED)
        {
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
        }
        // Clause 8.3.3.8 firmwareLimited and 8.3.3.9 svnLimited say the same
        // of an external object that brings its sensitive half: an object
        // whose use is bound to this TPM's firmware or version cannot have
        // arrived from outside it.
        if public
            .object_attributes
            .has(ObjectAttributes::FIRMWARE_LIMITED)
            || public
                .object_attributes
                .has(ObjectAttributes::SVN_LIMITED)
        {
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(2));
        }
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
    // Part 2 Table 45: an object of a hierarchy whose enable is CLEAR "may not
    // be used", so one is not loaded into it either.
    if !state.hierarchies.is_enabled(hierarchy) {
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

/// A loaded object, transient or persistent.
///
/// Part 2 clause 9.4 gives TPMI_DH_OBJECT both ranges, so a command that names
/// one takes an object that TPM2_EvictControl has made persistent as readily as
/// one TPM2_Load put in a transient slot.
fn loaded_object(state: &TpmState, handle: u32) -> TpmResult<&Object> {
    use crate::tpm::constants::hc;

    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle)
    } else if (hc::PERSISTENT_FIRST..=hc::PERSISTENT_LAST).contains(&handle) {
        state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))
    } else {
        Err(TpmRc(rc::HANDLE))
    }
}

/// TPM2_Unseal, Part 3 clause 12.7.
pub fn unseal(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let object = loaded_object(state, handle).map_err(|e| e.with_handle(1))?;
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
    let new_auth = Tpm2bDigest::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    r.expect_end()?;

    let parent = parent_of(state, parent_handle).map_err(|e| e.with_handle(2))?;
    // Part 3 clause 12.8.1: "the object may be a transient object or a
    // persistent object", which is why its handle is a TPMI_DH_OBJECT.
    let object = loaded_object(state, object_handle).map_err(|e| e.with_handle(1))?;
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

    /// A loaded keyed hash Derivation Parent with the given hashes and secret.
    fn derivation_parent_object(name_alg: u16, scheme_hash: u16, secret: &[u8]) -> Object {
        use crate::tpm::structures::base::Tpm2bSensitiveData;
        use crate::tpm::structures::schemes::{Scheme, SchemeDetail, SchemeXor};

        let public = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg,
            object_attributes: ObjectAttributes(
                ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme {
                    scheme: alg::XOR,
                    detail: SchemeDetail::Xor(SchemeXor {
                        hash_alg: scheme_hash,
                        kdf: alg::KDF1_SP800_108,
                    }),
                },
            },
            unique: PublicId::KeyedHash(Tpm2bDigest::empty()),
        };
        let sensitive = TpmtSensitive {
            sensitive_type: alg::KEYEDHASH,
            auth_value: Tpm2bDigest::empty(),
            seed_value: Tpm2bDigest::empty(),
            sensitive: SensitiveComposite::Bits(Tpm2bSensitiveData::new(secret.to_vec()).unwrap()),
        };
        Object::new(public, Some(sensitive), rh::OWNER, &[], true).unwrap()
    }

    #[test]
    fn the_derivation_hash_is_the_parent_name_algorithm() {
        // Part 1 clause 25.4.1 lists the KDF parameters and says hashAlg is
        // "the nameAlg of the derivation parent". Clause 25.2 says only that
        // the KDF is a property of the parent, which is why the scheme is a
        // plausible but wrong place to read the hash from.
        let secret = b"a derivation parent secret";

        let a = derivation_parent_of(&derivation_parent_object(alg::SHA256, alg::SHA256, secret))
            .unwrap();
        let b = derivation_parent_of(&derivation_parent_object(alg::SHA256, alg::SHA384, secret))
            .unwrap();
        let c = derivation_parent_of(&derivation_parent_object(alg::SHA384, alg::SHA256, secret))
            .unwrap();

        assert_eq!(a.hash_alg, alg::SHA256);
        assert_eq!(
            b.hash_alg,
            alg::SHA256,
            "the scheme hash was taken for the KDF hash"
        );
        assert_eq!(c.hash_alg, alg::SHA384, "the nameAlg was not taken");

        // The octets follow the hash, so two parents that share a nameAlg and a
        // secret derive the same stream whatever their schemes say.
        let stream = |p: &DerivationParent| {
            let mut o = DerivedOctets::new(p.hash_alg, &p.sensitive, b"label", b"context").unwrap();
            o.bytes(64).unwrap()
        };
        assert_eq!(stream(&a), stream(&b), "the scheme reached the KDF");
        assert_ne!(stream(&a), stream(&c));
    }

    #[test]
    fn the_derived_octets_are_one_kdfa_call_read_from_the_front() {
        // Part 1 clause 25.4.1: KDFa(hashAlg, sensitive, label, context, 0,
        // 8192), whose 1024 octets are used "from most significant byte to
        // least significant byte with no bytes skipped". The buffer is compared
        // against KDFa computed here, so the label termination, the context and
        // the bit count are all pinned down.
        let secret = b"a derivation parent secret";
        let expected = crate::tpm::crypto::hmac::kdfa_bytes(
            alg::SHA256,
            secret,
            b"label",
            b"context",
            &[],
            8192,
        )
        .unwrap();
        assert_eq!(expected.len(), 1024, "clause 25.4.1 asks for 1024 octets");

        let mut octets = DerivedOctets::new(alg::SHA256, secret, b"label", b"context").unwrap();
        // Read in uneven pieces: nothing may be skipped between them.
        let mut got = octets.bytes(7).unwrap();
        got.extend(octets.bytes(40).unwrap());
        got.extend(octets.bytes(32).unwrap());
        assert_eq!(got, expected[..79]);

        // The buffer ends after 1024 octets rather than generating more.
        let mut octets = DerivedOctets::new(alg::SHA256, secret, b"label", b"context").unwrap();
        assert!(octets.bytes(1024).is_ok());
        assert_eq!(octets.bytes(1).unwrap_err(), TpmRc(rc::NO_RESULT));
    }

    #[test]
    fn a_derived_symmetric_key_matches_the_clause_25_4_1_example() {
        // Part 1 clause 25.4.1: "For a 128-bit AES key in a SYMCIPHER object
        // having SHA-256 as its nameAlg, the most significant 16 bytes of the
        // KDF data are used for the AES key and the next-most-significant 32
        // bytes are used for the seedValue."
        let secret = b"a derivation parent secret";
        let stream =
            crate::tpm::crypto::hmac::kdfa_bytes(alg::SHA256, secret, b"l", b"c", &[], 8192)
                .unwrap();

        let template = TpmtPublic {
            object_type: alg::SYMCIPHER,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::DECRYPT),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::SymCipher {
                sym: SymDef::new(alg::AES, 128, alg::CFB),
            },
            unique: PublicId::Sym(Tpm2bDigest::empty()),
        };

        let mut octets = DerivedOctets::new(alg::SHA256, secret, b"l", b"c").unwrap();
        let (sensitive, unique) =
            derived_sensitive(&mut octets, &template, &Tpm2bSensitiveCreate::default()).unwrap();

        let SensitiveComposite::Sym(key) = &sensitive.sensitive else {
            panic!("a symmetric object must hold a symmetric key");
        };
        assert_eq!(key.as_slice(), &stream[..16], "the key is not the first 16");
        assert_eq!(
            sensitive.seed_value.as_slice(),
            &stream[16..48],
            "the seedValue does not follow the key"
        );

        // Equation 1 of Part 3 clause 12.1 builds the unique value from the two.
        let PublicId::Sym(digest) = &unique else {
            panic!("a symmetric object names a digest");
        };
        assert_eq!(
            digest.as_slice(),
            crate::tpm::crypto::hash::digest_parts(
                alg::SHA256,
                &[&stream[16..48], &stream[..16]]
            )
            .unwrap()
        );
    }

    #[test]
    fn a_derived_ecc_key_takes_the_octets_clause_25_4_1_names() {
        // Part 1 clause 25.4.1: "For a 256-bit ECC key, the most-significant 40
        // bytes are used to generate the private key and, if the nameAlg of the
        // derived object is SHA-256, the next-most-significant 32 bytes will be
        // used for the seedValue." The scalar comes from FIPS 186-5 A.2.1,
        // which reduces those 40 octets rather than rejecting any of them.
        use crate::tpm::crypto::bn::{BigNum, BnCtx};
        use crate::tpm::structures::schemes::{Scheme, SymDef};

        let secret = b"a derivation parent secret";
        let stream =
            crate::tpm::crypto::hmac::kdfa_bytes(alg::SHA256, secret, b"l", b"c", &[], 8192)
                .unwrap();

        let template = TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::SIGN_ENCRYPT),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                curve_id: curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(EccPoint::default()),
        };

        let mut octets = DerivedOctets::new(alg::SHA256, secret, b"l", b"c").unwrap();
        let (sensitive, _unique) =
            derived_sensitive(&mut octets, &template, &Tpm2bSensitiveCreate::default()).unwrap();

        // The scalar is the first 40 octets reduced modulo one less than the
        // order, with one added.
        let curve = crate::tpm::crypto::ecc::Curve::new(curve::NIST_P256).unwrap();
        let ctx = BnCtx::new().unwrap();
        let expected = BigNum::from_bytes(&stream[..40])
            .unwrap()
            .modulo(&curve.order().unwrap().sub_word(1).unwrap(), &ctx)
            .unwrap()
            .add_word(1)
            .unwrap();
        let SensitiveComposite::Ecc(private) = &sensitive.sensitive else {
            panic!("an ECC object holds a scalar");
        };
        assert_eq!(private.as_slice(), expected.to_bytes_padded(32).unwrap());

        // Part 3 clause 12.1 gives a seedValue only to a Storage Key, and this
        // key signs, so none of the octets after the scalar are taken.
        assert!(
            sensitive.seed_value.is_empty(),
            "a signing key is not a Storage Key, so it has no seedValue"
        );
    }

    #[test]
    fn an_extra_random_bits_scalar_takes_the_bits_the_order_needs() {
        // FIPS 186-5 A.2.1, which Part 1 clause 25.4.1 names for derivation,
        // takes N + 64 bits where N is the length of the order. P-256 gives 320
        // bits, a whole 40 octets. P-521 gives 585, which is 74 octets with the
        // top 7 bits not part of the candidate; taking all 592 would derive a
        // key no other TPM produces.
        use crate::tpm::crypto::bn::{BigNum, BnCtx};
        use crate::tpm::crypto::ecc::{private_key_extra_bits, Curve};

        /// Hands out a fixed stream so the scalar can be predicted.
        struct Fixed(Vec<u8>, usize);
        impl Rng for Fixed {
            fn fill(&mut self, out: &mut [u8]) -> TpmResult<()> {
                out.copy_from_slice(&self.0[self.1..self.1 + out.len()]);
                self.1 += out.len();
                Ok(())
            }
        }

        let ctx = BnCtx::new().unwrap();
        for (curve_id, octets, order_bits) in [
            (curve::NIST_P256, 40usize, 256usize),
            (curve::NIST_P384, 56, 384),
            (curve::NIST_P521, 74, 521),
        ] {
            let curve = Curve::new(curve_id).unwrap();
            assert_eq!(curve.order().unwrap().bits(), order_bits);

            // A stream of set bits shows the masking, and what follows the
            // scalar shows how many octets were taken.
            let stream = vec![0xffu8; 256];
            let mut rng = Fixed(stream.clone(), 0);
            let got = private_key_extra_bits(&curve, &mut rng).unwrap();
            assert_eq!(rng.1, octets, "the wrong number of octets was taken");

            let wanted = order_bits + 64;
            let mut bytes = stream[..octets].to_vec();
            let spare = octets * 8 - wanted;
            if spare > 0 {
                bytes[0] &= 0xffu8 >> spare;
            }
            let expected = BigNum::from_bytes(&bytes)
                .unwrap()
                .modulo(&curve.order().unwrap().sub_word(1).unwrap(), &ctx)
                .unwrap()
                .add_word(1)
                .unwrap();
            assert_eq!(
                got.to_bytes().unwrap(),
                expected.to_bytes().unwrap(),
                "the candidate was not reduced to {wanted} bits"
            );
        }
    }

    #[test]
    fn a_template_that_gives_both_values_ignores_the_sensitive_area() {
        // Part 1 clause 25.2: "If provided in the unique field, the
        // corresponding value in the inSensitive.data field is ignored." A
        // buffer that is ignored is not read, so one that could not be a
        // TPMS_DERIVE does not turn into an error.
        use crate::tpm::structures::base::{Tpm2bLabel, Tpm2bSensitiveData};

        let mut template = ecc_template(ObjectAttributes::SIGN_ENCRYPT);
        template.unique = PublicId::Derive(Derive {
            label: Tpm2bLabel::new(b"label".to_vec()).unwrap(),
            context: Tpm2bLabel::new(b"context".to_vec()).unwrap(),
        });

        let mut junk = Tpm2bSensitiveCreate::default();
        junk.sensitive.data = Tpm2bSensitiveData::new(vec![0xff; 3]).unwrap();
        let (label, context) = label_and_context(&template, &junk).unwrap();
        assert_eq!(label, b"label");
        assert_eq!(context, b"context");

        // With one of them missing the buffer is read after all, and a buffer
        // that is not a TPMS_DERIVE is then an error rather than a silent zero.
        let mut half = template.clone();
        half.unique = PublicId::Derive(Derive {
            label: Tpm2bLabel::new(b"label".to_vec()).unwrap(),
            context: Tpm2bLabel::empty(),
        });
        assert!(label_and_context(&half, &junk).is_err());
    }
}
