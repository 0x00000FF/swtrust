//! Loaded objects and the transient object slots, Part 1 clauses 25 and 30.

use std::collections::BTreeMap;

use crate::tpm::config;
use crate::tpm::constants::{alg, hc, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::structures::attributes::ObjectAttributes;
use crate::tpm::structures::keys::{TpmtPublic, TpmtSensitive};

use super::names;

/// What an object slot holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub public: TpmtPublic,
    /// Absent for an object loaded with only a public area.
    pub sensitive: Option<TpmtSensitive>,
    pub name: Vec<u8>,
    pub qualified_name: Vec<u8>,
    /// The hierarchy the object belongs to, or TPM_RH_NULL.
    pub hierarchy: u32,
    /// Set when the object was created by this TPM rather than imported or
    /// loaded from outside, which TPM2_CertifyCreation needs.
    pub tpm_generated: bool,
    /// The stateClear property of Part 1 clause 30.4.2: "an Object has the
    /// stateClear property when stClear is SET in the Object or in any of its
    /// ancestor keys." It is carried rather than read off the object because
    /// the ancestors are gone by the time it is asked for.
    pub state_clear: bool,
}

impl Object {
    /// Build an object and compute its Name and Qualified Name.
    pub fn new(
        public: TpmtPublic,
        sensitive: Option<TpmtSensitive>,
        hierarchy: u32,
        parent_qualified_name: &[u8],
        tpm_generated: bool,
    ) -> TpmResult<Object> {
        let name = names::object_name(&public)?;
        let qualified_name =
            names::qualified_name(public.name_alg, parent_qualified_name, &name)?;
        let state_clear = public
            .object_attributes
            .has(ObjectAttributes::ST_CLEAR);
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

    /// True when only the public area is loaded.
    pub fn is_public_only(&self) -> bool {
        self.sensitive.is_none()
    }

    /// True when the object may protect the sensitive area of a child.
    ///
    /// Part 1 clause 20.2 divides the objects that carry both restricted and
    /// decrypt into two: "Asymmetric keys and symmetric keys with these
    /// attributes are Storage Parents, and keyedHash objects with these
    /// attributes are Derivation Parents." A Derivation Parent protects
    /// nothing, it only supplies entropy, so it is not one of these.
    pub fn is_storage_key(&self) -> bool {
        self.is_storage_public() && !self.is_public_only()
    }

    /// True when the public area alone describes a Storage Key.
    ///
    /// TPM2_MakeCredential protects a credential with a key it only has the
    /// public half of, so it asks this rather than [`Object::is_storage_key`].
    pub fn is_storage_public(&self) -> bool {
        self.public
            .object_attributes
            .has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT)
            && self.public.object_type != alg::KEYEDHASH
    }

    /// True when the object derives children rather than protecting them.
    ///
    /// The same clause 20.2 sentence names these, and Part 3 clause 12.9.1 says
    /// that "if parentHandle references a Derivation Parent, then a Derived
    /// Object is generated".
    pub fn is_derivation_parent(&self) -> bool {
        self.public
            .object_attributes
            .has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT)
            && self.public.object_type == alg::KEYEDHASH
            && !self.is_public_only()
    }

    /// The authorization value of the object.
    pub fn auth_value(&self) -> &[u8] {
        match &self.sensitive {
            Some(s) => s.auth_value.as_slice(),
            None => &[],
        }
    }

    /// The seed used to protect this object's children.
    pub fn seed_value(&self) -> &[u8] {
        match &self.sensitive {
            Some(s) => s.seed_value.as_slice(),
            None => &[],
        }
    }

    /// The nameAlg, which fixes the digest used for the object's children.
    pub fn name_alg(&self) -> u16 {
        self.public.name_alg
    }
}

/// A sequence in progress, created by TPM2_HashSequenceStart,
/// TPM2_HMAC_Start or an event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequence {
    /// The kind of sequence and the state it needs.
    pub kind: SequenceKind,
    /// The authorization value given when the sequence was started.
    pub auth: Vec<u8>,
    /// Everything fed in so far.
    ///
    /// The data is buffered rather than folded into a running hash state so a
    /// sequence can be saved and reloaded by TPM2_ContextSave, which needs the
    /// state to be serialisable.
    pub buffer: Vec<u8>,
    /// Whether the first buffer given to the sequence was a short one.
    ///
    /// Part 3 clause 17.8.1: "Regardless of the contents of the first octets of
    /// the hashed message, if the first buffer sent to the TPM had fewer than
    /// sizeof(TPM_GENERATED) octets, then the TPM will operate as if digest is
    /// not safe to sign." The whole message may begin with something else, so
    /// what the first buffer held has to be remembered as it arrives.
    pub short_first_buffer: bool,
}

/// The three kinds of sequence Part 3 clause 17 defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceKind {
    /// TPM2_HashSequenceStart with a hash algorithm.
    Hash { hash_alg: u16 },
    /// TPM2_HMAC_Start, which carries the key and algorithm of the object.
    Hmac { hash_alg: u16, key: Vec<u8> },
    /// An event sequence, which feeds every allocated PCR bank.
    Event,
}

/// Largest amount a single sequence will buffer.
///
/// A sequence has no length limit in the specification, but a software TPM
/// cannot grow without bound, so a sequence that exceeds this reports
/// TPM_RC_MEMORY rather than exhausting the host.
///
/// TPM2_HashSequenceStart needs no authorization, so a caller can hold
/// `MAX_LOADED_OBJECTS` sequences at once. The bound is therefore chosen so
/// that all of them together stay well inside what a host can spare, while
/// still being far larger than the TPM2B_MAX_BUFFER a single
/// TPM2_SequenceUpdate carries.
///
/// A sequence longer than a saved context can hold cannot be swapped out, and
/// TPM2_ContextSave answers TPM_RC_SIZE for it. That is a consequence of
/// buffering the data rather than folding it into a hash state, which is what
/// makes a sequence context serialisable at all.
pub const MAX_SEQUENCE_BYTES: usize = 1024 * 1024;

impl Sequence {
    /// Append to the sequence.
    pub fn update(&mut self, data: &[u8]) -> TpmResult<()> {
        if self.buffer.len().saturating_add(data.len()) > MAX_SEQUENCE_BYTES {
            return Err(TpmRc(rc::MEMORY));
        }
        if self.buffer.is_empty() && data.len() < 4 {
            self.short_first_buffer = true;
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Whether a ticket may say the digest is safe to sign.
    ///
    /// The first buffer decides it as well as the first octets, so a sequence
    /// that was fed fewer than sizeof(TPM_GENERATED) octets to begin with is
    /// never safe.
    pub fn may_be_safe_to_sign(&self) -> bool {
        !self.short_first_buffer
    }

    /// The hash algorithm of a hash or HMAC sequence.
    pub fn hash_alg(&self) -> Option<u16> {
        match &self.kind {
            SequenceKind::Hash { hash_alg } => Some(*hash_alg),
            SequenceKind::Hmac { hash_alg, .. } => Some(*hash_alg),
            SequenceKind::Event => None,
        }
    }

    /// True when this is an event sequence.
    pub fn is_event(&self) -> bool {
        matches!(self.kind, SequenceKind::Event)
    }
}

/// What occupies a transient handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    Object(Box<Object>),
    Sequence(Box<Sequence>),
}

impl Slot {
    /// The object in this slot, or TPM_RC_HANDLE when it holds a sequence.
    pub fn as_object(&self) -> TpmResult<&Object> {
        match self {
            Slot::Object(o) => Ok(o),
            Slot::Sequence(_) => Err(TpmRc(rc::HANDLE)),
        }
    }

    /// The sequence in this slot, or TPM_RC_MODE when it holds an object.
    pub fn as_sequence(&self) -> TpmResult<&Sequence> {
        match self {
            Slot::Sequence(s) => Ok(s),
            Slot::Object(_) => Err(TpmRc(rc::MODE)),
        }
    }

    /// The sequence in this slot, for modification.
    pub fn as_sequence_mut(&mut self) -> TpmResult<&mut Sequence> {
        match self {
            Slot::Sequence(s) => Ok(s),
            Slot::Object(_) => Err(TpmRc(rc::MODE)),
        }
    }

    /// The authorization value of whatever is in the slot.
    pub fn auth_value(&self) -> &[u8] {
        match self {
            Slot::Object(o) => o.auth_value(),
            Slot::Sequence(s) => &s.auth,
        }
    }

    /// The Name of whatever is in the slot.
    ///
    /// A sequence object has no public area, so Part 1 clause 32.4.2 gives it
    /// an empty Name.
    pub fn name(&self) -> &[u8] {
        match self {
            Slot::Object(o) => &o.name,
            Slot::Sequence(_) => &[],
        }
    }
}

/// The transient object slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectSlots {
    slots: BTreeMap<u32, Slot>,
}

impl ObjectSlots {
    pub fn new() -> ObjectSlots {
        ObjectSlots::default()
    }

    /// Number of occupied slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Slots still free.
    pub fn available(&self) -> usize {
        config::MAX_LOADED_OBJECTS as usize - self.slots.len()
    }

    /// Put `slot` in the lowest free transient handle.
    pub fn insert(&mut self, slot: Slot) -> TpmResult<u32> {
        if self.slots.len() >= config::MAX_LOADED_OBJECTS as usize {
            return Err(TpmRc(rc::OBJECT_MEMORY));
        }
        for i in 0..config::MAX_LOADED_OBJECTS as u32 {
            let handle = hc::TRANSIENT_FIRST + i;
            if !self.slots.contains_key(&handle) {
                self.slots.insert(handle, slot);
                return Ok(handle);
            }
        }
        Err(TpmRc(rc::OBJECT_MEMORY))
    }

    /// Put `slot` at a specific handle, which context load needs.
    pub fn insert_at(&mut self, handle: u32, slot: Slot) -> TpmResult<()> {
        if !Self::is_transient(handle) {
            return Err(TpmRc(rc::HANDLE));
        }
        if self.slots.contains_key(&handle) {
            return Err(TpmRc(rc::HANDLE));
        }
        if self.slots.len() >= config::MAX_LOADED_OBJECTS as usize {
            return Err(TpmRc(rc::OBJECT_MEMORY));
        }
        self.slots.insert(handle, slot);
        Ok(())
    }

    pub fn get(&self, handle: u32) -> TpmResult<&Slot> {
        self.slots.get(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    pub fn get_mut(&mut self, handle: u32) -> TpmResult<&mut Slot> {
        self.slots.get_mut(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    /// The object at `handle`, or TPM_RC_HANDLE.
    pub fn object(&self, handle: u32) -> TpmResult<&Object> {
        self.get(handle)?.as_object()
    }

    /// Remove and return the slot at `handle`.
    pub fn remove(&mut self, handle: u32) -> TpmResult<Slot> {
        self.slots.remove(&handle).ok_or(TpmRc(rc::HANDLE))
    }

    /// True when the handle is in the transient range.
    pub fn is_transient(handle: u32) -> bool {
        (hc::TRANSIENT_FIRST..=hc::TRANSIENT_LAST).contains(&handle)
    }

    /// Every occupied handle, in increasing order.
    pub fn handles(&self) -> Vec<u32> {
        self.slots.keys().copied().collect()
    }

    /// Drop every object whose hierarchy is `hierarchy`.
    ///
    /// TPM2_Clear and TPM2_HierarchyControl both need this so that objects
    /// under a hierarchy that has gone away cannot still be used.
    pub fn flush_hierarchy(&mut self, hierarchy: u32) {
        self.slots.retain(|_, slot| match slot {
            Slot::Object(o) => o.hierarchy != hierarchy,
            Slot::Sequence(_) => true,
        });
    }

    /// Drop every object whose stClear attribute is set.
    pub fn flush_st_clear(&mut self) {
        self.slots.retain(|_, slot| match slot {
            Slot::Object(o) => !o
                .public
                .object_attributes
                .has(ObjectAttributes::ST_CLEAR),
            Slot::Sequence(_) => true,
        });
    }

    /// Drop everything, which a TPM Reset does.
    pub fn clear(&mut self) {
        self.slots.clear();
    }
}

/// Check that a public area is internally consistent, Part 3 clause 12.2.2.
///
/// The checks that do not depend on the parent or on other command parameters
/// live here so that TPM2_Create, TPM2_CreatePrimary, TPM2_Load and
/// TPM2_LoadExternal all apply the same rules.
///
/// The unique field is not one of them. In a creation template it holds no key,
/// and Part 3 clauses 12.2.1 and 24.1.1 both say that "the size of the unique
/// field shall not be checked for consistency with the other object
/// parameters", so a caller that sends a placeholder of the wrong size, or of
/// the right size filled with zeros, is still asking for a key the TPM can
/// make. A public area that does carry a key is checked by
/// [`validate_loaded_public`] instead.
pub fn validate_public(public: &TpmtPublic) -> TpmResult<()> {
    let attrs = public.object_attributes;

    // A restricted key must be either a signing key or a decryption key, not
    // both, and a decryption key must name a symmetric algorithm.
    let sign = attrs.has(ObjectAttributes::SIGN_ENCRYPT);
    let decrypt = attrs.has(ObjectAttributes::DECRYPT);
    if attrs.has(ObjectAttributes::RESTRICTED) && sign && decrypt {
        return Err(TpmRc(rc::ATTRIBUTES));
    }

    // fixedTPM requires fixedParent: an object that cannot leave the TPM
    // cannot be re-parented either.
    if attrs.has(ObjectAttributes::FIXED_TPM) && !attrs.has(ObjectAttributes::FIXED_PARENT) {
        return Err(TpmRc(rc::ATTRIBUTES));
    }

    // encryptedDuplication and fixedTPM cannot both be set, because an object
    // that never leaves the TPM is never duplicated.
    if attrs.has(ObjectAttributes::ENCRYPTED_DUPLICATION)
        && attrs.has(ObjectAttributes::FIXED_TPM)
    {
        return Err(TpmRc(rc::ATTRIBUTES));
    }

    // Part 3 clause 18.1: "For a restricted signing key, the key's scheme
    // cannot be TPM_ALG_NULL and cannot be overridden." A restricted key signs
    // only what the TPM itself produced, and the scheme is part of what the
    // verifier is told to expect, so leaving it open would let the caller
    // choose it later and the restriction would say nothing.
    //
    // A symmetric block cipher key is not a signing key. Part 2 clause 8.3.3.14
    // says sign/encrypt on one means permission to encrypt, and that "a
    // restricted symmetric block cipher key may only be used to encrypt a data
    // block", so that combination is a key the specification defines rather
    // than one to refuse, and it has no signing scheme to name.
    if sign && attrs.has(ObjectAttributes::RESTRICTED) && public.object_type != alg::SYMCIPHER {
        let scheme_is_null = public
            .scheme()
            .map(|s| s.is_null())
            .unwrap_or(true);
        if scheme_is_null {
            return Err(TpmRc(rc::SCHEME));
        }
    }

    // Part 2 Table 229 says of an ECC key's kdf that it belongs to "an
    // unrestricted decryption TPM_ALG_ECDH key" and "shall be NULL in all
    // other cases (TPM_RC_KDF)". Part 1 clause 44.4.1 makes that same field
    // what says the key is a KEM key, so a key that names one without being
    // able to use it describes nothing.
    if let crate::tpm::structures::keys::PublicParms::Ecc {
        scheme,
        curve_id,
        kdf,
        ..
    } = &public.parameters
    {
        if !kdf.is_null() {
            if attrs.has(ObjectAttributes::RESTRICTED) || !decrypt || scheme.scheme != alg::ECDH {
                return Err(TpmRc(rc::KDF));
            }
            // The field names a KEM, so it has to name one this TPM can run on
            // this curve. Table 229 answers a KDF the TPM does not support with
            // TPM_RC_KDF at the point the key is described.
            if !crate::tpm::crypto::dhkem::is_kem_suite(*curve_id, kdf) {
                return Err(TpmRc(rc::KDF));
            }
        }
    }

    // The name algorithm must be a hash unless the object cannot be a parent.
    if public.name_alg == alg::NULL
        && attrs.has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::HASH));
    }

    // Part 3 clause 12.3 says the TPM validates that the authPolicy is either
    // the size of the digest produced by nameAlg or the Empty Buffer. A policy
    // of any other length can never match the digest a session accumulates, so
    // the object would be loaded and then be unusable through the policy it
    // claims to have.
    if !public.auth_policy.is_empty() {
        let want = match crate::tpm::crypto::hash::digest_size(public.name_alg) {
            Ok(size) => size,
            // With no name algorithm there is no digest, so no policy fits.
            Err(_) => return Err(TpmRc(rc::SIZE)),
        };
        if public.auth_policy.as_slice().len() != want {
            return Err(TpmRc(rc::SIZE));
        }
    }

    Ok(())
}

/// Check a template the TPM is about to make an object from.
///
/// TPM2_Create, TPM2_CreatePrimary and TPM2_CreateLoaded share the rules of
/// Part 3 clause 12.1, which are stricter than the ones an already made object
/// has to satisfy when it is loaded.
pub fn validate_creation_template(public: &TpmtPublic) -> TpmResult<()> {
    validate_public(public)?;
    validate_action_attributes(public)
}

/// What an object is allowed to do, for the commands that say so.
///
/// Part 3 states the first rule twice in the same words, in clause 12.1.1 for
/// TPM2_Create and TPM2_CreatePrimary and in clause 12.2.1 for TPM2_Load: "If
/// the Object is a not a keyedHash object, and the sign and encrypt attributes
/// are CLEAR, the TPM shall return TPM_RC_ATTRIBUTES." Only a keyed hash object
/// is allowed to be inert, because that is what a sealed data object is.
///
/// The second is Part 2 clause 8.3.3.12, which says restricted "shall be CLEAR
/// in template if neither sign nor decrypt is SET in template" on creation and
/// "shall be CLEAR if neither sign nor decrypt is SET in the object" on load.
/// restricted only qualifies what signing or decryption may do, so on an object
/// that does neither it describes nothing. A sealed data object is exactly a
/// keyed hash with both clear, so this is the rule that keeps one from claiming
/// to be restricted.
///
/// Neither is stated for TPM2_LoadExternal, and clause 8.3.3.12 gives
/// TPM2_Import its own answer of "may be SET or CLEAR", so neither command
/// applies these.
pub fn validate_action_attributes(public: &TpmtPublic) -> TpmResult<()> {
    let attrs = public.object_attributes;
    if public.object_type != alg::KEYEDHASH
        && !attrs.has(ObjectAttributes::SIGN_ENCRYPT)
        && !attrs.has(ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES));
    }
    validate_restricted_has_an_action(public)
}

/// Refuse restricted on an object that neither signs nor decrypts.
///
/// This is the clause 8.3.3.12 half of [`validate_action_attributes`], kept
/// apart because it is the half that holds however the object arrived. Creation
/// and load both require it; TPM2_LoadExternal requires restricted to be CLEAR
/// outright when a sensitive area comes with the public one and reads no
/// attribute column at all when it does not, so an external object satisfies it
/// either way; and an object TPM2_Import accepts with restricted SET has to be
/// loaded before it can be used, which applies the rule then.
pub fn validate_restricted_has_an_action(public: &TpmtPublic) -> TpmResult<()> {
    let attrs = public.object_attributes;
    if attrs.has(ObjectAttributes::RESTRICTED)
        && !attrs.has(ObjectAttributes::SIGN_ENCRYPT)
        && !attrs.has(ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES));
    }
    Ok(())
}

/// Check an object a state file or a saved context gave back.
///
/// The blob was written by whatever build was running then, so what it holds is
/// checked rather than trusted. What can be checked is what is true of every
/// resident object however it arrived: the key material has to agree with the
/// parameters beside it, and a sensitive area has to belong to its public one.
///
/// Not the attribute rules. Part 2 clause 8.3.3.1 gives each of TPM2_Create,
/// TPM2_Load, TPM2_Import and TPM2_LoadExternal its own column of the attribute
/// table, and clause 8.3.3.1 exempts a public area loaded on its own from every
/// entry in the External column, so the same attributes are legal through one
/// command and not through another. A saved object does not record which
/// command admitted it, so applying any of those columns here would refuse
/// something that was resident legitimately, which would lose a caller's state
/// on a restart.
pub fn validate_restored(
    public: &TpmtPublic,
    sensitive: Option<&TpmtSensitive>,
) -> TpmResult<()> {
    validate_loaded_public(public)?;
    if let Some(sensitive) = sensitive {
        check_binding(public, sensitive)?;
    }
    Ok(())
}

/// Check a public area that carries a key, for TPM2_Load and TPM2_LoadExternal.
///
/// These are the checks of the unique field that a creation template is exempt
/// from. Here the field is the key itself rather than a placeholder, so a value
/// that disagrees with the parameters beside it describes an object the TPM
/// could never use.
pub fn validate_loaded_public(public: &TpmtPublic) -> TpmResult<()> {
    validate_public(public)?;

    // Part 2 Table 195 defines keyBits as the number of bits in the public
    // modulus, and Part 3 clause 12.2 requires the key size to agree with the
    // public area or the answer is TPM_RC_KEY_SIZE. The count is of the bits
    // the modulus actually has, not of the octets it was sent in, so a 2047
    // bit modulus does not pass as a 2048 bit one just by being padded.
    if let (
        crate::tpm::structures::keys::PublicId::Rsa(modulus),
        crate::tpm::structures::keys::PublicParms::Rsa { key_bits, .. },
    ) = (&public.unique, &public.parameters)
    {
        if !modulus.is_empty() && significant_bits(modulus.as_slice()) != *key_bits as usize {
            return Err(TpmRc(rc::KEY_SIZE));
        }
    }

    // An ECC public area names a point, and a point that is not on the curve is
    // not a public key. Every use of it fails later anyway, because the point
    // is validated whenever it is loaded into the library, but a key the TPM
    // accepted has a Name that stands for nothing, so it is refused here.
    if let (
        crate::tpm::structures::keys::PublicId::Ecc(point),
        crate::tpm::structures::keys::PublicParms::Ecc { curve_id, .. },
    ) = (&public.unique, &public.parameters)
    {
        if !point.x.is_empty() || !point.y.is_empty() {
            let curve = crate::tpm::crypto::ecc::Curve::new(*curve_id)?;
            crate::tpm::crypto::ecc::Point::from_coordinates(
                &curve,
                point.x.as_slice(),
                point.y.as_slice(),
            )?;
        }
    }

    Ok(())
}

/// The number of bits in a big endian integer, ignoring leading zero octets.
pub fn significant_bits(bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    if i == bytes.len() {
        return 0;
    }
    (bytes.len() - i - 1) * 8 + (8 - bytes[i].leading_zeros() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{curve, rh};
    use crate::tpm::structures::base::Tpm2bDigest;
    use crate::tpm::structures::keys::{PublicId, PublicParms};
    use crate::tpm::structures::schemes::{Scheme, SymDef};

    fn public(attrs: u32) -> TpmtPublic {
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
            unique: PublicId::Ecc(Default::default()),
        }
    }

    fn object(attrs: u32) -> Object {
        Object::new(public(attrs), None, rh::OWNER, &rh::OWNER.to_be_bytes(), true).unwrap()
    }

    /// A symmetric block cipher key with the given attributes.
    fn symcipher(attrs: u32) -> TpmtPublic {
        TpmtPublic {
            object_type: alg::SYMCIPHER,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(attrs),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::SymCipher {
                sym: SymDef::new(alg::AES, 128, alg::CFB),
            },
            unique: PublicId::Sym(Default::default()),
        }
    }

    #[test]
    fn a_restricted_symmetric_key_may_encrypt() {
        // Part 2 clause 8.3.3.14: sign/encrypt on a symmetric block cipher key
        // means permission to encrypt, and "a restricted symmetric block cipher
        // key may only be used to encrypt a data block". It is a key the
        // specification defines rather than one to refuse, and it has no
        // signing scheme to name.
        let public = symcipher(
            ObjectAttributes::SIGN_ENCRYPT
                | ObjectAttributes::RESTRICTED
                | ObjectAttributes::USER_WITH_AUTH,
        );
        assert!(validate_public(&public).is_ok());
        assert!(validate_action_attributes(&public).is_ok());
    }

    #[test]
    fn restricted_says_nothing_on_an_object_that_neither_signs_nor_decrypts() {
        // Part 2 clause 8.3.3.12: restricted "shall be CLEAR in template if
        // neither sign nor decrypt is SET in template" on creation and "shall
        // be CLEAR if neither sign nor decrypt is SET in the object" on load. A
        // sealed data object is a keyed hash with both clear, so this is what
        // keeps one from claiming to be restricted.
        let sealed = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::RESTRICTED | ObjectAttributes::USER_WITH_AUTH,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme::null(),
            },
            unique: PublicId::KeyedHash(Default::default()),
        };
        assert_eq!(
            validate_action_attributes(&sealed).unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );
        // Without restricted the same object is an ordinary sealed one.
        let mut plain = sealed.clone();
        plain.object_attributes = ObjectAttributes(ObjectAttributes::USER_WITH_AUTH);
        assert!(validate_action_attributes(&plain).is_ok());
    }

    #[test]
    fn a_restricted_signing_key_still_needs_a_scheme() {
        // The rule of Part 3 clause 18.1 is about signing keys, so narrowing it
        // away from the symmetric case must not have loosened it here.
        let mut public = public(
            ObjectAttributes::SIGN_ENCRYPT
                | ObjectAttributes::RESTRICTED
                | ObjectAttributes::USER_WITH_AUTH,
        );
        assert!(validate_public(&public).is_ok());
        public.parameters = PublicParms::Ecc {
            symmetric: SymDef::null(),
            scheme: Scheme::null(),
            curve_id: curve::NIST_P256,
            kdf: Scheme::null(),
        };
        assert_eq!(validate_public(&public).unwrap_err(), TpmRc(rc::SCHEME));
    }

    fn sequence() -> Slot {
        Slot::Sequence(Box::new(Sequence {
            kind: SequenceKind::Hash {
                hash_alg: alg::SHA256,
            },
            auth: b"auth".to_vec(),
            buffer: Vec::new(),
            short_first_buffer: false,
        }))
    }

    #[test]
    fn an_object_carries_its_name_and_qualified_name() {
        let o = object(ObjectAttributes::SIGN_ENCRYPT);
        assert_eq!(o.name, names::object_name(&o.public).unwrap());
        assert_eq!(o.name.len(), 34);
        assert_eq!(o.qualified_name.len(), 34);
        assert!(o.is_public_only());
        assert_eq!(o.auth_value(), b"");
        assert_eq!(o.name_alg(), alg::SHA256);
    }

    #[test]
    fn slots_are_allocated_from_the_transient_range() {
        let mut slots = ObjectSlots::new();
        let a = slots
            .insert(Slot::Object(Box::new(object(ObjectAttributes::SIGN_ENCRYPT))))
            .unwrap();
        let b = slots.insert(sequence()).unwrap();
        assert_eq!(a, hc::TRANSIENT_FIRST);
        assert_eq!(b, hc::TRANSIENT_FIRST + 1);
        assert!(ObjectSlots::is_transient(a));
        assert_eq!(slots.len(), 2);
        assert_eq!(slots.handles(), vec![a, b]);
    }

    #[test]
    fn a_freed_handle_is_reused() {
        let mut slots = ObjectSlots::new();
        let a = slots
            .insert(Slot::Object(Box::new(object(ObjectAttributes::SIGN_ENCRYPT))))
            .unwrap();
        let _b = slots.insert(sequence()).unwrap();
        slots.remove(a).unwrap();
        let c = slots.insert(sequence()).unwrap();
        assert_eq!(c, a);
    }

    #[test]
    fn the_slot_count_is_bounded() {
        let mut slots = ObjectSlots::new();
        for _ in 0..config::MAX_LOADED_OBJECTS {
            slots.insert(sequence()).unwrap();
        }
        assert_eq!(slots.available(), 0);
        assert_eq!(slots.insert(sequence()).unwrap_err(), TpmRc(rc::OBJECT_MEMORY));
    }

    #[test]
    fn an_unknown_handle_reports_tpm_rc_handle() {
        let slots = ObjectSlots::new();
        assert_eq!(slots.get(hc::TRANSIENT_FIRST).unwrap_err(), TpmRc(rc::HANDLE));
        assert_eq!(
            slots.object(hc::TRANSIENT_FIRST).unwrap_err(),
            TpmRc(rc::HANDLE)
        );
    }

    #[test]
    fn a_sequence_slot_is_not_an_object() {
        let mut slots = ObjectSlots::new();
        let h = slots.insert(sequence()).unwrap();
        assert_eq!(slots.object(h).unwrap_err(), TpmRc(rc::HANDLE));
        assert!(slots.get(h).unwrap().as_sequence().is_ok());
        assert_eq!(slots.get(h).unwrap().auth_value(), b"auth");
        assert!(slots.get(h).unwrap().name().is_empty());

        let o = slots
            .insert(Slot::Object(Box::new(object(ObjectAttributes::SIGN_ENCRYPT))))
            .unwrap();
        assert_eq!(
            slots.get(o).unwrap().as_sequence().unwrap_err(),
            TpmRc(rc::MODE)
        );
    }

    #[test]
    fn insert_at_places_a_slot_at_a_chosen_handle() {
        let mut slots = ObjectSlots::new();
        let handle = hc::TRANSIENT_FIRST + 3;
        slots.insert_at(handle, sequence()).unwrap();
        assert!(slots.get(handle).is_ok());
        // The same handle cannot be taken twice.
        assert_eq!(
            slots.insert_at(handle, sequence()).unwrap_err(),
            TpmRc(rc::HANDLE)
        );
        // Only transient handles are allowed.
        assert_eq!(
            slots.insert_at(hc::PERSISTENT_FIRST, sequence()).unwrap_err(),
            TpmRc(rc::HANDLE)
        );
    }

    #[test]
    fn flushing_a_hierarchy_leaves_sequences_alone() {
        let mut slots = ObjectSlots::new();
        let owner = slots
            .insert(Slot::Object(Box::new(object(ObjectAttributes::SIGN_ENCRYPT))))
            .unwrap();
        let mut other = object(ObjectAttributes::SIGN_ENCRYPT);
        other.hierarchy = rh::PLATFORM;
        let platform = slots.insert(Slot::Object(Box::new(other))).unwrap();
        let seq = slots.insert(sequence()).unwrap();

        slots.flush_hierarchy(rh::OWNER);
        assert!(slots.get(owner).is_err());
        assert!(slots.get(platform).is_ok());
        assert!(slots.get(seq).is_ok());
    }

    #[test]
    fn flushing_st_clear_drops_only_marked_objects() {
        let mut slots = ObjectSlots::new();
        let plain = slots
            .insert(Slot::Object(Box::new(object(ObjectAttributes::SIGN_ENCRYPT))))
            .unwrap();
        let marked = slots
            .insert(Slot::Object(Box::new(object(
                ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::ST_CLEAR,
            ))))
            .unwrap();
        slots.flush_st_clear();
        assert!(slots.get(plain).is_ok());
        assert!(slots.get(marked).is_err());
    }

    #[test]
    fn sequences_buffer_their_input() {
        let mut s = Sequence {
            kind: SequenceKind::Hash {
                hash_alg: alg::SHA256,
            },
            auth: Vec::new(),
            buffer: Vec::new(),
            short_first_buffer: false,
        };
        s.update(b"abc").unwrap();
        s.update(b"def").unwrap();
        assert_eq!(s.buffer, b"abcdef");
        assert_eq!(s.hash_alg(), Some(alg::SHA256));
        assert!(!s.is_event());

        let e = Sequence {
            kind: SequenceKind::Event,
            auth: Vec::new(),
            buffer: Vec::new(),
            short_first_buffer: false,
        };
        assert!(e.is_event());
        assert_eq!(e.hash_alg(), None);
    }

    #[test]
    fn a_sequence_is_bounded() {
        let mut s = Sequence {
            kind: SequenceKind::Event,
            auth: Vec::new(),
            buffer: vec![0u8; MAX_SEQUENCE_BYTES],
            short_first_buffer: false,
        };
        assert_eq!(s.update(b"x").unwrap_err(), TpmRc(rc::MEMORY));
    }

    #[test]
    fn public_area_consistency_rules() {
        // A restricted key cannot both sign and decrypt.
        assert_eq!(
            validate_public(&public(
                ObjectAttributes::RESTRICTED
                    | ObjectAttributes::SIGN_ENCRYPT
                    | ObjectAttributes::DECRYPT
            ))
            .unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );
        // fixedTPM without fixedParent is refused.
        assert_eq!(
            validate_public(&public(ObjectAttributes::FIXED_TPM)).unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );
        // encryptedDuplication with fixedTPM is refused.
        assert_eq!(
            validate_public(&public(
                ObjectAttributes::FIXED_TPM
                    | ObjectAttributes::FIXED_PARENT
                    | ObjectAttributes::ENCRYPTED_DUPLICATION
            ))
            .unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );
        // A parent needs a name algorithm.
        let mut p = public(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT);
        p.name_alg = alg::NULL;
        assert_eq!(validate_public(&p).unwrap_err(), TpmRc(rc::HASH));
        // An ordinary signing key passes.
        assert!(validate_public(&public(
            ObjectAttributes::FIXED_TPM
                | ObjectAttributes::FIXED_PARENT
                | ObjectAttributes::SIGN_ENCRYPT
        ))
        .is_ok());
    }

    /// An RSA public area whose modulus is not the length keyBits names.
    fn rsa_public(key_bits: u16, modulus_bytes: usize) -> TpmtPublic {
        use crate::tpm::structures::base::Tpm2bPublicKeyRsa;
        use crate::tpm::structures::schemes::{Scheme, SymDef};
        TpmtPublic {
            object_type: alg::RSA,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::SIGN_ENCRYPT),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Rsa {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::RSAPSS, alg::SHA256),
                key_bits,
                exponent: 0,
            },
            unique: PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&vec![0xab; modulus_bytes]).unwrap()),
        }
    }

    #[test]
    fn an_rsa_modulus_must_be_the_length_key_bits_names() {
        // Part 2 Table 195 makes keyBits the number of bits in the public
        // modulus, so a public area that says 4096 while carrying a 2048 bit
        // modulus is refused rather than loaded.
        assert_eq!(
            validate_loaded_public(&rsa_public(4096, 256)).unwrap_err(),
            TpmRc(rc::KEY_SIZE)
        );
        // The other direction is refused too.
        assert_eq!(
            validate_loaded_public(&rsa_public(2048, 512)).unwrap_err(),
            TpmRc(rc::KEY_SIZE)
        );
        // A modulus of the stated length is accepted.
        assert!(validate_loaded_public(&rsa_public(2048, 256)).is_ok());
    }

    #[test]
    fn a_creation_template_keeps_whatever_unique_field_it_was_sent() {
        use crate::tpm::structures::base::Tpm2bPublicKeyRsa;
        // Part 3 clauses 12.2.1 and 24.1.1: "The size of the unique field shall
        // not be checked for consistency with the other object parameters."
        // TPM2_Create, TPM2_CreatePrimary and TPM2_CreateLoaded are making the
        // key, so the field holds no key to disagree with them.

        // An Empty Buffer is a legal unique field value, clause 24.1.1.
        let mut template = rsa_public(2048, 256);
        template.unique = PublicId::Rsa(Default::default());
        assert!(validate_public(&template).is_ok());

        // Windows sends a placeholder of the full modulus length filled with
        // zeros. Counted in bits that is a modulus of 0, which is not 2048, so
        // checking it here would refuse every key Windows asks for.
        let zeros = vec![0u8; 256];
        let mut template = rsa_public(2048, 256);
        template.unique = PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&zeros).unwrap());
        assert_eq!(significant_bits(&zeros), 0);
        assert!(
            validate_public(&template).is_ok(),
            "a zero filled unique field was checked against keyBits"
        );

        // A placeholder of some other size is not checked either, since it is
        // the size the clauses above name.
        let mut template = rsa_public(2048, 256);
        template.unique = PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&[0xab; 128]).unwrap());
        assert!(validate_public(&template).is_ok());

        // The same exemption covers an ECC point that is not on the curve.
        use crate::tpm::structures::base::Tpm2bEccParameter;
        use crate::tpm::structures::schemes::EccPoint;
        let mut template = public(ObjectAttributes::SIGN_ENCRYPT);
        template.unique = PublicId::Ecc(EccPoint {
            x: Tpm2bEccParameter::new(vec![0u8; 32]).unwrap(),
            y: Tpm2bEccParameter::new(vec![0u8; 32]).unwrap(),
        });
        assert!(validate_public(&template).is_ok());
    }

    #[test]
    fn an_rsa_modulus_is_counted_in_bits_not_octets() {
        use crate::tpm::structures::base::Tpm2bPublicKeyRsa;
        // A 2047 bit modulus fits in 256 octets, so counting octets would let
        // it pass as a 2048 bit key. Counting bits refuses it.
        let mut short = vec![0xabu8; 256];
        short[0] = 0x7f;
        let mut p = rsa_public(2048, 256);
        p.unique = PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&short).unwrap());
        assert_eq!(significant_bits(&short), 2047);
        assert_eq!(validate_loaded_public(&p).unwrap_err(), TpmRc(rc::KEY_SIZE));

        // Leading zero octets do not make a modulus longer either.
        let mut padded = vec![0u8; 256];
        padded[128] = 0x80;
        let mut p = rsa_public(2048, 256);
        p.unique = PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&padded).unwrap());
        assert_eq!(significant_bits(&padded), 1024);
        assert_eq!(validate_loaded_public(&p).unwrap_err(), TpmRc(rc::KEY_SIZE));

        // A modulus with its top bit set is the stated length.
        let mut full = vec![0xabu8; 256];
        full[0] = 0x80;
        let mut p = rsa_public(2048, 256);
        p.unique = PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&full).unwrap());
        assert_eq!(significant_bits(&full), 2048);
        assert!(validate_loaded_public(&p).is_ok());
    }

    #[test]
    fn an_auth_policy_must_be_the_size_of_the_name_digest() {
        use crate::tpm::structures::base::Tpm2bDigest;
        // Part 3 clause 12.3: the authPolicy is either the size of the digest
        // produced by nameAlg or the Empty Buffer.
        let with_policy = |alg: u16, len: usize| {
            let mut p = public(ObjectAttributes::SIGN_ENCRYPT);
            p.name_alg = alg;
            p.auth_policy = Tpm2bDigest::new(vec![0xaa; len]).unwrap();
            p
        };
        // The right size for the algorithm named is accepted.
        assert!(validate_public(&with_policy(alg::SHA256, 32)).is_ok());
        assert!(validate_public(&with_policy(alg::SHA384, 48)).is_ok());
        // A digest of another algorithm is not.
        assert_eq!(
            validate_public(&with_policy(alg::SHA256, 20)).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        assert_eq!(
            validate_public(&with_policy(alg::SHA256, 48)).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        // An empty policy is always allowed.
        let mut p = public(ObjectAttributes::SIGN_ENCRYPT);
        p.auth_policy = Tpm2bDigest::empty();
        assert!(validate_public(&p).is_ok());
        // With no name algorithm there is no digest, so no policy fits.
        assert_eq!(
            validate_public(&with_policy(alg::NULL, 32)).unwrap_err(),
            TpmRc(rc::SIZE)
        );
    }

    #[test]
    fn an_ecc_public_point_must_be_on_its_curve() {
        use crate::tpm::structures::base::Tpm2bEccParameter;
        use crate::tpm::structures::schemes::EccPoint;

        let with_point = |x: Vec<u8>, y: Vec<u8>| {
            let mut p = public(ObjectAttributes::SIGN_ENCRYPT);
            p.unique = PublicId::Ecc(EccPoint {
                x: Tpm2bEccParameter::new(x).unwrap(),
                y: Tpm2bEccParameter::new(y).unwrap(),
            });
            p
        };

        // A point that does not satisfy the curve equation is refused.
        let bad = with_point(vec![0x11; 32], vec![0x22; 32]);
        assert_eq!(
            validate_loaded_public(&bad).unwrap_err(),
            TpmRc(rc::ECC_POINT),
            "an off curve point was accepted"
        );

        // So is one whose coordinates are not the right size for the curve.
        assert!(validate_loaded_public(&with_point(vec![0x01; 8], vec![0x02; 8])).is_err());

        // A real point on P-256 is accepted.
        let mut rng = crate::tpm::crypto::rand::Drbg::new(&[0x77u8; 48], b"t").unwrap();
        let key = crate::tpm::crypto::ecc::generate(curve::NIST_P256, &mut rng).unwrap();
        assert!(
            validate_loaded_public(&with_point(key.public_x.clone(), key.public_y.clone())).is_ok()
        );

        // A creation template names no point yet, so it is left alone.
        assert!(validate_public(&public(ObjectAttributes::SIGN_ENCRYPT)).is_ok());
    }

    #[test]
    fn significant_bits_counts_what_is_there() {
        assert_eq!(significant_bits(&[]), 0);
        assert_eq!(significant_bits(&[0x00]), 0);
        assert_eq!(significant_bits(&[0x00, 0x00]), 0);
        assert_eq!(significant_bits(&[0x01]), 1);
        assert_eq!(significant_bits(&[0x7f]), 7);
        assert_eq!(significant_bits(&[0x80]), 8);
        assert_eq!(significant_bits(&[0xff]), 8);
        assert_eq!(significant_bits(&[0x01, 0x00]), 9);
        assert_eq!(significant_bits(&[0x00, 0x80]), 8);
        assert_eq!(significant_bits(&[0xff, 0xff]), 16);
    }
}

/// Check that a sensitive area belongs with a public area.
///
/// Part 3 clause 12.2.1 answers TPM_RC_BINDING when the two do not go
/// together. For a keyed hash or a symmetric key the public unique value is
/// the obfuscated digest of the secret, and for an asymmetric key the public
/// value is recomputed from the private one.
pub fn check_binding(public: &TpmtPublic, sensitive: &TpmtSensitive) -> TpmResult<()> {
    use crate::tpm::crypto::{bn, ecc, rsa};
    use crate::tpm::structures::keys::{PublicId, PublicParms, SensitiveComposite};

    if sensitive.sensitive_type != public.object_type {
        return Err(TpmRc(rc::TYPE));
    }
    let bad = || TpmRc(rc::BINDING);
    match (&public.unique, &sensitive.sensitive) {
        (PublicId::KeyedHash(unique), SensitiveComposite::Bits(bits)) => {
            check_obfuscated(public.name_alg, unique.as_slice(), sensitive.seed_value.as_slice(), bits.as_slice())
        }
        (PublicId::Sym(unique), SensitiveComposite::Sym(key)) => {
            check_obfuscated(public.name_alg, unique.as_slice(), sensitive.seed_value.as_slice(), key.as_slice())
        }
        (PublicId::Rsa(modulus), SensitiveComposite::Rsa(prime)) => {
            let PublicParms::Rsa { exponent, .. } = public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            // The prime has to divide the modulus, which is what makes it the
            // private half of this key.
            let key = rsa::RsaPrivate::from_prime(modulus.as_slice(), exponent, prime.as_slice())
                .map_err(|_| bad())?;
            let _ = key;
            Ok(())
        }
        (PublicId::Ecc(point), SensitiveComposite::Ecc(scalar)) => {
            let PublicParms::Ecc { curve_id, .. } = public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let curve = ecc::Curve::new(curve_id).map_err(|_| bad())?;
            let private = bn::BigNum::from_bytes(scalar.as_slice()).map_err(|_| bad())?;
            let computed = ecc::multiply_generator(&curve, &private).map_err(|_| bad())?;
            let (x, y) = computed.coordinates(&curve).map_err(|_| bad())?;
            if x != point.x.as_slice() || y != point.y.as_slice() {
                return Err(bad());
            }
            Ok(())
        }
        _ => Err(TpmRc(rc::TYPE)),
    }
}

/// The unique value of a keyed hash or symmetric object.
///
/// Part 1 clause 25.2.2 obfuscates the secret with the seed so the public area
/// binds to it without revealing it.
fn check_obfuscated(
    name_alg: u16,
    unique: &[u8],
    seed: &[u8],
    secret: &[u8],
) -> TpmResult<()> {
    let expected = crate::tpm::crypto::hash::digest_parts(name_alg, &[seed, secret])?;
    if unique != expected {
        return Err(TpmRc(rc::BINDING));
    }
    Ok(())
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use crate::tpm::crypto::hash;
    use crate::tpm::structures::base::{Tpm2bDigest, Tpm2bSensitiveData};
    use crate::tpm::structures::keys::{PublicId, PublicParms, SensitiveComposite};
    use crate::tpm::structures::schemes::Scheme;

    fn keyed_hash(seed: &[u8], secret: &[u8], unique: Vec<u8>) -> (TpmtPublic, TpmtSensitive) {
        let public = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::USER_WITH_AUTH),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme::null(),
            },
            unique: PublicId::KeyedHash(Tpm2bDigest::new(unique).unwrap()),
        };
        let sensitive = TpmtSensitive {
            sensitive_type: alg::KEYEDHASH,
            auth_value: Tpm2bDigest::empty(),
            seed_value: Tpm2bDigest::from_slice(seed).unwrap(),
            sensitive: SensitiveComposite::Bits(Tpm2bSensitiveData::from_slice(secret).unwrap()),
        };
        (public, sensitive)
    }

    #[test]
    fn a_sensitive_area_has_to_belong_with_its_public_area() {
        let seed = [1u8; 32];
        let secret = b"the sealed value";
        let unique = hash::digest_parts(alg::SHA256, &[&seed, secret]).unwrap();

        // Part 1 clause 25.2.2 obfuscates the secret into the unique value, so
        // a matching pair is accepted.
        let (public, sensitive) = keyed_hash(&seed, secret, unique.clone());
        check_binding(&public, &sensitive).unwrap();

        // A different secret under the same public area is refused, which is
        // what Part 3 clause 12.2.1 answers TPM_RC_BINDING for.
        let (public, sensitive) = keyed_hash(&seed, b"another value", unique.clone());
        assert_eq!(
            check_binding(&public, &sensitive).unwrap_err(),
            TpmRc(rc::BINDING)
        );

        // So is the right secret under a different seed.
        let (public, sensitive) = keyed_hash(&[2u8; 32], secret, unique);
        assert_eq!(
            check_binding(&public, &sensitive).unwrap_err(),
            TpmRc(rc::BINDING)
        );
    }

    #[test]
    fn a_sensitive_area_of_the_wrong_type_is_refused() {
        let seed = [1u8; 32];
        let secret = b"value";
        let unique = hash::digest_parts(alg::SHA256, &[&seed, secret]).unwrap();
        let (public, mut sensitive) = keyed_hash(&seed, secret, unique);
        sensitive.sensitive_type = alg::RSA;
        assert_eq!(
            check_binding(&public, &sensitive).unwrap_err(),
            TpmRc(rc::TYPE)
        );
    }
}
