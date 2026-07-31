//! Hashing, signing, asymmetric operations and symmetric encryption.
//!
//! These are the commands of Part 3 clauses 13 to 15 and 17.

use crate::tpm::config;
use crate::tpm::constants::{alg, rc, rh, st};
use crate::tpm::core::object::{Object, Sequence, SequenceKind, Slot};
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{ecc, hash, hmac as mac, rand::Rng, rsa, sym};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attributes::ObjectAttributes;
use crate::tpm::structures::base::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bIv, Tpm2bMaxBuffer, Tpm2bPublicKeyRsa, Tpm2bSensitiveData,
    TpmtHa,
};
use crate::tpm::structures::keys::{PublicId, PublicParms};
use crate::tpm::structures::lists::TpmlDigestValues;
use crate::tpm::structures::schemes::{EccPoint, Scheme, Tpm2bEccPoint};
use crate::tpm::structures::signature::{
    SignatureEcc, SignatureRsa, SignatureValue, Ticket, TpmtSignature, VerifiedTicket,
};

use super::dispatch::{Request, Response};
use super::execute::{respond, respond_with_handle};

/// The object a command names, transient or persistent.
fn object_of(state: &TpmState, handle: u32) -> TpmResult<&Object> {
    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle)
    } else if (crate::tpm::constants::hc::PERSISTENT_FIRST
        ..=crate::tpm::constants::hc::PERSISTENT_LAST)
        .contains(&handle)
    {
        state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))
    } else {
        Err(TpmRc(rc::HANDLE))
    }
}

/// TPM2_Hash, Part 3 clause 15.4.
pub fn hash_command(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let data = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    let hash_alg = r.u16()?;
    let hierarchy = r.u32()?;
    r.expect_end()?;

    let digest = hash::digest(hash_alg, data.as_slice())
        .map_err(|_| TpmRc(rc::HASH).with_parameter(2))?;
    let ticket = hash_ticket(state, hierarchy, hash_alg, data.as_slice(), &digest)?;
    respond(move |w| {
        Tpm2bDigest::new(digest)?.marshal(w);
        ticket.marshal(w);
        Ok(())
    })
}

/// The hash check ticket of Part 3 clause 15.4.
///
/// The ticket says the TPM produced the digest and that the data did not start
/// with TPM_GENERATED_VALUE, so it cannot be a forged attestation.
fn hash_ticket(
    state: &TpmState,
    hierarchy: u32,
    hash_alg: u16,
    data: &[u8],
    digest: &[u8],
) -> TpmResult<Ticket> {
    let safe = data.len() < 4
        || u32::from_be_bytes([data[0], data[1], data[2], data[3]])
            != crate::tpm::constants::TPM_GENERATED_VALUE;
    if hierarchy == rh::NULL || !safe {
        return Ok(Ticket::null(st::HASHCHECK));
    }
    let proof = state.hierarchy_proof(hierarchy)?.to_vec();
    let hmac = mac::hmac_parts(
        config::CONTEXT_INTEGRITY_HASH_ALG,
        &proof,
        &[
            &st::HASHCHECK.to_be_bytes(),
            &hash_alg.to_be_bytes(),
            digest,
        ],
    )?;
    Ok(Ticket {
        tag: st::HASHCHECK,
        hierarchy,
        digest: Tpm2bDigest::new(hmac)?,
    })
}

/// Check a TPMT_TK_HASHCHECK against the digest it is meant to cover.
///
/// Part 3 clause 20.5.1 uses the ticket as proof that the TPM produced the
/// digest with `hash_alg` and that the hashed data did not start with
/// TPM_GENERATED_VALUE. `parameter` names the ticket in an error.
pub fn verify_hash_ticket(
    state: &TpmState,
    validation: &Ticket,
    hash_alg: u16,
    digest: &[u8],
    parameter: usize,
) -> TpmResult<()> {
    let reject = || TpmRc(rc::TICKET).with_parameter(parameter);
    if validation.digest.is_empty() {
        return Err(reject());
    }
    let proof = state
        .hierarchy_proof(validation.hierarchy)
        .map_err(|_| reject())?
        .to_vec();
    let expected = mac::hmac_parts(
        config::CONTEXT_INTEGRITY_HASH_ALG,
        &proof,
        &[
            &st::HASHCHECK.to_be_bytes(),
            &hash_alg.to_be_bytes(),
            digest,
        ],
    )?;
    if !crate::tpm::core::protect::constant_time_eq(&expected, validation.digest.as_slice()) {
        return Err(reject());
    }
    Ok(())
}

/// True when the object signs with HMAC.
///
/// Part 3 Table 115 splits the signing commands by whether the algorithm signs
/// a message or a digest, and HMAC is the one message algorithm this TPM
/// implements. A keyed hash object whose scheme is not HMAC is an obfuscation
/// key rather than a signing key, so it is not one of these.
pub fn signs_a_message(object: &Object) -> bool {
    if object.public.object_type != alg::KEYEDHASH {
        return false;
    }
    matches!(
        &object.public.parameters,
        PublicParms::KeyedHash { scheme } if scheme.scheme == alg::HMAC
    )
}

/// Check that an object may perform a signing command.
///
/// Part 3 clause 20.5.1 answers TPM_RC_KEY unless the sign attribute is SET,
/// and TPM_RC_ATTRIBUTES when x509sign is, because such a key signs only X.509
/// certificates. Table 115 gives message signing to HMAC alone, so a keyed
/// hash object with any other scheme is not a signing key at all. The errors
/// carry no handle number; the caller adds the one its table gives.
pub fn check_signing_key(object: &Object) -> TpmResult<()> {
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::SIGN_ENCRYPT)
    {
        return Err(TpmRc(rc::KEY));
    }
    if object.public.object_attributes.has(ObjectAttributes::X509_SIGN) {
        return Err(TpmRc(rc::ATTRIBUTES));
    }
    if object.public.object_type == alg::KEYEDHASH && !signs_a_message(object) {
        return Err(TpmRc(rc::KEY));
    }
    if object.sensitive.is_none() {
        return Err(TpmRc(rc::KEY));
    }
    Ok(())
}

/// Sign a whole message, Part 3 Table 115.
///
/// An HMAC key takes the message itself. Every other algorithm signs the
/// digest of the message under the hash of its scheme.
pub fn sign_message(
    state: &mut TpmState,
    object: &Object,
    scheme: &Scheme,
    message: &[u8],
) -> TpmResult<TpmtSignature> {
    if !signs_a_message(object) {
        let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME))?;
        let digest = hash::digest(hash_alg, message)?;
        return sign_digest(state, object, scheme, &digest);
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME))?;
    Ok(TpmtSignature {
        sig_alg: alg::HMAC,
        signature: SignatureValue::Hmac(TpmtHa::new(
            hash_alg,
            mac::hmac(hash_alg, sensitive.sensitive.as_slice(), message)?,
        )?),
    })
}

/// Check a signature over a whole message, Part 3 Table 115.
pub fn verify_message(
    object: &Object,
    message: &[u8],
    signature: &TpmtSignature,
) -> TpmResult<()> {
    if !signs_a_message(object) {
        let hash_alg = signature
            .hash_alg()
            .ok_or(TpmRc(rc::SCHEME).with_parameter(1))?;
        let digest = hash::digest(hash_alg, message)?;
        return verify_digest(object, &digest, signature);
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let SignatureValue::Hmac(mac_value) = &signature.signature else {
        return Err(TpmRc(rc::SIGNATURE).with_parameter(1));
    };
    let expected = mac::hmac(
        mac_value.hash_alg,
        sensitive.sensitive.as_slice(),
        message,
    )?;
    if !crate::tpm::core::protect::constant_time_eq(&expected, &mac_value.digest) {
        return Err(TpmRc(rc::SIGNATURE).with_parameter(1));
    }
    Ok(())
}

/// Check that a signature was made with the scheme the key is restricted to.
///
/// Part 3 clause 20.4.1 requires the whole scheme, including its hash, to be
/// the one keyHandle carries. A key whose scheme is TPM_ALG_NULL is not
/// restricted to any, so anything it can verify is allowed.
pub fn check_signature_scheme(object: &Object, signature: &TpmtSignature) -> TpmResult<()> {
    let scheme = object.public.scheme().copied().unwrap_or_default();
    if scheme.is_null() {
        return Ok(());
    }
    if scheme.scheme != signature.sig_alg {
        return Err(TpmRc(rc::SCHEME));
    }
    match (scheme.hash_alg(), signature.hash_alg()) {
        (Some(expected), Some(used)) if expected != used => Err(TpmRc(rc::SCHEME)),
        _ => Ok(()),
    }
}

/// Check that a digest is the size the signature hash produces.
///
/// Part 3 clause 20.4.1 refuses a digest that does not match, so a short one
/// cannot be padded or truncated into a signature the TPM will vouch for.
pub fn check_digest_size(digest: &[u8], signature: &TpmtSignature) -> TpmResult<()> {
    let Some(hash_alg) = signature.hash_alg() else {
        return Ok(());
    };
    if digest.len() != hash::digest_size(hash_alg)? {
        return Err(TpmRc(rc::SIZE));
    }
    Ok(())
}

/// The HMAC of a signature verification ticket.
///
/// Every TPMT_TK_VERIFIED commits to its tag, the digest that was verified and
/// the Name of the key that verified it. TPM_ST_DIGEST_VERIFIED also carries
/// the hash that made the digest, which TPM2_PolicyAuthorize needs in order to
/// recompute the ticket.
pub fn verified_ticket_hmac(
    proof: &[u8],
    tag: u16,
    signed: &[u8],
    name: &[u8],
    digest_alg: Option<u16>,
) -> TpmResult<Vec<u8>> {
    let tag_field = tag.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&tag_field, signed, name];
    // Part 2 Table 111 gives metadata only to TPM_ST_DIGEST_VERIFIED, so
    // nothing is added for the other two tags.
    let alg_field;
    if let Some(a) = digest_alg {
        alg_field = a.to_be_bytes();
        parts.push(&alg_field);
    }
    mac::hmac_parts(config::CONTEXT_INTEGRITY_HASH_ALG, proof, &parts)
}

/// TPM2_HMAC, Part 3 clause 15.5.
pub fn hmac_command(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let buffer = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    let requested = r.u16()?;
    r.expect_end()?;

    let (key, hash_alg) = hmac_key(state, handle, requested)?;
    let digest = mac::hmac(hash_alg, &key, buffer.as_slice())?;
    respond(move |w| {
        Tpm2bDigest::new(digest)?.marshal(w);
        Ok(())
    })
}

/// The key and hash of a keyed hash object used for an HMAC.
fn hmac_key(state: &TpmState, handle: u32, requested: u16) -> TpmResult<(Vec<u8>, u16)> {
    let object = object_of(state, handle).map_err(|e| e.with_handle(1))?;
    if object.public.object_type != alg::KEYEDHASH {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::SIGN_ENCRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    // The scheme of the object fixes the hash unless it is null, in which case
    // the caller chooses.
    let scheme_hash = match &object.public.parameters {
        PublicParms::KeyedHash { scheme } if !scheme.is_null() => {
            if scheme.scheme != alg::HMAC {
                return Err(TpmRc(rc::SCHEME).with_handle(1));
            }
            scheme.hash_alg()
        }
        _ => None,
    };
    let hash_alg = match (scheme_hash, requested) {
        (Some(h), r) if r == alg::NULL || r == h => h,
        (Some(_), _) => return Err(TpmRc(rc::VALUE).with_parameter(2)),
        (None, r) if r != alg::NULL => r,
        (None, _) => return Err(TpmRc(rc::VALUE).with_parameter(2)),
    };
    if !hash::is_supported(hash_alg) {
        return Err(TpmRc(rc::HASH).with_parameter(2));
    }
    Ok((sensitive.sensitive.as_slice().to_vec(), hash_alg))
}

/// TPM2_HashSequenceStart, Part 3 clause 17.3.
pub fn hash_sequence_start(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    let hash_alg = r.u16()?;
    r.expect_end()?;

    // TPM_ALG_NULL starts an event sequence, which feeds every PCR bank.
    let kind = if hash_alg == alg::NULL {
        SequenceKind::Event
    } else {
        if !hash::is_supported(hash_alg) {
            return Err(TpmRc(rc::HASH).with_parameter(2));
        }
        SequenceKind::Hash { hash_alg }
    };
    let handle = state.objects.insert(Slot::Sequence(Box::new(Sequence {
        kind,
        auth: auth.as_slice().to_vec(),
        buffer: Vec::new(),
    })))?;
    respond_with_handle(handle, |_| Ok(()))
}

/// TPM2_HMAC_Start, Part 3 clause 17.2.
pub fn hmac_start(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    let requested = r.u16()?;
    r.expect_end()?;

    let (key, hash_alg) = hmac_key(state, key_handle, requested)?;
    let handle = state.objects.insert(Slot::Sequence(Box::new(Sequence {
        kind: SequenceKind::Hmac { hash_alg, key },
        auth: auth.as_slice().to_vec(),
        buffer: Vec::new(),
    })))?;
    respond_with_handle(handle, |_| Ok(()))
}

/// TPM2_SequenceUpdate, Part 3 clause 17.4.
pub fn sequence_update(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let buffer = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    r.expect_end()?;
    state
        .objects
        .get_mut(handle)
        .map_err(|e| e.with_handle(1))?
        .as_sequence_mut()?
        .update(buffer.as_slice())?;
    respond(|_| Ok(()))
}

/// TPM2_SequenceComplete, Part 3 clause 17.5.
pub fn sequence_complete(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let handle = request.handle(0)?;
    let mut r = request.reader();
    let buffer = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    let hierarchy = r.u32()?;
    r.expect_end()?;

    let sequence = state
        .objects
        .get(handle)
        .map_err(|e| e.with_handle(1))?
        .as_sequence()?
        .clone();
    if sequence.is_event() {
        // An event sequence is finished by TPM2_EventSequenceComplete.
        return Err(TpmRc(rc::MODE).with_handle(1));
    }
    let mut data = sequence.buffer.clone();
    data.extend_from_slice(buffer.as_slice());

    let (digest, ticket) = match &sequence.kind {
        SequenceKind::Hash { hash_alg } => {
            let d = hash::digest(*hash_alg, &data)?;
            let t = hash_ticket(state, hierarchy, *hash_alg, &data, &d)?;
            (d, t)
        }
        SequenceKind::Hmac { hash_alg, key } => {
            (mac::hmac(*hash_alg, key, &data)?, Ticket::null(st::HASHCHECK))
        }
        SequenceKind::Event => unreachable!("event sequences are handled above"),
    };
    // The dispatcher flushes the handle because the command has the flushed
    // attribute.
    respond(move |w| {
        Tpm2bDigest::new(digest)?.marshal(w);
        ticket.marshal(w);
        Ok(())
    })
}

/// TPM2_EventSequenceComplete, Part 3 clause 17.6.
pub fn event_sequence_complete(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let pcr_handle = request.handle(0)?;
    let sequence_handle = request.handle(1)?;
    let mut r = request.reader();
    let buffer = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    r.expect_end()?;

    let sequence = state
        .objects
        .get(sequence_handle)
        .map_err(|e| e.with_handle(2))?
        .as_sequence()?
        .clone();
    if !sequence.is_event() {
        return Err(TpmRc(rc::MODE).with_handle(2));
    }
    let mut data = sequence.buffer.clone();
    data.extend_from_slice(buffer.as_slice());

    let digests = if pcr_handle == rh::NULL {
        let mut out = Vec::new();
        for a in state.pcr.algorithms() {
            out.push((a, hash::digest(a, &data)?));
        }
        out
    } else {
        let index = (pcr_handle - crate::tpm::constants::hc::PCR_FIRST) as u16;
        state.pcr.event(index, request.locality, &data)?
    };

    respond(move |w| {
        let items = digests
            .into_iter()
            .map(|(a, d)| TpmtHa::new(a, d))
            .collect::<TpmResult<Vec<_>>>()?;
        TpmlDigestValues::new(items)?.marshal(w);
        Ok(())
    })
}

/// The signing scheme a command uses: the object's when it has one, otherwise
/// the caller's.
pub fn signing_scheme(object: &Object, supplied: &Scheme) -> TpmResult<Scheme> {
    let object_scheme = object.public.scheme().copied().unwrap_or_default();
    if object_scheme.is_null() {
        if supplied.is_null() {
            return Err(TpmRc(rc::SCHEME).with_parameter(2));
        }
        Ok(*supplied)
    } else {
        if !supplied.is_null() && supplied.scheme != object_scheme.scheme {
            return Err(TpmRc(rc::SCHEME).with_parameter(2));
        }
        Ok(object_scheme)
    }
}

/// Sign `digest` with `object` using `scheme`.
pub fn sign_digest(
    state: &mut TpmState,
    object: &Object,
    scheme: &Scheme,
    digest: &[u8],
) -> TpmResult<TpmtSignature> {
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME))?;
    if digest.len() != hash::digest_size(hash_alg)? {
        return Err(TpmRc(rc::SIZE).with_parameter(1));
    }

    match object.public.object_type {
        alg::RSA => {
            let PublicParms::Rsa {
                key_bits, exponent, ..
            } = object.public.parameters
            else {
                return Err(TpmRc(rc::TYPE));
            };
            let PublicId::Rsa(modulus) = &object.public.unique else {
                return Err(TpmRc(rc::TYPE));
            };
            let key = rsa::RsaPrivate::from_prime(
                modulus.as_slice(),
                exponent,
                sensitive.sensitive.as_slice(),
            )?;
            let size = key.size();
            let block = match scheme.scheme {
                alg::RSASSA => rsa::pkcs1v15_sign_encode(hash_alg, digest, size)?,
                alg::RSAPSS => {
                    let em = rsa::pss_encode(hash_alg, digest, key_bits as usize, &mut state.rng)?;
                    let mut b = vec![0u8; size - em.len()];
                    b.extend_from_slice(&em);
                    b
                }
                _ => return Err(TpmRc(rc::SCHEME).with_parameter(2)),
            };
            let sig = rsa::private_op(&key, &block)?;
            Ok(TpmtSignature {
                sig_alg: scheme.scheme,
                signature: SignatureValue::Rsa(SignatureRsa {
                    hash: hash_alg,
                    sig: Tpm2bPublicKeyRsa::new(sig)?,
                }),
            })
        }
        alg::ECC => {
            let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let curve = ecc::Curve::new(curve_id)?;
            let private =
                crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;
            let sig = match scheme.scheme {
                alg::ECDSA => ecc::ecdsa_sign(&curve, &private, digest, &mut state.rng)?,
                alg::ECSCHNORR => {
                    ecc::ecschnorr_sign(&curve, &private, hash_alg, digest, &mut state.rng)?
                }
                _ => return Err(TpmRc(rc::SCHEME).with_parameter(2)),
            };
            Ok(TpmtSignature {
                sig_alg: scheme.scheme,
                signature: SignatureValue::Ecc(SignatureEcc {
                    hash: hash_alg,
                    signature_r: Tpm2bEccParameter::new(sig.r)?,
                    signature_s: Tpm2bEccParameter::new(sig.s)?,
                }),
            })
        }
        alg::KEYEDHASH => {
            let key = sensitive.sensitive.as_slice();
            Ok(TpmtSignature {
                sig_alg: alg::HMAC,
                signature: SignatureValue::Hmac(TpmtHa::new(
                    hash_alg,
                    mac::hmac(hash_alg, key, digest)?,
                )?),
            })
        }
        _ => Err(TpmRc(rc::TYPE).with_handle(1)),
    }
}

/// Verify `signature` over `digest` with the public part of `object`.
pub fn verify_digest_public(
    object: &Object,
    digest: &[u8],
    signature: &TpmtSignature,
) -> TpmResult<()> {
    verify_digest(object, digest, signature)
}

/// Verify `signature` over `digest` with the public part of `object`.
fn verify_digest(object: &Object, digest: &[u8], signature: &TpmtSignature) -> TpmResult<()> {
    check_signature_scheme(object, signature).map_err(|e| e.with_parameter(2))?;
    match (&object.public.unique, &signature.signature) {
        (PublicId::Rsa(modulus), SignatureValue::Rsa(sig)) => {
            let PublicParms::Rsa { exponent, .. } = object.public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let public = rsa::RsaPublic::new(modulus.as_slice(), exponent)?;
            let recovered = rsa::public_op(&public, sig.sig.as_slice())
                .map_err(|_| TpmRc(rc::SIGNATURE).with_parameter(2))?;
            match signature.sig_alg {
                alg::RSASSA => {
                    let expected =
                        rsa::pkcs1v15_sign_encode(sig.hash, digest, public.size())?;
                    if recovered != expected {
                        return Err(TpmRc(rc::SIGNATURE).with_parameter(2));
                    }
                }
                alg::RSAPSS => {
                    let em_len = (public.bits() - 1 + 7) / 8;
                    rsa::pss_verify(
                        sig.hash,
                        digest,
                        &recovered[recovered.len() - em_len..],
                        public.bits(),
                    )
                    .map_err(|_| TpmRc(rc::SIGNATURE).with_parameter(2))?;
                }
                _ => return Err(TpmRc(rc::SCHEME).with_parameter(2)),
            }
            Ok(())
        }
        (PublicId::Ecc(point), SignatureValue::Ecc(sig)) => {
            let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let curve = ecc::Curve::new(curve_id)?;
            let value = ecc::EccSignature {
                r: sig.signature_r.as_slice().to_vec(),
                s: sig.signature_s.as_slice().to_vec(),
            };
            match signature.sig_alg {
                alg::ECDSA => ecc::ecdsa_verify(
                    &curve,
                    point.x.as_slice(),
                    point.y.as_slice(),
                    digest,
                    &value,
                ),
                alg::ECSCHNORR => ecc::ecschnorr_verify(
                    &curve,
                    point.x.as_slice(),
                    point.y.as_slice(),
                    sig.hash,
                    digest,
                    &value,
                ),
                _ => Err(TpmRc(rc::SCHEME).with_parameter(2)),
            }
            .map_err(|_| TpmRc(rc::SIGNATURE).with_parameter(2))
        }
        (PublicId::KeyedHash(_), SignatureValue::Hmac(ha)) => {
            let Some(sensitive) = &object.sensitive else {
                return Err(TpmRc(rc::HANDLE).with_handle(1));
            };
            let expected = mac::hmac(ha.hash_alg, sensitive.sensitive.as_slice(), digest)?;
            if !crate::tpm::core::protect::constant_time_eq(&expected, &ha.digest) {
                return Err(TpmRc(rc::SIGNATURE).with_parameter(2));
            }
            Ok(())
        }
        _ => Err(TpmRc(rc::SIGNATURE).with_parameter(2)),
    }
}

/// TPM2_Sign, Part 3 clause 20.2.
pub fn sign(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let digest = Tpm2bDigest::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;
    let validation = Ticket::unmarshal_tagged(&mut r, &[st::HASHCHECK])?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    // Part 3 clause 20.5.1 needs a signing key that is not reserved for X.509.
    check_signing_key(&object).map_err(|e| e.with_handle(1))?;
    let scheme = signing_scheme(&object, &in_scheme)?;
    // Part 3 clause 20.5.1 requires the ticket for a restricted key, and
    // checks one that is supplied even when the key does not require it.
    let restricted = object
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED);
    if restricted || !validation.digest.is_empty() {
        let hash_alg = scheme.hash_alg().unwrap_or(object.public.name_alg);
        if hash::digest_size(hash_alg)? != digest.len() {
            return Err(TpmRc(rc::TICKET).with_parameter(3));
        }
        verify_hash_ticket(state, &validation, hash_alg, digest.as_slice(), 3)?;
    }
    let signature = sign_digest(state, &object, &scheme, digest.as_slice())?;
    respond(move |w| {
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_VerifySignature, Part 3 clause 20.1.
pub fn verify_signature(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let digest = Tpm2bDigest::unmarshal(&mut r)?;
    let signature = TpmtSignature::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
    verify_digest(object, digest.as_slice(), &signature)?;

    // The ticket says this TPM checked the signature.
    let hierarchy = object.hierarchy;
    let ticket = if hierarchy == rh::NULL {
        VerifiedTicket::null()
    } else {
        let proof = state.hierarchy_proof(hierarchy)?.to_vec();
        let hmac = verified_ticket_hmac(
            &proof,
            st::VERIFIED,
            digest.as_slice(),
            &object.name,
            None,
        )?;
        VerifiedTicket {
            tag: st::VERIFIED,
            hierarchy,
            digest_alg: None,
            hmac: Tpm2bDigest::new(hmac)?,
        }
    };
    respond(move |w| {
        ticket.marshal(w);
        Ok(())
    })
}

/// TPM2_RSA_Encrypt, Part 3 clause 14.2.
pub fn rsa_encrypt(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let message = Tpm2bPublicKeyRsa::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_rsa_decrypt(&mut r)?;
    let label = crate::tpm::structures::base::Tpm2bData::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if object.public.object_type != alg::RSA {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let PublicParms::Rsa { exponent, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let PublicId::Rsa(modulus) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE));
    };
    let public = rsa::RsaPublic::new(modulus.as_slice(), exponent)?;
    let scheme = signing_scheme(&object, &in_scheme).unwrap_or(in_scheme);

    let block = match scheme.scheme {
        alg::OAEP => {
            let hash_alg = scheme.hash_alg().unwrap_or(object.public.name_alg);
            let mut l = label.as_slice().to_vec();
            // Part 1 clause 11.2.4.4 terminates the label with a zero octet.
            if !l.last().is_some_and(|b| *b == 0) {
                l.push(0);
            }
            rsa::oaep_encode(hash_alg, public.size(), message.as_slice(), &l, &mut state.rng)?
        }
        alg::RSAES => {
            rsa::pkcs1v15_encrypt_pad(public.size(), message.as_slice(), &mut state.rng)?
        }
        alg::NULL => {
            if message.len() != public.size() {
                return Err(TpmRc(rc::SIZE).with_parameter(1));
            }
            message.as_slice().to_vec()
        }
        _ => return Err(TpmRc(rc::SCHEME).with_parameter(2)),
    };
    let out = rsa::public_op(&public, &block)?;
    respond(move |w| {
        Tpm2bPublicKeyRsa::new(out)?.marshal(w);
        Ok(())
    })
}

/// TPM2_RSA_Decrypt, Part 3 clause 14.3.
pub fn rsa_decrypt(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let cipher = Tpm2bPublicKeyRsa::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_rsa_decrypt(&mut r)?;
    let label = crate::tpm::structures::base::Tpm2bData::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
    if object.public.object_type != alg::RSA {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    if object
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED)
    {
        // A restricted decryption key only unwraps TPM structures.
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::Rsa { exponent, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let PublicId::Rsa(modulus) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE));
    };
    let key = rsa::RsaPrivate::from_prime(
        modulus.as_slice(),
        exponent,
        sensitive.sensitive.as_slice(),
    )?;
    let scheme = signing_scheme(object, &in_scheme).unwrap_or(in_scheme);

    let plain = rsa::private_op(&key, cipher.as_slice())?;
    let message = match scheme.scheme {
        alg::OAEP => {
            let hash_alg = scheme.hash_alg().unwrap_or(object.public.name_alg);
            let mut l = label.as_slice().to_vec();
            if !l.last().is_some_and(|b| *b == 0) {
                l.push(0);
            }
            rsa::oaep_decode(hash_alg, &plain, &l)?
        }
        alg::RSAES => rsa::pkcs1v15_encrypt_unpad(&plain)?,
        alg::NULL => plain,
        _ => return Err(TpmRc(rc::SCHEME).with_parameter(2)),
    };
    respond(move |w| {
        Tpm2bPublicKeyRsa::new(message)?.marshal(w);
        Ok(())
    })
}

/// TPM2_ECDH_KeyGen, Part 3 clause 14.4.
pub fn ecdh_key_gen(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    };
    let PublicId::Ecc(point) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    };

    let ephemeral = ecc::generate(curve_id, &mut state.rng)?;
    let (zx, zy) = ecc::ecdh(
        &ephemeral.curve,
        &ephemeral.private,
        point.x.as_slice(),
        point.y.as_slice(),
    )?;
    respond(move |w| {
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(zx)?,
                y: Tpm2bEccParameter::new(zy)?,
            },
        }
        .marshal(w);
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(ephemeral.public_x)?,
                y: Tpm2bEccParameter::new(ephemeral.public_y)?,
            },
        }
        .marshal(w);
        Ok(())
    })
}

/// TPM2_ECDH_ZGen, Part 3 clause 14.5.
pub fn ecdh_zgen(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_point = Tpm2bEccPoint::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
    if object.public.object_type != alg::ECC {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let curve = ecc::Curve::new(curve_id)?;
    let private = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;
    let (zx, zy) = ecc::ecdh(
        &curve,
        &private,
        in_point.point.x.as_slice(),
        in_point.point.y.as_slice(),
    )
    .map_err(|e| if e.0 == rc::ECC_POINT { e.with_parameter(1) } else { e })?;
    respond(move |w| {
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(zx)?,
                y: Tpm2bEccParameter::new(zy)?,
            },
        }
        .marshal(w);
        Ok(())
    })
}

/// TPM2_EncryptDecrypt, Part 3 clause 15.2, and TPM2_EncryptDecrypt2,
/// clause 15.3, which only differ in the order of their parameters.
pub fn encrypt_decrypt(
    state: &TpmState,
    request: &Request,
    data_first: bool,
) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let (decrypt_flag, mode, iv, data) = if data_first {
        let data = Tpm2bMaxBuffer::unmarshal(&mut r)?;
        let decrypt = r.u8()?;
        let mode = r.u16()?;
        let iv = Tpm2bIv::unmarshal(&mut r)?;
        (decrypt, mode, iv, data)
    } else {
        let decrypt = r.u8()?;
        let mode = r.u16()?;
        let iv = Tpm2bIv::unmarshal(&mut r)?;
        let data = Tpm2bMaxBuffer::unmarshal(&mut r)?;
        (decrypt, mode, iv, data)
    };
    r.expect_end()?;
    let decrypt = match decrypt_flag {
        0 => false,
        1 => true,
        _ => return Err(TpmRc(rc::VALUE).with_parameter(2)),
    };

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
    if object.public.object_type != alg::SYMCIPHER {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    if object
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::SymCipher { sym } = &object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    // TPM_ALG_NULL means the mode fixed by the key.
    let mode = if mode == alg::NULL { sym.mode } else { mode };
    if sym.mode != alg::NULL && mode != sym.mode {
        return Err(TpmRc(rc::VALUE).with_parameter(3));
    }

    let mut iv_buf = iv.as_slice().to_vec();
    if mode != alg::ECB && iv_buf.is_empty() {
        iv_buf = vec![0u8; sym::block_size(sym.algorithm)?];
    }
    let out = sym::crypt(
        sym.algorithm,
        mode,
        sensitive.sensitive.as_slice(),
        &mut iv_buf,
        data.as_slice(),
        if decrypt {
            sym::Direction::Decrypt
        } else {
            sym::Direction::Encrypt
        },
    )?;
    respond(move |w| {
        Tpm2bMaxBuffer::new(out)?.marshal(w);
        Tpm2bIv::new(iv_buf)?.marshal(w);
        Ok(())
    })
}

/// TPM2_MakeCredential, Part 3 clause 12.5.
pub fn make_credential(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bEncryptedSecret;
    use crate::tpm::structures::base::Tpm2bIdObject;

    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let credential = Tpm2bDigest::unmarshal(&mut r)?;
    let object_name = crate::tpm::structures::base::Tpm2bName::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if !object.is_storage_key() && !object.public.object_attributes.has(
        ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT,
    ) {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    let symmetric = object
        .public
        .parameters
        .symmetric()
        .copied()
        .ok_or(TpmRc(rc::TYPE))?;

    // The seed is carried to the target TPM protected by its public key.
    let name_alg = object.public.name_alg;
    let seed_size = hash::digest_size(name_alg)?;
    let seed = state.rng.bytes(seed_size)?;
    let secret = match (&object.public.unique, object.public.object_type) {
        (PublicId::Rsa(modulus), alg::RSA) => {
            let PublicParms::Rsa { exponent, .. } = object.public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let public = rsa::RsaPublic::new(modulus.as_slice(), exponent)?;
            let block = rsa::oaep_encode(
                name_alg,
                public.size(),
                &seed,
                b"IDENTITY\0",
                &mut state.rng,
            )?;
            rsa::public_op(&public, &block)?
        }
        _ => return Err(TpmRc(rc::TYPE).with_handle(1)),
    };

    let blob = crate::tpm::core::protect::wrap_credential(
        name_alg,
        &seed,
        &symmetric,
        object_name.as_slice(),
        credential.as_slice(),
    )?;
    respond(move |w| {
        Tpm2bIdObject::new(blob)?.marshal(w);
        Tpm2bEncryptedSecret::new(secret)?.marshal(w);
        Ok(())
    })
}

/// TPM2_ActivateCredential, Part 3 clause 12.6.
pub fn activate_credential(state: &TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bEncryptedSecret;
    use crate::tpm::structures::base::Tpm2bIdObject;

    let activate_handle = request.handle(0)?;
    let key_handle = request.handle(1)?;
    let mut r = request.reader();
    let credential_blob = Tpm2bIdObject::unmarshal(&mut r)?;
    let secret = Tpm2bEncryptedSecret::unmarshal(&mut r)?;
    r.expect_end()?;

    let key = object_of(state, key_handle).map_err(|e| e.with_handle(2))?;
    // Part 3 clause 12.5.1 needs a Storage Key here, the same one that made
    // the credential.
    if !key.is_storage_key() {
        return Err(TpmRc(rc::TYPE).with_handle(2));
    }
    let Some(sensitive) = &key.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(2));
    };
    let name_alg = key.public.name_alg;
    let symmetric = key
        .public
        .parameters
        .symmetric()
        .copied()
        .ok_or(TpmRc(rc::TYPE).with_handle(2))?;

    let seed = match (&key.public.unique, key.public.object_type) {
        (PublicId::Rsa(modulus), alg::RSA) => {
            let PublicParms::Rsa { exponent, .. } = key.public.parameters else {
                return Err(TpmRc(rc::TYPE));
            };
            let private = rsa::RsaPrivate::from_prime(
                modulus.as_slice(),
                exponent,
                sensitive.sensitive.as_slice(),
            )?;
            let plain = rsa::private_op(&private, secret.as_slice())?;
            rsa::oaep_decode(name_alg, &plain, b"IDENTITY\0")
                .map_err(|_| TpmRc(rc::VALUE).with_parameter(2))?
        }
        _ => return Err(TpmRc(rc::TYPE).with_handle(2)),
    };

    let activate = object_of(state, activate_handle).map_err(|e| e.with_handle(1))?;
    let credential = crate::tpm::core::protect::unwrap_credential(
        name_alg,
        &seed,
        &symmetric,
        &activate.name,
        credential_blob.as_slice(),
    )?;
    respond(move |w| {
        Tpm2bDigest::new(credential)?.marshal(w);
        Ok(())
    })
}

/// TPM2_EC_Ephemeral, Part 3 clause 19.4.
pub fn ec_ephemeral(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let mut r = request.reader();
    let curve_id = r.u16()?;
    r.expect_end()?;
    let key = ecc::generate(curve_id, &mut state.rng)
        .map_err(|_| TpmRc(rc::CURVE).with_parameter(1))?;
    // The commit counter identifies the ephemeral value for a later
    // TPM2_Commit; this TPM does not retain commitments, so it is always zero.
    respond(move |w| {
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(key.public_x)?,
                y: Tpm2bEccParameter::new(key.public_y)?,
            },
        }
        .marshal(w);
        w.u16(0);
        Ok(())
    })
}

/// The sensitive data of a keyed hash object, used by tests and by unsealing.
pub fn keyed_hash_data(object: &Object) -> TpmResult<Tpm2bSensitiveData> {
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE));
    };
    Tpm2bSensitiveData::from_slice(sensitive.sensitive.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::structures::schemes::SchemeHash;

    /// A keyed hash object with the given scheme and attributes.
    fn keyed_hash(scheme: Scheme, attributes: u32) -> Object {
        use crate::tpm::structures::keys::{PublicId, TpmtPublic, TpmtSensitive};
        let public = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(attributes),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash { scheme },
            unique: PublicId::KeyedHash(Tpm2bDigest::empty()),
        };
        let sensitive = TpmtSensitive {
            sensitive_type: alg::KEYEDHASH,
            auth_value: Tpm2bDigest::empty(),
            seed_value: Tpm2bDigest::empty(),
            sensitive: crate::tpm::structures::keys::SensitiveComposite::Bits(
                Tpm2bSensitiveData::new(vec![7u8; 32]).unwrap(),
            ),
        };
        Object::new(public, Some(sensitive), rh::NULL, &[], false).unwrap()
    }

    #[test]
    fn only_an_hmac_keyed_hash_key_is_a_signing_key() {
        let hmac = Scheme::hash(alg::HMAC, alg::SHA256);
        let xor = Scheme::hash(alg::XOR, alg::SHA256);
        let sign = ObjectAttributes::SIGN_ENCRYPT;

        assert!(signs_a_message(&keyed_hash(hmac, sign)));
        check_signing_key(&keyed_hash(hmac, sign)).unwrap();

        // Part 3 Table 115 gives message signing to HMAC alone, so an XOR
        // obfuscation key is not a signing key even with the sign attribute.
        let xor_key = keyed_hash(xor, sign);
        assert!(!signs_a_message(&xor_key));
        assert_eq!(check_signing_key(&xor_key).unwrap_err(), TpmRc(rc::KEY));

        // Part 3 clause 20.5.1 needs the sign attribute.
        assert_eq!(
            check_signing_key(&keyed_hash(hmac, 0)).unwrap_err(),
            TpmRc(rc::KEY)
        );

        // A key reserved for X.509 certificates signs nothing else.
        assert_eq!(
            check_signing_key(&keyed_hash(hmac, sign | ObjectAttributes::X509_SIGN))
                .unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );
    }

    #[test]
    fn a_digest_has_to_be_the_size_of_the_signature_hash() {
        let signature = TpmtSignature {
            sig_alg: alg::ECDSA,
            signature: SignatureValue::Ecc(SignatureEcc {
                hash: alg::SHA256,
                signature_r: Tpm2bEccParameter::new(vec![1u8; 32]).unwrap(),
                signature_s: Tpm2bEccParameter::new(vec![2u8; 32]).unwrap(),
            }),
        };
        check_digest_size(&[0u8; 32], &signature).unwrap();
        // Part 3 clause 20.4.1 refuses a digest that is not the right size, so
        // a short one cannot be truncated into a signature the TPM vouches for.
        assert_eq!(
            check_digest_size(&[0u8; 20], &signature).unwrap_err(),
            TpmRc(rc::SIZE)
        );
    }

    #[test]
    fn the_object_scheme_wins_when_it_has_one() {
        let mut object = crate::tpm::core::object::Object::new(
            crate::tpm::structures::keys::TpmtPublic {
                object_type: alg::ECC,
                name_alg: alg::SHA256,
                object_attributes: ObjectAttributes(ObjectAttributes::SIGN_ENCRYPT),
                auth_policy: Tpm2bDigest::empty(),
                parameters: PublicParms::Ecc {
                    symmetric: crate::tpm::structures::schemes::SymDef::null(),
                    scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                    curve_id: crate::tpm::constants::curve::NIST_P256,
                    kdf: Scheme::null(),
                },
                unique: PublicId::Ecc(EccPoint::default()),
            },
            None,
            rh::NULL,
            &rh::NULL.to_be_bytes(),
            true,
        )
        .unwrap();

        // A null request takes the object's scheme.
        let s = signing_scheme(&object, &Scheme::null()).unwrap();
        assert_eq!(s.scheme, alg::ECDSA);
        // A matching request is accepted.
        assert!(signing_scheme(&object, &Scheme::hash(alg::ECDSA, alg::SHA256)).is_ok());
        // A different one is refused.
        assert_eq!(
            signing_scheme(&object, &Scheme::hash(alg::ECSCHNORR, alg::SHA256))
                .unwrap_err()
                .0
                & 0x03F,
            rc::SCHEME & 0x03F
        );

        // With a null object scheme the caller must supply one.
        object.public.parameters = PublicParms::Ecc {
            symmetric: crate::tpm::structures::schemes::SymDef::null(),
            scheme: Scheme::null(),
            curve_id: crate::tpm::constants::curve::NIST_P256,
            kdf: Scheme::null(),
        };
        assert!(signing_scheme(&object, &Scheme::null()).is_err());
        let s = signing_scheme(&object, &Scheme::hash(alg::ECDSA, alg::SHA384)).unwrap();
        assert_eq!(s.detail, crate::tpm::structures::schemes::SchemeDetail::Hash(
            SchemeHash { hash_alg: alg::SHA384 }
        ));
    }
}
