//! The one shot and sequence signing commands added in version 185, and the
//! split ECC operations of Part 3 clause 19.

use crate::tpm::config;
use crate::tpm::constants::{alg, rc, rh, st};
use crate::tpm::core::object::{Object, Sequence, SequenceKind, Slot};
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::{ecc, hash};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attributes::ObjectAttributes;
use crate::tpm::structures::base::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bMaxBuffer, Tpm2bSensitiveData, Tpm2bSignatureCtx,
    Tpm2bSignatureHint,
};
use crate::tpm::structures::keys::{PublicId, PublicParms};
use crate::tpm::structures::schemes::{EccPoint, Scheme, Tpm2bEccPoint};
use crate::tpm::structures::signature::{Ticket, TpmtSignature, VerifiedTicket};

use super::crypto::{
    check_digest_size, check_signature_scheme, check_signing_key, sign_digest, sign_message,
    signing_scheme, signs_a_message, verified_ticket_hmac, verify_digest_public,
    verify_hash_ticket, verify_message,
};
use super::dispatch::{Request, Response};
use super::execute::{respond, respond_with_handle};

/// The object a handle names, transient or persistent.
fn object_of(state: &TpmState, handle: u32) -> TpmResult<&Object> {
    if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle)
    } else {
        state.persistent.get(&handle).ok_or(TpmRc(rc::HANDLE))
    }
}

/// Reject a signature context for a scheme that has none.
///
/// Part 2 Table 220 gives a context only to ECDAA, SM2 and ML-DSA. Of those
/// only ECDAA is implemented here, and this is for the commands that take no
/// counter, so a caller that supplies one is asking for something the TPM
/// cannot do.
fn check_no_context(context: &Tpm2bSignatureCtx, parameter: usize) -> TpmResult<()> {
    if context.is_empty() {
        Ok(())
    } else {
        Err(TpmRc(rc::VALUE).with_parameter(parameter))
    }
}

/// The commit counter a signature context carries, if the key needs one.
///
/// Part 3 clause 17.5.1 says that if the scheme of the key uses a counter,
/// "then context shall contain the counter value from TPM2_Commit() to use for
/// the signature". Part 2 Table 220 makes that counter a UINT16 for ECDAA, and
/// gives no context to any other scheme this TPM implements.
fn context_counter(
    object: &Object,
    context: &Tpm2bSignatureCtx,
    parameter: usize,
) -> TpmResult<Option<u16>> {
    let uses_counter = object
        .public
        .scheme()
        .map(|s| s.scheme == alg::ECDAA)
        .unwrap_or(false);
    if !uses_counter {
        check_no_context(context, parameter)?;
        return Ok(None);
    }
    let bytes = context.as_slice();
    if bytes.len() != 2 {
        return Err(TpmRc(rc::SIZE).with_parameter(parameter));
    }
    Ok(Some(u16::from_be_bytes([bytes[0], bytes[1]])))
}

/// The scheme to sign with, carrying the counter the context supplied.
fn scheme_with_counter(object: &Object, counter: Option<u16>) -> TpmResult<Scheme> {
    let mut scheme = signing_scheme(object, &Scheme::null())?;
    if let Some(count) = counter {
        let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME))?;
        scheme = Scheme::ecdaa(hash_alg, count);
    }
    Ok(scheme)
}

/// TPM2_SignDigest, Part 3 clause 20.7.
///
/// The digest is signed as it stands. A restricted key needs the hash check
/// ticket to show the TPM produced the digest and that it did not start with
/// TPM_GENERATED_VALUE.
pub fn sign_digest_command(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let context = Tpm2bSignatureCtx::unmarshal(&mut r)?;
    let digest = Tpm2bDigest::unmarshal(&mut r)?;
    let validation = Ticket::unmarshal_tagged(&mut r, &[st::HASHCHECK])?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    check_signing_key(&object).map_err(|e| e.with_handle(1))?;
    // Part 3 Table 115 leaves HMAC out of the digest commands, because an
    // HMAC key signs a message. No other keyed hash scheme signs at all.
    if object.public.object_type == alg::KEYEDHASH {
        return Err(TpmRc(rc::SCHEME).with_handle(1));
    }
    let counter = context_counter(&object, &context, 1)?;
    let scheme = scheme_with_counter(&object, counter)?;
    let restricted = object
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED);
    // A restricted key signs only what the TPM hashed itself, and the ticket
    // is the proof of that. Part 3 clause 20.5.1 also checks a ticket that is
    // supplied when the key does not require one.
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

/// TPM2_VerifyDigestSignature, Part 3 clause 20.4.
pub fn verify_digest_signature(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let context = Tpm2bSignatureCtx::unmarshal(&mut r)?;
    let digest = Tpm2bDigest::unmarshal(&mut r)?;
    let signature = TpmtSignature::unmarshal(&mut r)?;
    r.expect_end()?;
    check_no_context(&context, 1)?;

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
    // Part 3 Table 115 leaves every keyed hash key out of the digest commands.
    if object.public.object_type == alg::KEYEDHASH {
        return Err(TpmRc(rc::SCHEME).with_handle(1));
    }
    // Part 3 clause 20.4.1 requires the scheme and the digest to match the
    // key. The signature is parameter three of this command.
    check_signature_scheme(object, &signature).map_err(|e| e.with_parameter(3))?;
    check_digest_size(digest.as_slice(), &signature).map_err(|e| e.with_parameter(2))?;
    verify_digest_public(object, digest.as_slice(), &signature)?;

    let hierarchy = object.hierarchy;
    let hash_alg = signature.hash_alg().unwrap_or(object.public.name_alg);
    let ticket = if hierarchy == rh::NULL {
        VerifiedTicket {
            tag: st::DIGEST_VERIFIED,
            hierarchy: rh::NULL,
            digest_alg: Some(hash_alg),
            hmac: Tpm2bDigest::empty(),
        }
    } else {
        let proof = state.hierarchy_proof(hierarchy)?.to_vec();
        // The metadata of a digest verification ticket is the hash that made
        // the digest, so it is part of the HMAC.
        let hmac = verified_ticket_hmac(
            &proof,
            st::DIGEST_VERIFIED,
            digest.as_slice(),
            &object.name,
            Some(hash_alg),
        )?;
        VerifiedTicket {
            tag: st::DIGEST_VERIFIED,
            hierarchy,
            digest_alg: Some(hash_alg),
            hmac: Tpm2bDigest::new(hmac)?,
        }
    };
    respond(move |w| {
        ticket.marshal(w);
        Ok(())
    })
}

/// TPM2_SignSequenceStart, Part 3 clause 20.6.
///
/// The sequence buffers the message; the key is bound to the sequence so the
/// completion cannot switch to another one.
pub fn sign_sequence_start(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    let context = Tpm2bSignatureCtx::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    // Part 3 clause 20.6.1 needs a signing key here.
    check_signing_key(&object).map_err(|e| e.with_handle(1))?;
    let counter = context_counter(&object, &context, 2)?;
    // The sequence hashes with the algorithm of the key's signing scheme,
    // because that is the algorithm the signature will use.
    let scheme = signing_scheme(&object, &Scheme::null())?;
    let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_handle(1))?;
    if !hash::is_supported(hash_alg) {
        return Err(TpmRc(rc::HASH).with_handle(1));
    }

    // The key handle is recorded in the sequence so the completion can check
    // it, which is what TPM_RC_SIGN_CONTEXT_KEY is for.
    let mut buffer = key_handle.to_be_bytes().to_vec();
    buffer.extend_from_slice(&hash_alg.to_be_bytes());
    buffer.extend_from_slice(&counter_bytes(counter));
    let handle = state.objects.insert(Slot::Sequence(Box::new(Sequence {
        kind: SequenceKind::Hash { hash_alg },
        auth: auth.as_slice().to_vec(),
        buffer,
    })))?;
    respond_with_handle(handle, |_| Ok(()))
}

/// True when the message begins with TPM_GENERATED_VALUE.
fn starts_with_generated_value(message: &[u8]) -> bool {
    message.len() >= 4
        && u32::from_be_bytes([message[0], message[1], message[2], message[3]])
            == crate::tpm::constants::TPM_GENERATED_VALUE
}

/// The key handle and hash a signing sequence was started with.
fn sequence_binding(sequence: &Sequence) -> TpmResult<(u32, u16, Option<u16>, &[u8])> {
    if sequence.buffer.len() < 9 {
        return Err(TpmRc(rc::SEQUENCE));
    }
    let handle = u32::from_be_bytes([
        sequence.buffer[0],
        sequence.buffer[1],
        sequence.buffer[2],
        sequence.buffer[3],
    ]);
    let hash_alg = u16::from_be_bytes([sequence.buffer[4], sequence.buffer[5]]);
    // The counter of Part 3 clause 17.5.1 is supplied at the start of the
    // sequence and needed at its end, so it travels with the binding.
    let counter = if sequence.buffer[6] != 0 {
        Some(u16::from_be_bytes([sequence.buffer[7], sequence.buffer[8]]))
    } else {
        None
    };
    Ok((handle, hash_alg, counter, &sequence.buffer[9..]))
}

/// The three octets a sequence records for an optional counter.
fn counter_bytes(counter: Option<u16>) -> [u8; 3] {
    match counter {
        Some(c) => {
            let b = c.to_be_bytes();
            [1, b[0], b[1]]
        }
        None => [0, 0, 0],
    }
}

/// TPM2_SignSequenceComplete, Part 3 clause 20.6.
///
/// The handle area is the sequence first and the key second, as Table 124
/// defines it.
pub fn sign_sequence_complete(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sequence_handle = request.handle(0)?;
    let key_handle = request.handle(1)?;
    let mut r = request.reader();
    let buffer = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    r.expect_end()?;

    let sequence = state
        .objects
        .get(sequence_handle)
        .map_err(|e| e.with_handle(1))?
        .as_sequence()?
        .clone();
    let (bound_handle, hash_alg, counter, message) = sequence_binding(&sequence)?;
    if bound_handle != key_handle {
        return Err(TpmRc(rc::SIGN_CONTEXT_KEY).with_handle(2));
    }
    let mut data = message.to_vec();
    data.extend_from_slice(buffer.as_slice());
    let _ = hash_alg;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(2))?
        .clone();
    check_signing_key(&object).map_err(|e| e.with_handle(2))?;
    let restricted = object
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED);
    // Part 3 clause 20.6 has no validation parameter, so a restricted HMAC
    // key, which signs only digests the TPM made, cannot be used here.
    if signs_a_message(&object) && restricted {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(2));
    }
    // A restricted asymmetric key may not sign anything that could be taken
    // for an attestation the TPM produced, Part 3 clause 20.6.1.
    if restricted && starts_with_generated_value(&data) {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }
    // The counter the sequence carried names the TPM2_Commit this signature
    // completes, per Part 3 clause 17.5.1.
    let scheme = scheme_with_counter(&object, counter)?;
    // Part 3 Table 115: an HMAC key signs the message itself, everything else
    // signs the digest of the message.
    let signature = sign_message(state, &object, &scheme, &data)?;
    respond(move |w| {
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_VerifySequenceStart, Part 3 clause 17.6.
pub fn verify_sequence_start(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let auth = Tpm2bDigest::unmarshal(&mut r)?;
    let hint = Tpm2bSignatureHint::unmarshal(&mut r)?;
    let context = Tpm2bSignatureCtx::unmarshal(&mut r)?;
    r.expect_end()?;
    // Part 2 Table 222 gives a hint only to EdDSA, which is not implemented.
    if !hint.is_empty() {
        return Err(TpmRc(rc::VALUE).with_parameter(2));
    }
    check_no_context(&context, 3)?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    let scheme = object.public.scheme().copied().unwrap_or_default();
    let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_handle(1))?;
    if !hash::is_supported(hash_alg) {
        return Err(TpmRc(rc::HASH).with_handle(1));
    }

    let mut buffer = key_handle.to_be_bytes().to_vec();
    buffer.extend_from_slice(&hash_alg.to_be_bytes());
    // Part 1 clause 44.3.3.1 says the TPM may not verify an ECDAA signature,
    // so a verification sequence never carries a counter.
    buffer.extend_from_slice(&counter_bytes(None));
    let handle = state.objects.insert(Slot::Sequence(Box::new(Sequence {
        kind: SequenceKind::Hash { hash_alg },
        auth: auth.as_slice().to_vec(),
        buffer,
    })))?;
    respond_with_handle(handle, |_| Ok(()))
}

/// TPM2_VerifySequenceComplete, Part 3 clause 20.3.
///
/// The handle area is the sequence first and the key second, as Table 118
/// defines it, and the message arrived through TPM2_SequenceUpdate.
pub fn verify_sequence_complete(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sequence_handle = request.handle(0)?;
    let key_handle = request.handle(1)?;
    let mut r = request.reader();
    let signature = TpmtSignature::unmarshal(&mut r)?;
    r.expect_end()?;

    let sequence = state
        .objects
        .get(sequence_handle)
        .map_err(|e| e.with_handle(1))?
        .as_sequence()?
        .clone();
    let (bound_handle, hash_alg, counter, message) = sequence_binding(&sequence)?;
    if bound_handle != key_handle {
        return Err(TpmRc(rc::SIGN_CONTEXT_KEY).with_handle(2));
    }
    let _ = hash_alg;
    // A verification sequence never records one, because the TPM does not
    // verify the one scheme that uses a counter.
    debug_assert!(counter.is_none());
    let message = message.to_vec();

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(2))?;
    check_signature_scheme(object, &signature).map_err(|e| e.with_parameter(1))?;
    verify_message(object, &message, &signature)?;

    let hierarchy = object.hierarchy;
    let ticket = if hierarchy == rh::NULL {
        VerifiedTicket {
            tag: st::MESSAGE_VERIFIED,
            hierarchy: rh::NULL,
            digest_alg: None,
            hmac: Tpm2bDigest::empty(),
        }
    } else {
        let proof = state.hierarchy_proof(hierarchy)?.to_vec();
        // Part 3 clause 20.3 verifies a message, so the ticket commits to the
        // message itself and TPM2_PolicyAuthorize can recompute it from the
        // approved policy and the policy reference.
        let hmac = verified_ticket_hmac(
            &proof,
            st::MESSAGE_VERIFIED,
            &message,
            &object.name,
            None,
        )?;
        VerifiedTicket {
            tag: st::MESSAGE_VERIFIED,
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

/// TPM2_ECC_Encrypt, Part 3 clause 14.9.
///
/// The message is encrypted to the public point of an ECC key using the
/// one pass Diffie-Hellman construction: an ephemeral key is generated, the
/// shared point keys a symmetric cipher through KDFe, and the ephemeral public
/// point travels with the ciphertext.
pub fn ecc_encrypt(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let plain = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_kdf(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
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
    let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let PublicId::Ecc(point) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE));
    };
    let hash_alg = in_scheme.hash_alg().unwrap_or(object.public.name_alg);

    let ephemeral = ecc::generate(curve_id, &mut state.rng)?;
    let (zx, _) = ecc::ecdh(
        &ephemeral.curve,
        &ephemeral.private,
        point.x.as_slice(),
        point.y.as_slice(),
    )?;
    let (key, iv) = ecc_kem_key(hash_alg, &zx, &ephemeral.public_x, point.x.as_slice())?;
    let cipher = crate::tpm::crypto::sym::cfb_encrypt(&key, &iv, plain.as_slice())?;
    let digest = crate::tpm::crypto::hmac::hmac(hash_alg, &key, &cipher)?;

    respond(move |w| {
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(ephemeral.public_x)?,
                y: Tpm2bEccParameter::new(ephemeral.public_y)?,
            },
        }
        .marshal(w);
        Tpm2bMaxBuffer::new(cipher)?.marshal(w);
        Tpm2bDigest::new(digest)?.marshal(w);
        Ok(())
    })
}

/// TPM2_ECC_Decrypt, Part 3 clause 14.10.
pub fn ecc_decrypt(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let c1 = Tpm2bEccPoint::unmarshal(&mut r)?;
    let c2 = Tpm2bMaxBuffer::unmarshal(&mut r)?;
    let c3 = Tpm2bDigest::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_kdf(&mut r)?;
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
    let PublicId::Ecc(point) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE));
    };
    let hash_alg = in_scheme.hash_alg().unwrap_or(object.public.name_alg);

    let curve = ecc::Curve::new(curve_id)?;
    let private = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;
    let (zx, _) = ecc::ecdh(
        &curve,
        &private,
        c1.point.x.as_slice(),
        c1.point.y.as_slice(),
    )
    .map_err(|e| e.with_parameter(1))?;
    let (key, iv) = ecc_kem_key(hash_alg, &zx, c1.point.x.as_slice(), point.x.as_slice())?;

    let expected = crate::tpm::crypto::hmac::hmac(hash_alg, &key, c2.as_slice())?;
    if !crate::tpm::core::protect::constant_time_eq(&expected, c3.as_slice()) {
        return Err(TpmRc(rc::VALUE).with_parameter(3));
    }
    let plain = crate::tpm::crypto::sym::cfb_decrypt(&key, &iv, c2.as_slice())?;
    respond(move |w| {
        Tpm2bMaxBuffer::new(plain)?.marshal(w);
        Ok(())
    })
}

/// The symmetric key and IV derived from an ECC shared secret.
fn ecc_kem_key(
    hash_alg: u16,
    z: &[u8],
    party_u: &[u8],
    party_v: &[u8],
) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    let key_bits = crate::tpm::config::MAX_SYM_KEY_BITS as u32;
    let block = crate::tpm::crypto::sym::block_size(alg::AES)?;
    let out = crate::tpm::crypto::hmac::kdfe(
        hash_alg,
        z,
        "SECRET",
        party_u,
        party_v,
        key_bits + (block * 8) as u32,
    )?;
    let key_bytes = key_bits as usize / 8;
    Ok((out[..key_bytes].to_vec(), out[key_bytes..].to_vec()))
}

/// TPM2_Commit, Part 3 clause 19.2.
///
/// The commitment is `K = [d]P1`, `L = [r]P2` and `E = [r]P1` for the ECDAA
/// construction. This TPM keeps no commitment table, so the counter is always
/// zero and a later TPM2_Sign with TPM_ALG_ECDAA supplies its own value.
pub fn commit(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let p1 = Tpm2bEccPoint::unmarshal(&mut r)?;
    let s2 = Tpm2bSensitiveData::unmarshal(&mut r)?;
    let y2 = Tpm2bEccParameter::unmarshal(&mut r)?;
    r.expect_end()?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if object.public.object_type != alg::ECC {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::Ecc { curve_id, scheme, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    // Part 3 clause 19.2.1 requires the scheme of the key to be anonymous.
    if !crate::tpm::structures::schemes::is_anonymous(scheme.scheme) {
        return Err(TpmRc(rc::SCHEME).with_handle(1));
    }
    let curve = ecc::Curve::new(curve_id)?;
    let private = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;
    let ctx = crate::tpm::crypto::bn::BnCtx::new()?;

    // Part 1 clause 44.2.3 step 1: s2 and y2 are given together or not at all.
    if s2.is_empty() != y2.is_empty() {
        return Err(TpmRc(rc::SIZE).with_parameter(2));
    }

    // Steps 3 and 4: the second base point comes from the digest of s2 as its
    // x coordinate, reduced by the field modulus, with y2 as its y.
    let second = if s2.is_empty() {
        None
    } else {
        let (p, _, _) = curve.parameters()?;
        let digest = hash::digest(object.public.name_alg, s2.as_slice())?;
        let x2 = crate::tpm::crypto::bn::BigNum::from_bytes(&digest)?
            .modulo(&p, &ctx)?
            .to_bytes_padded(curve.coordinate_size())?;
        let point = ecc::Point::from_coordinates(&curve, &x2, y2.as_slice())
            .map_err(|_| TpmRc(rc::ECC_POINT).with_parameter(2))?;
        Some(point)
    };

    // Step 5: a P1 that is given has to be on the curve as well.
    let first = if p1.point.is_empty() {
        None
    } else {
        Some(
            ecc::Point::from_coordinates(&curve, p1.point.x.as_slice(), p1.point.y.as_slice())
                .map_err(|_| TpmRc(rc::ECC_POINT).with_parameter(1))?,
        )
    };

    // Steps 7 and 8: the commit value, reduced by the order of the curve.
    let order = curve.order()?;
    let bits = ((order.bits() + 7) / 8 * 8) as u32;
    let (r_bytes, counter) = state
        .commits
        .next(object.public.name_alg, &object.name, bits)?;
    let r_value = crate::tpm::crypto::bn::BigNum::from_bytes(&r_bytes)?.modulo(&order, &ctx)?;

    let as_point = |p: ecc::Point| -> TpmResult<EccPoint> {
        // Step 12: none of the three may be the point at infinity.
        if p.is_at_infinity(&curve) {
            return Err(TpmRc(rc::NO_RESULT));
        }
        let (x, y) = p.coordinates(&curve)?;
        Ok(EccPoint {
            x: Tpm2bEccParameter::new(x)?,
            y: Tpm2bEccParameter::new(y)?,
        })
    };

    // Steps 6, 9, 10 and 11.
    let mut k = EccPoint::default();
    let mut l = EccPoint::default();
    let mut e = EccPoint::default();
    if let Some(base) = &second {
        k = as_point(base.multiply(&curve, &private)?)?;
        l = as_point(base.multiply(&curve, &r_value)?)?;
    }
    if let Some(point) = &first {
        e = as_point(point.multiply(&curve, &r_value)?)?;
    } else if second.is_none() {
        let point = ecc::multiply_generator(&curve, &r_value)?;
        e = as_point(point)?;
        // [r]G is a generated key pair, and the scalar was derived rather than
        // drawn, so ecc::generate did not test it. FIPS 140-3 Table 40 asks
        // for a pair-wise consistency test on every generated pair.
        crate::tpm::fips::pairwise_ecc(
            curve_id,
            &r_value.to_bytes_padded(curve.coordinate_size())?,
            e.x.as_slice(),
            e.y.as_slice(),
            false,
        )?;
    }

    // Steps 13 and 14. Nothing above this point has recorded the counter, so
    // a command that failed at step 12 leaves the array and the count alone.
    state.commits.take(counter);

    respond(move |w| {
        Tpm2bEccPoint { point: k }.marshal(w);
        Tpm2bEccPoint { point: l }.marshal(w);
        Tpm2bEccPoint { point: e }.marshal(w);
        w.u16(counter);
        Ok(())
    })
}

/// TPM2_ZGen_2Phase, Part 3 clause 14.8.
pub fn zgen_2phase(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_qs_b = Tpm2bEccPoint::unmarshal(&mut r)?;
    let in_qe_b = Tpm2bEccPoint::unmarshal(&mut r)?;
    let in_scheme = r.u16()?;
    let counter = r.u16()?;
    r.expect_end()?;

    if !matches!(in_scheme, alg::ECDH | alg::ECMQV) {
        return Err(TpmRc(rc::SCHEME).with_parameter(3));
    }
    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if object.public.object_type != alg::ECC {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    // Part 3 Table 54 names keyA "handle of an unrestricted ECC decryption
    // key". A signing key or a restricted one would be used here as a key
    // agreement scalar, which is not what its attributes allow.
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::DECRYPT)
        || object
            .public
            .object_attributes
            .has(ObjectAttributes::RESTRICTED)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    };
    let curve = ecc::Curve::new(curve_id)?;
    let ctx = crate::tpm::crypto::bn::BnCtx::new()?;
    let order = curve.order()?;
    let d_s = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;

    // Part 1 clause 44.8.4.3 step 4: both peer points are on the curve. This
    // runs before the commit is spent, so a bad point does not consume one.
    let q_s_b = ecc::Point::from_coordinates(
        &curve,
        in_qs_b.point.x.as_slice(),
        in_qs_b.point.y.as_slice(),
    )
    .map_err(|e| e.with_parameter(1))?;
    let q_e_b = ecc::Point::from_coordinates(
        &curve,
        in_qe_b.point.x.as_slice(),
        in_qe_b.point.y.as_slice(),
    )
    .map_err(|e| e.with_parameter(2))?;

    // Clause 44.2.5: the ephemeral private key is the commit value the counter
    // names. TPM2_EC_Ephemeral made it, so the derivation uses the same empty
    // Name it did, and using it here spends it.
    let bits = ((order.bits() + 7) / 8 * 8) as u32;
    let r_bytes = state
        .commits
        .use_counter(config::COMMIT_EPHEMERAL_HASH_ALG, &[], counter, bits)
        .map_err(|_| TpmRc(rc::VALUE).with_parameter(4))?;
    let d_e = crate::tpm::crypto::bn::BigNum::from_bytes(&r_bytes)?.modulo(&order, &ctx)?;
    if d_e.is_zero() {
        return Err(TpmRc(rc::NO_RESULT));
    }

    // A point at infinity is reported as a point with empty coordinates, which
    // is what the notes in clause 44.8.4 ask for.
    let as_point = |p: ecc::Point| -> TpmResult<EccPoint> {
        if p.is_at_infinity(&curve) {
            return Ok(EccPoint::default());
        }
        let (x, y) = p.coordinates(&curve)?;
        Ok(EccPoint {
            x: Tpm2bEccParameter::new(x)?,
            y: Tpm2bEccParameter::new(y)?,
        })
    };

    let (z1, z2) = if in_scheme == alg::ECDH {
        // Clause 44.8.4.2, the Full Unified Model: the static key gives the
        // first result and the ephemeral key the second.
        (
            as_point(q_s_b.multiply(&curve, &d_s)?)?,
            as_point(q_e_b.multiply(&curve, &d_e)?)?,
        )
    } else {
        // Clause 44.8.4.3, Full MQV.
        let q_e_a = ecc::multiply_generator(&curve, &d_e)?;
        // The same pair TPM2_EC_Ephemeral produced, rebuilt here, so it is
        // tested here as well.
        let (ax, ay) = q_e_a.coordinates(&curve)?;
        crate::tpm::fips::pairwise_ecc(
            curve_id,
            &d_e.to_bytes_padded(curve.coordinate_size())?,
            &ax,
            &ay,
            false,
        )?;
        let t_a = d_e
            .add(&d_s.mul(&avf(&curve, &q_e_a, &ctx)?, &ctx)?)?
            .modulo(&order, &ctx)?;
        // Qe,B + [avf(Qe,B)]Qs,B
        let base = q_e_b.add(&curve, &q_s_b.multiply(&curve, &avf(&curve, &q_e_b, &ctx)?)?)?;
        // The cofactor of every curve this TPM implements is one, so [h * tA]
        // is [tA].
        (as_point(base.multiply(&curve, &t_a)?)?, EccPoint::default())
    };

    respond(move |w| {
        Tpm2bEccPoint { point: z1 }.marshal(w);
        Tpm2bEccPoint { point: z2 }.marshal(w);
        Ok(())
    })
}

/// The associated value function of Part 1 clause 44.8.4.3.
///
/// ```text
/// f  := ceil(ceil(log2(n)) / 2)
/// x' := 2^f + (x mod 2^f)
/// ```
fn avf(
    curve: &ecc::Curve,
    point: &ecc::Point,
    ctx: &crate::tpm::crypto::bn::BnCtx,
) -> TpmResult<crate::tpm::crypto::bn::BigNum> {
    use crate::tpm::crypto::bn::BigNum;
    let order = curve.order()?;
    let f = (order.bits() + 1) / 2;
    let (x, _) = point.coordinates(curve)?;
    let x = BigNum::from_bytes(&x)?;
    // 2^f, as a number with only bit f set.
    let mut power = BigNum::new()?;
    power.set_bit(f)?;
    Ok(x.modulo(&power, ctx)?.add(&power)?)
}

/// TPM2_Encapsulate, Part 3 clause 14.11.
///
/// Part 2 Table 229 defines the ECC form as DHKEM from RFC 9180: an ephemeral
/// key is generated, the shared point is run through the key derivation
/// function the key names, and the ephemeral public point is the ciphertext.
pub fn encapsulate(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bSharedSecret;

    let key_handle = request.handle(0)?;
    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if object.public.object_type != alg::ECC {
        // ML-KEM is the other form and is not implemented.
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::DECRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let PublicParms::Ecc { curve_id, kdf, .. } = &object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let PublicId::Ecc(point) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE));
    };
    let hash_alg = kdf.hash_alg().unwrap_or(object.public.name_alg);

    let ephemeral = ecc::generate(*curve_id, &mut state.rng)?;
    let (zx, _) = ecc::ecdh(
        &ephemeral.curve,
        &ephemeral.private,
        point.x.as_slice(),
        point.y.as_slice(),
    )?;
    let secret = crate::tpm::crypto::hmac::kdfe(
        hash_alg,
        &zx,
        "SECRET",
        &ephemeral.public_x,
        point.x.as_slice(),
        (hash::digest_size(hash_alg)? * 8) as u32,
    )?;

    respond(move |w| {
        Tpm2bSharedSecret::new(secret)?.marshal(w);
        // The ciphertext of the ECC form is the ephemeral point.
        w.sized16_with(|w| {
            Tpm2bEccPoint {
                point: EccPoint {
                    x: Tpm2bEccParameter::new(ephemeral.public_x.clone()).unwrap_or_default(),
                    y: Tpm2bEccParameter::new(ephemeral.public_y.clone()).unwrap_or_default(),
                },
            }
            .marshal(w)
        });
        Ok(())
    })
}

/// TPM2_Decapsulate, Part 3 clause 14.12.
pub fn decapsulate(state: &TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::structures::base::Tpm2bSharedSecret;

    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let size = r.u16()? as usize;
    let mut inner = r.sub(size)?;
    r.expect_end()?;
    let ciphertext = Tpm2bEccPoint::unmarshal(&mut inner)?;

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
    let PublicParms::Ecc { curve_id, kdf, .. } = &object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let PublicId::Ecc(point) = &object.public.unique else {
        return Err(TpmRc(rc::TYPE));
    };
    let hash_alg = kdf.hash_alg().unwrap_or(object.public.name_alg);

    let curve = ecc::Curve::new(*curve_id)?;
    let private = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;
    let (zx, _) = ecc::ecdh(
        &curve,
        &private,
        ciphertext.point.x.as_slice(),
        ciphertext.point.y.as_slice(),
    )
    .map_err(|e| e.with_parameter(1))?;
    let secret = crate::tpm::crypto::hmac::kdfe(
        hash_alg,
        &zx,
        "SECRET",
        ciphertext.point.x.as_slice(),
        point.x.as_slice(),
        (hash::digest_size(hash_alg)? * 8) as u32,
    )?;
    respond(move |w| {
        Tpm2bSharedSecret::new(secret)?.marshal(w);
        Ok(())
    })
}

/// TPM2_CertifyX509, Part 3 clause 18.8.
///
/// The command asks the TPM to complete a partial X.509 certificate. Building
/// and re-encoding the DER structure is not implemented, so the command is
/// refused rather than producing a certificate the caller cannot rely on.
pub fn certify_x509(_state: &mut TpmState, _request: &Request) -> TpmResult<Response> {
    Err(TpmRc(rc::COMMAND_CODE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signing_sequence_records_its_key_and_hash() {
        let sequence = Sequence {
            kind: SequenceKind::Hash {
                hash_alg: alg::SHA256,
            },
            auth: Vec::new(),
            buffer: {
                let mut b = 0x8000_0000u32.to_be_bytes().to_vec();
                b.extend_from_slice(&alg::SHA256.to_be_bytes());
                b.extend_from_slice(&counter_bytes(None));
                b.extend_from_slice(b"message");
                b
            },
        };
        let (handle, hash_alg, counter, message) = sequence_binding(&sequence).unwrap();
        assert_eq!(handle, 0x8000_0000);
        assert_eq!(hash_alg, alg::SHA256);
        assert_eq!(counter, None);
        assert_eq!(message, b"message");
    }

    #[test]
    fn a_signing_sequence_records_a_commit_counter() {
        // Part 3 clause 17.5.1 gives the counter at the start of the sequence
        // and needs it at the end, so the sequence has to carry it.
        let sequence = Sequence {
            kind: SequenceKind::Hash {
                hash_alg: alg::SHA256,
            },
            auth: Vec::new(),
            buffer: {
                let mut b = 0x8000_0001u32.to_be_bytes().to_vec();
                b.extend_from_slice(&alg::SHA256.to_be_bytes());
                b.extend_from_slice(&counter_bytes(Some(0x1234)));
                b.extend_from_slice(b"data");
                b
            },
        };
        let (handle, _, counter, message) = sequence_binding(&sequence).unwrap();
        assert_eq!(handle, 0x8000_0001);
        assert_eq!(counter, Some(0x1234));
        assert_eq!(message, b"data");
    }

    #[test]
    fn a_short_sequence_buffer_is_refused() {
        let sequence = Sequence {
            kind: SequenceKind::Event,
            auth: Vec::new(),
            buffer: vec![0u8; 4],
        };
        assert_eq!(sequence_binding(&sequence).unwrap_err(), TpmRc(rc::SEQUENCE));
    }

    #[test]
    fn the_kem_key_depends_on_every_input() {
        let base = ecc_kem_key(alg::SHA256, b"z", b"u", b"v").unwrap();
        assert_eq!(base.0.len(), 32);
        assert_eq!(base.1.len(), 16);
        assert_ne!(base, ecc_kem_key(alg::SHA256, b"y", b"u", b"v").unwrap());
        assert_ne!(base, ecc_kem_key(alg::SHA256, b"z", b"x", b"v").unwrap());
        assert_ne!(base, ecc_kem_key(alg::SHA256, b"z", b"u", b"w").unwrap());
        assert_ne!(base, ecc_kem_key(alg::SHA384, b"z", b"u", b"v").unwrap());
    }
}
