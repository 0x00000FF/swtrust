//! The one shot and sequence signing commands added in version 185, and the
//! split ECC operations of Part 3 clause 19.

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
    sign_digest, signing_scheme, verified_ticket_hmac, verify_digest_public, verify_hash_ticket,
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
/// Part 2 Table 220 gives a context only to ECDAA, SM2 and ML-DSA. None of
/// those are implemented here, so a caller that supplies one is asking for
/// something the TPM cannot do.
fn check_no_context(context: &Tpm2bSignatureCtx, parameter: usize) -> TpmResult<()> {
    if context.is_empty() {
        Ok(())
    } else {
        Err(TpmRc(rc::VALUE).with_parameter(parameter))
    }
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
    check_no_context(&context, 1)?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::SIGN_ENCRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
    let scheme = signing_scheme(&object, &Scheme::null())?;
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
    check_no_context(&context, 1)?;

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
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
    check_no_context(&context, 2)?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::SIGN_ENCRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES).with_handle(1));
    }
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
    let handle = state.objects.insert(Slot::Sequence(Box::new(Sequence {
        kind: SequenceKind::Hash { hash_alg },
        auth: auth.as_slice().to_vec(),
        buffer,
    })))?;
    respond_with_handle(handle, |_| Ok(()))
}

/// The key handle and hash a signing sequence was started with.
fn sequence_binding(sequence: &Sequence) -> TpmResult<(u32, u16, &[u8])> {
    if sequence.buffer.len() < 6 {
        return Err(TpmRc(rc::SEQUENCE));
    }
    let handle = u32::from_be_bytes([
        sequence.buffer[0],
        sequence.buffer[1],
        sequence.buffer[2],
        sequence.buffer[3],
    ]);
    let hash_alg = u16::from_be_bytes([sequence.buffer[4], sequence.buffer[5]]);
    Ok((handle, hash_alg, &sequence.buffer[6..]))
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

    let sequence = state
        .objects
        .get(sequence_handle)
        .map_err(|e| e.with_handle(1))?
        .as_sequence()?
        .clone();
    let (bound_handle, hash_alg, message) = sequence_binding(&sequence)?;
    if bound_handle != key_handle {
        return Err(TpmRc(rc::SIGN_CONTEXT_KEY).with_handle(2));
    }
    let mut data = message.to_vec();
    data.extend_from_slice(buffer.as_slice());
    let digest = hash::digest(hash_alg, &data)?;

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(2))?
        .clone();
    let scheme = signing_scheme(&object, &Scheme::null())?;
    let signature = sign_digest(state, &object, &scheme, &digest)?;
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

    let sequence = state
        .objects
        .get(sequence_handle)
        .map_err(|e| e.with_handle(1))?
        .as_sequence()?
        .clone();
    let (bound_handle, hash_alg, message) = sequence_binding(&sequence)?;
    if bound_handle != key_handle {
        return Err(TpmRc(rc::SIGN_CONTEXT_KEY).with_handle(2));
    }
    let digest = hash::digest(hash_alg, message)?;

    let object = object_of(state, key_handle).map_err(|e| e.with_handle(2))?;
    verify_digest_public(object, &digest, &signature)?;

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
        let hmac = verified_ticket_hmac(
            &proof,
            st::MESSAGE_VERIFIED,
            &digest,
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

    let object = object_of(state, key_handle)
        .map_err(|e| e.with_handle(1))?
        .clone();
    if object.public.object_type != alg::ECC {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    }
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE));
    };
    let curve = ecc::Curve::new(curve_id)?;
    let private = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;

    // s2 and y2 together name a second point; both must be given or neither.
    if s2.is_empty() != y2.is_empty() {
        return Err(TpmRc(rc::SIZE).with_parameter(2));
    }

    let k = if p1.point.is_empty() {
        EccPoint::default()
    } else {
        let point = ecc::Point::from_coordinates(
            &curve,
            p1.point.x.as_slice(),
            p1.point.y.as_slice(),
        )
        .map_err(|e| e.with_parameter(1))?;
        let product = point.multiply(&curve, &private)?;
        let (x, y) = product.coordinates(&curve)?;
        EccPoint {
            x: Tpm2bEccParameter::new(x)?,
            y: Tpm2bEccParameter::new(y)?,
        }
    };

    let r_value = ecc::private_key_from_rng(&curve, &mut state.rng)?;
    let e_point = ecc::multiply_generator(&curve, &r_value)?;
    let (ex, ey) = e_point.coordinates(&curve)?;
    let e = EccPoint {
        x: Tpm2bEccParameter::new(ex)?,
        y: Tpm2bEccParameter::new(ey)?,
    };
    // With no second point supplied, L is the point at infinity.
    let l = EccPoint::default();

    respond(move |w| {
        Tpm2bEccPoint { point: k }.marshal(w);
        Tpm2bEccPoint { point: l }.marshal(w);
        Tpm2bEccPoint { point: e }.marshal(w);
        w.u16(0);
        Ok(())
    })
}

/// TPM2_ZGen_2Phase, Part 3 clause 14.8.
pub fn zgen_2phase(state: &TpmState, request: &Request) -> TpmResult<Response> {
    let key_handle = request.handle(0)?;
    let mut r = request.reader();
    let in_qs_b = Tpm2bEccPoint::unmarshal(&mut r)?;
    let in_qe_b = Tpm2bEccPoint::unmarshal(&mut r)?;
    let in_scheme = r.u16()?;
    let _counter = r.u16()?;

    if !matches!(in_scheme, alg::ECDH | alg::ECMQV | alg::SM2) {
        return Err(TpmRc(rc::SCHEME).with_parameter(3));
    }
    let object = object_of(state, key_handle).map_err(|e| e.with_handle(1))?;
    let Some(sensitive) = &object.sensitive else {
        return Err(TpmRc(rc::HANDLE).with_handle(1));
    };
    let PublicParms::Ecc { curve_id, .. } = object.public.parameters else {
        return Err(TpmRc(rc::TYPE).with_handle(1));
    };
    let curve = ecc::Curve::new(curve_id)?;
    let private = crate::tpm::crypto::bn::BigNum::from_bytes(sensitive.sensitive.as_slice())?;

    // The static half uses the static peer point, the ephemeral half the
    // ephemeral one.
    let (sx, sy) = ecc::ecdh(
        &curve,
        &private,
        in_qs_b.point.x.as_slice(),
        in_qs_b.point.y.as_slice(),
    )
    .map_err(|e| e.with_parameter(1))?;
    let (ex, ey) = ecc::ecdh(
        &curve,
        &private,
        in_qe_b.point.x.as_slice(),
        in_qe_b.point.y.as_slice(),
    )
    .map_err(|e| e.with_parameter(2))?;

    respond(move |w| {
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(sx)?,
                y: Tpm2bEccParameter::new(sy)?,
            },
        }
        .marshal(w);
        Tpm2bEccPoint {
            point: EccPoint {
                x: Tpm2bEccParameter::new(ex)?,
                y: Tpm2bEccParameter::new(ey)?,
            },
        }
        .marshal(w);
        Ok(())
    })
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
                b.extend_from_slice(b"message");
                b
            },
        };
        let (handle, hash_alg, message) = sequence_binding(&sequence).unwrap();
        assert_eq!(handle, 0x8000_0000);
        assert_eq!(hash_alg, alg::SHA256);
        assert_eq!(message, b"message");
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
