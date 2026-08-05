//! Attestation, Part 3 clause 18, and the audit digests of clause 21.

use crate::tpm::constants::{alg, cc, rc, rh};
use crate::tpm::core::object::Object;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::hash;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Unmarshal};
use crate::tpm::structures::attest::{Attest, Attested, TimeInfo};
use crate::tpm::structures::attributes::ObjectAttributes;
use crate::tpm::structures::base::{
    Tpm2bAttest, Tpm2bData, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bName,
};
use crate::tpm::structures::lists::TpmlPcrSelection;
use crate::tpm::structures::schemes::Scheme;
use crate::tpm::structures::signature::TpmtSignature;

use super::crypto::{sign_digest, signing_scheme_at};
use super::dispatch::{Request, Response};
use super::execute::respond;
use super::management::clock_info;

/// The object a signing handle names.
fn signing_object(state: &TpmState, handle: u32) -> TpmResult<Object> {
    let object = if crate::tpm::core::object::ObjectSlots::is_transient(handle) {
        state.objects.object(handle)?
    } else {
        state
            .persistent
            .get(&handle)
            .ok_or(TpmRc(rc::HANDLE))?
    };
    // Part 3 clause 18.1 gives the attestation commands one rule about the key:
    // "If the sign attribute is not SET in the key referenced by signHandle then
    // the TPM shall return TPM_RC_KEY."
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::SIGN_ENCRYPT)
    {
        return Err(TpmRc(rc::KEY));
    }
    // A restricted key is not required. The clause only observes that
    // "attestation commands typically use a restricted, sensitiveDataOrigin
    // signing key. A key that is not restricted can sign any digest and would
    // permit a forged attestation", which is advice to whoever trusts the
    // result rather than a rule for the TPM. The same clause says outright that
    // "for a signing key that is not restricted, the caller may specify the
    // scheme to be used", so such a key reaching here is expected. Windows
    // quotes with one, and refusing it left BitLocker unable to bind a key to
    // the PCR values it had just measured.
    Ok(object.clone())
}

/// Hide the values an attestation would otherwise let a verifier correlate.
///
/// Part 3 clause 18.1 computes the value as
/// `KDFa(signHandle->nameAlg, shProof, "OBFUSCATE", signHandle->QN, 0, 128)`,
/// takes 64 of the returned bits into the version number and 32 each into the
/// two counters, and says of TPM_RH_NULL that "the data structure is produced
/// but not signed; and the values in the signed data structure are obfuscated",
/// with the context integrity hash standing in for the nameAlg.
fn obfuscated(
    state: &TpmState,
    sign_handle: u32,
    qualified_name: &[u8],
) -> TpmResult<(crate::tpm::structures::attest::ClockInfo, u64)> {
    let mut clock = clock_info(state);
    let mut firmware = crate::tpm::config::FIRMWARE_VERSION_1 as u64;
    let hierarchy = if sign_handle == rh::NULL {
        rh::NULL
    } else {
        signing_object(state, sign_handle)?.hierarchy
    };
    if matches!(hierarchy, rh::ENDORSEMENT | rh::PLATFORM) {
        return Ok((clock, firmware));
    }
    let name_alg = if sign_handle == rh::NULL {
        crate::tpm::config::CONTEXT_INTEGRITY_HASH_ALG
    } else {
        signing_object(state, sign_handle)?.public.name_alg
    };
    let value = crate::tpm::crypto::hmac::kdfa(
        name_alg,
        state.hierarchy_proof(rh::OWNER)?,
        "OBFUSCATE",
        qualified_name,
        &[],
        128,
    )?;
    firmware = firmware.wrapping_add(u64::from_be_bytes(value[..8].try_into().unwrap()));
    clock.reset_count = clock
        .reset_count
        .wrapping_add(u32::from_be_bytes(value[8..12].try_into().unwrap()));
    clock.restart_count = clock
        .restart_count
        .wrapping_add(u32::from_be_bytes(value[12..16].try_into().unwrap()));
    Ok((clock, firmware))
}

/// Build and sign an attestation structure.
///
/// When `sign_handle` is TPM_RH_NULL the structure is returned unsigned, which
/// Part 3 clause 18.1 allows so a caller can inspect the values.
///
/// `sign_handle_number` is which handle of the command signHandle is, counting
/// from one. Part 2 clause 6.6.2 puts that number in the N field of a response
/// code, and the attestation commands do not agree on where the signing key
/// sits: TPM2_Quote and TPM2_CertifyCreation take it first, TPM2_Certify and
/// TPM2_GetTime take it second.
fn attest_and_sign(
    state: &mut TpmState,
    sign_handle: u32,
    sign_handle_number: usize,
    in_scheme: &Scheme,
    extra_data: &Tpm2bData,
    attested: Attested,
    scheme_parameter: usize,
) -> TpmResult<(Tpm2bAttest, TpmtSignature)> {
    let (object, scheme) = if sign_handle == rh::NULL {
        (None, None)
    } else {
        let object =
            signing_object(state, sign_handle).map_err(|e| e.with_handle(sign_handle_number))?;
        let scheme = signing_scheme_at(&object, in_scheme, scheme_parameter)?;
        (Some(object), Some(scheme))
    };

    // Part 1 clause 44.3.3.3 hides the signer when the scheme is anonymous.
    let anonymous = scheme
        .map(|s| crate::tpm::structures::schemes::is_anonymous(s.scheme))
        .unwrap_or(false);

    // Clause 21.5 says that with an anonymous scheme the qualifiedSigner of
    // the attestation is an Empty Buffer, because the qualified name would
    // otherwise say exactly which key signed.
    let qualified_signer = match (&object, anonymous) {
        (Some(o), false) => o.qualified_name.clone(),
        _ => Vec::new(),
    };
    // The same clause empties the qualified name of a certified key, which
    // would name the signer's parentage just as clearly.
    let attested = match (attested, anonymous) {
        (Attested::Certify { name, .. }, true) => Attested::Certify {
            name,
            qualified_name: Tpm2bName::empty(),
        },
        (other, _) => other,
    };

    // Part 3 clause 18.1: the clock information and firmware version "may be
    // considered privacy-sensitive because they would aid in the correlation
    // of attestations by different keys. To provide improved privacy, the
    // resetCount, restartCount, and firmwareVersion numbers are obfuscated
    // when the signing key is not in the Endorsement or Platform hierarchies."
    // Part 3 clause 18.1 takes signHandle->QN as the contextU of the KDF, so
    // that "the obfuscation value for each signing key will be unique to that
    // key in a specific location". An anonymous attestation leaves the Name out
    // of the structure but the key still has one, and the QN of TPM_RH_NULL is
    // TPM_RH_NULL rather than nothing at all.
    let obfuscation_name = if sign_handle == rh::NULL {
        rh::NULL.to_be_bytes().to_vec()
    } else {
        signing_object(state, sign_handle)?.qualified_name.clone()
    };
    let (clock, firmware) = obfuscated(state, sign_handle, &obfuscation_name)?;
    let attest = Attest::new(
        Tpm2bName::from_slice(&qualified_signer)?,
        extra_data.clone(),
        clock,
        firmware,
        attested,
    );
    let body = attest.to_bytes();

    let signature = match (object, scheme) {
        (Some(object), Some(scheme)) => {
            let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_parameter(1))?;
            let digest = if anonymous {
                // Clause 44.3.3.3 sets both qualifiedSigner and extraData to
                // the Empty Buffer before the block is hashed, then Equation
                // 61 gives the value to sign:
                //   P := H(qualifyingData || H(TPMS_ATTEST))
                let blinded = Attest::new(
                    Tpm2bName::empty(),
                    Tpm2bData::empty(),
                    attest.clock_info,
                    attest.firmware_version,
                    attest.attested.clone(),
                )
                .to_bytes();
                let inner = hash::digest(hash_alg, &blinded)?;
                hash::digest_parts(hash_alg, &[extra_data.as_slice(), &inner])?
            } else {
                hash::digest(hash_alg, &body)?
            };
            // Part 2 clause 6.6.2 names the parameter an error belongs to,
            // and for a commit counter that is the scheme this command was
            // given.
            sign_digest(
                state,
                &object,
                &scheme,
                &digest,
                super::crypto::SignParameters::at(0, scheme_parameter),
            )
            .map_err(|e| {
                super::crypto::with_counter_parameter(e, &object, scheme_parameter)
            })?
        }
        _ => TpmtSignature::null(),
    };
    Ok((Tpm2bAttest::new(body)?, signature))
}

/// TPM2_Certify, Part 3 clause 18.2.
pub fn certify(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let object_handle = request.handle(0)?;
    let sign_handle = request.handle(1)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    let object = if crate::tpm::core::object::ObjectSlots::is_transient(object_handle) {
        state.objects.object(object_handle).map_err(|e| e.with_handle(1))?
    } else {
        state
            .persistent
            .get(&object_handle)
            .ok_or(TpmRc(rc::HANDLE).with_handle(1))?
    };
    let attested = Attested::Certify {
        name: Tpm2bName::from_slice(&object.name)?,
        qualified_name: Tpm2bName::from_slice(&object.qualified_name)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 2, &in_scheme, &qualifying_data, attested, 2)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_CertifyCreation, Part 3 clause 18.3.
pub fn certify_creation(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    use crate::tpm::constants::st;
    use crate::tpm::structures::signature::Ticket;

    let sign_handle = request.handle(0)?;
    let object_handle = request.handle(1)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let creation_hash = Tpm2bDigest::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(3))?;
    let creation_ticket =
        Ticket::unmarshal_tagged(&mut r, &[st::CREATION]).map_err(|e| e.with_parameter(4))?;
    r.expect_end()?;

    let object = if crate::tpm::core::object::ObjectSlots::is_transient(object_handle) {
        state
            .objects
            .object(object_handle)
            .map_err(|e| e.with_handle(2))?
    } else {
        state
            .persistent
            .get(&object_handle)
            .ok_or(TpmRc(rc::HANDLE).with_handle(2))?
    };
    let object_name = object.name.clone();

    // The ticket must be the one this TPM produced for this object and
    // creation data.
    let proof = state
        .hierarchy_proof(creation_ticket.hierarchy)
        .map_err(|_| TpmRc(rc::TICKET).with_parameter(4))?
        .to_vec();
    let expected = crate::tpm::crypto::hmac::hmac_parts(
        crate::tpm::config::CONTEXT_INTEGRITY_HASH_ALG,
        &proof,
        &[
            &st::CREATION.to_be_bytes(),
            &object_name,
            creation_hash.as_slice(),
        ],
    )?;
    if !crate::tpm::core::protect::constant_time_eq(&expected, creation_ticket.digest.as_slice()) {
        return Err(TpmRc(rc::TICKET).with_parameter(4));
    }

    let attested = Attested::Creation {
        object_name: Tpm2bName::from_slice(&object_name)?,
        creation_hash: creation_hash.clone(),
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 1, &in_scheme, &qualifying_data, attested, 3)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_Quote, Part 3 clause 18.4.
pub fn quote(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sign_handle = request.handle(0)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    let selection = TpmlPcrSelection::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    r.expect_end()?;

    // Part 3 clause 18.4.1: "the TPM will hash the list of PCR selected by
    // PCRselect using the hash algorithm in the selected signing scheme. If
    // the selected signing scheme or the scheme hash algorithm is
    // TPM_ALG_NULL, then the TPM shall return TPM_RC_SCHEME." The nameAlg of
    // the key is a different algorithm whenever the two were chosen apart.
    let hash_alg = if sign_handle == rh::NULL {
        // The clause makes no exception for an unsigned quote: without a
        // scheme there is no algorithm to hash the registers with.
        in_scheme
            .hash_alg()
            .ok_or(TpmRc(rc::SCHEME).with_parameter(2))?
    } else {
        let object = signing_object(state, sign_handle).map_err(|e| e.with_handle(1))?;
        let scheme = super::crypto::signing_scheme_at(&object, &in_scheme, 2)?;
        scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_parameter(2))?
    };
    let filtered = state.pcr.filter_selection(&selection);
    let pcr_digest = state.pcr.selection_digest(hash_alg, &filtered)?;

    let attested = Attested::Quote {
        pcr_select: filtered,
        pcr_digest: Tpm2bDigest::new(pcr_digest)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 1, &in_scheme, &qualifying_data, attested, 2)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_GetTime, Part 3 clause 18.6.
pub fn get_time(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sign_handle = request.handle(1)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    let attested = Attested::Time {
        time: TimeInfo {
            time: state.clock.time,
            clock_info: clock_info(state),
        },
        firmware_version: crate::tpm::config::FIRMWARE_VERSION_1 as u64,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 2, &in_scheme, &qualifying_data, attested, 2)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_NV_Certify, Part 3 clause 31.16.
pub fn nv_certify(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sign_handle = request.handle(0)?;
    let auth_handle = request.handle(1)?;
    let nv_handle = request.handle(2)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    let size = r.u16().map_err(|e| e.with_parameter(3))?;
    let offset = r.u16().map_err(|e| e.with_parameter(4))?;
    r.expect_end()?;

    let index = state.nv.get(nv_handle).map_err(|e| e.with_handle(3))?;
    // Part 3 clause 31.16.1 certifies only what the authorization is entitled
    // to read, so the same read authority TPM2_NV_Read applies holds here.
    // The Index authorization is the second one, so that is the session whose
    // type decides between the policy and the value attributes.
    let is_policy = super::nv::auth_is_policy(state, request, 1);
    super::nv::check_read_authority(index, auth_handle, is_policy)
        .map_err(|e| e.with_handle(2))?;
    if index.read_locked {
        return Err(TpmRc(rc::NV_LOCKED));
    }
    let index_name = index.name()?;

    // Part 3 clause 31.16.1: "If size and offset are both zero (0), then
    // certifyInfo in the response will contain a TPMS_NV_DIGEST_CERTIFY_INFO,
    // otherwise, it will contain a TPMS_NV_CERTIFY_INFO. The digest in the
    // TPMS_NV_DIGEST_CERTIFY_INFO is created using the hash algorithm of the
    // selected signing scheme. If size and offset are both zero and signHandle
    // is TPM_RH_NULL, the digest is computed using the hash algorithm provided
    // in inScheme, unless the scheme or hash algorithm is TPM_ALG_NULL, in
    // which case the TPM shall return TPM_RC_SCHEME." The note beside it gives
    // the reason: this form "permits TPM2_NV_Certify() to certify NV Index
    // contents that are larger than MAX_NV_BUFFER_SIZE".
    let attested = if size == 0 && offset == 0 {
        if !index.written() {
            return Err(TpmRc(rc::NV_UNINITIALIZED));
        }
        let contents = index.data.clone();
        let hash_alg = if sign_handle == rh::NULL {
            in_scheme
                .hash_alg()
                .ok_or(TpmRc(rc::SCHEME).with_parameter(2))?
        } else {
            let object = signing_object(state, sign_handle).map_err(|e| e.with_handle(1))?;
            let scheme = super::crypto::signing_scheme_at(&object, &in_scheme, 2)?;
            scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_parameter(2))?
        };
        Attested::NvDigest {
            index_name: Tpm2bName::from_slice(&index_name)?,
            nv_digest: Tpm2bDigest::new(crate::tpm::crypto::hash::digest(hash_alg, &contents)?)?,
        }
    } else {
        let data = index.read(offset, size)?;
        Attested::Nv {
            index_name: Tpm2bName::from_slice(&index_name)?,
            offset,
            nv_contents: Tpm2bMaxNvBuffer::new(data)?,
        }
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 1, &in_scheme, &qualifying_data, attested, 2)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_GetSessionAuditDigest, Part 3 clause 18.7.
pub fn get_session_audit_digest(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sign_handle = request.handle(1)?;
    let session_handle = request.handle(2)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    let session = state
        .sessions
        .get(session_handle)
        .map_err(|e| e.with_handle(3))?;
    if !session.audit.is_audit {
        return Err(TpmRc(rc::TYPE).with_handle(3));
    }
    let attested = Attested::SessionAudit {
        // Part 1 clause 17.2 keeps the exclusive status on the TPM, not on the
        // session, so it is read from there.
        exclusive_session: state.audit.exclusive_session == session_handle,
        session_digest: Tpm2bDigest::from_slice(&session.audit.digest)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 2, &in_scheme, &qualifying_data, attested, 2)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_GetCommandAuditDigest, Part 3 clause 18.5.
pub fn get_command_audit_digest(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sign_handle = request.handle(1)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    r.expect_end()?;

    let digest_alg = state.audit.alg;
    let audit_digest = state.audit.digest.clone();
    let counter = state.audit.counter;
    // The command digest covers the list of audited commands.
    let mut w = crate::tpm::marshal::Writer::new();
    for c in &state.audit.commands {
        w.u32(*c);
    }
    let command_digest = hash::digest(digest_alg, &w.finish()?)?;

    let attested = Attested::CommandAudit {
        audit_counter: counter,
        digest_alg,
        audit_digest: Tpm2bDigest::from_slice(&audit_digest)?,
        command_digest: Tpm2bDigest::new(command_digest)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, 2, &in_scheme, &qualifying_data, attested, 2)?;
    // Part 1 clause 32 ends the audit log when the command returns a
    // signature, so a report taken with TPM_RH_NULL leaves the log running.
    // The counter is not touched here; it moves when the next log starts.
    if sign_handle != rh::NULL {
        state.audit.digest.clear();
    }
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_SetCommandCodeAuditStatus, Part 3 clause 21.2.
pub fn set_command_code_audit_status(
    state: &mut TpmState,
    request: &Request,
) -> TpmResult<Response> {
    use crate::tpm::structures::lists::TpmlCc;

    let mut r = request.reader();
    let audit_alg = r.u16().map_err(|e| e.with_parameter(1))?;
    let set_list = TpmlCc::unmarshal(&mut r).map_err(|e| e.with_parameter(2))?;
    let clear_list = TpmlCc::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    r.expect_end()?;

    if audit_alg != alg::NULL && !hash::is_supported(audit_alg) {
        return Err(TpmRc(rc::HASH).with_parameter(1));
    }
    // Part 3 clause 21.2.1 lets one command change the algorithm or the list,
    // never both.
    if audit_alg != alg::NULL && audit_alg != state.audit.alg {
        if !set_list.items.is_empty() || !clear_list.items.is_empty() {
            return Err(TpmRc(rc::VALUE).with_parameter(1));
        }
        state.audit.alg = audit_alg;
        state.audit.digest.clear();
        // Changing the algorithm is not itself an audited event.
        state.command_audit_suppressed = true;
        return respond(|_| Ok(()));
    }

    // A command code that is not implemented or that is already in the state
    // asked for is not an error, it simply changes nothing. setList is applied
    // first so a code in both lists ends up not audited.
    for code in &set_list.items {
        if super::table::lookup(*code).is_none() {
            continue;
        }
        if !state.audit.commands.contains(code) {
            state.audit.commands.push(*code);
        }
    }
    for code in &clear_list.items {
        // TPM2_SetCommandCodeAuditStatus is always audited, so asking to
        // clear it is ignored.
        if *code == cc::SetCommandCodeAuditStatus {
            continue;
        }
        state.audit.commands.retain(|c| c != code);
    }
    state.audit.commands.sort_unstable();
    respond(|_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::TPM_GENERATED_VALUE;
    use crate::tpm::structures::keys::{PublicId, PublicParms, TpmtPublic};
    use crate::tpm::structures::schemes::{EccPoint, SymDef};

    fn signing_public(attrs: u32) -> TpmtPublic {
        TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: crate::tpm::structures::attributes::ObjectAttributes(attrs),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                curve_id: crate::tpm::constants::curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(EccPoint::default()),
        }
    }

    #[test]
    fn any_signing_key_may_attest_and_nothing_else_may() {
        let mut state = TpmState::manufacture().unwrap();
        let plain = Object::new(
            signing_public(ObjectAttributes::SIGN_ENCRYPT),
            None,
            rh::OWNER,
            &rh::OWNER.to_be_bytes(),
            true,
        )
        .unwrap();
        let handle = state
            .objects
            .insert(crate::tpm::core::object::Slot::Object(Box::new(plain)))
            .unwrap();
        // Part 3 clause 18.1 asks only for the sign attribute. A key that is
        // not restricted is named there as one the caller may choose a scheme
        // for, so it attests too; that it "would permit a forged attestation"
        // is a warning to whoever trusts the result, not a rule for the TPM.
        assert!(signing_object(&state, handle).is_ok());

        let restricted = Object::new(
            signing_public(ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::RESTRICTED),
            None,
            rh::OWNER,
            &rh::OWNER.to_be_bytes(),
            true,
        )
        .unwrap();
        let handle = state
            .objects
            .insert(crate::tpm::core::object::Slot::Object(Box::new(restricted)))
            .unwrap();
        assert!(signing_object(&state, handle).is_ok());

        // A key without the sign attribute cannot attest, and the clause
        // names the answer: "the TPM shall return TPM_RC_KEY".
        let decrypting = Object::new(
            signing_public(ObjectAttributes::DECRYPT),
            None,
            rh::OWNER,
            &rh::OWNER.to_be_bytes(),
            true,
        )
        .unwrap();
        let handle = state
            .objects
            .insert(crate::tpm::core::object::Slot::Object(Box::new(decrypting)))
            .unwrap();
        assert_eq!(signing_object(&state, handle).unwrap_err(), TpmRc(rc::KEY));
    }

    #[test]
    fn an_unsigned_attestation_still_carries_the_magic_and_the_values() {
        let mut state = TpmState::manufacture().unwrap();
        let (info, signature) = attest_and_sign(
            &mut state,
            rh::NULL,
            1,
            &Scheme::null(),
            &Tpm2bData::from_slice(b"qualifier").unwrap(),
            Attested::Time {
                time: TimeInfo::default(),
                firmware_version: 1,
            },
            2,
        )
        .unwrap();
        assert!(signature.is_null());
        let attest = Attest::from_bytes(info.as_slice()).unwrap();
        assert_eq!(attest.magic, TPM_GENERATED_VALUE);
        assert_eq!(attest.extra_data.as_slice(), b"qualifier");
        assert!(attest.qualified_signer.is_empty());
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use crate::tpm::core::state::TpmState;

    #[test]
    fn a_key_outside_the_two_hierarchies_has_its_counters_hidden() {
        // Part 3 clause 18.1: "the resetCount, restartCount, and
        // firmwareVersion numbers are obfuscated when the signing key is not in
        // the Endorsement or Platform hierarchies", and a null signing key is
        // obfuscated too.
        let mut state = TpmState::manufacture().unwrap();
        state.on_startup_clear(0).unwrap();
        let plain = clock_info(&state);

        let (hidden, firmware) = obfuscated(&state, rh::NULL, &rh::NULL.to_be_bytes()).unwrap();
        assert!(
            hidden.reset_count != plain.reset_count
                || hidden.restart_count != plain.restart_count,
            "the counters came through unchanged"
        );
        assert_ne!(
            firmware,
            crate::tpm::config::FIRMWARE_VERSION_1 as u64,
            "the version came through unchanged"
        );

        // A different qualified name gives a different value, which is what
        // stops one attestation being tied to another.
        let (other, _) = obfuscated(&state, rh::NULL, b"another name").unwrap();
        assert_ne!(
            (hidden.reset_count, hidden.restart_count),
            (other.reset_count, other.restart_count),
            "two keys were hidden the same way"
        );
    }
}
