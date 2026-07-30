//! Attestation, Part 3 clause 18, and the audit digests of clause 21.

use crate::tpm::constants::{alg, rc, rh};
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

use super::crypto::{sign_digest, signing_scheme};
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
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::SIGN_ENCRYPT)
    {
        return Err(TpmRc(rc::ATTRIBUTES));
    }
    if !object
        .public
        .object_attributes
        .has(ObjectAttributes::RESTRICTED)
    {
        // Only a restricted signing key may sign TPM generated structures, so
        // that an ordinary key cannot be used to forge one.
        return Err(TpmRc(rc::ATTRIBUTES));
    }
    Ok(object.clone())
}

/// Build a TPMS_ATTEST and sign it.
///
/// When `sign_handle` is TPM_RH_NULL the structure is returned unsigned, which
/// Part 3 clause 18.1 allows so a caller can inspect the values.
fn attest_and_sign(
    state: &mut TpmState,
    sign_handle: u32,
    in_scheme: &Scheme,
    extra_data: &Tpm2bData,
    attested: Attested,
) -> TpmResult<(Tpm2bAttest, TpmtSignature)> {
    let (qualified_signer, object) = if sign_handle == rh::NULL {
        (Vec::new(), None)
    } else {
        let object = signing_object(state, sign_handle).map_err(|e| e.with_handle(1))?;
        (object.qualified_name.clone(), Some(object))
    };

    let attest = Attest::new(
        Tpm2bName::from_slice(&qualified_signer)?,
        extra_data.clone(),
        clock_info(state),
        crate::tpm::config::FIRMWARE_VERSION_1 as u64,
        attested,
    );
    let body = attest.to_bytes();

    let signature = match object {
        None => TpmtSignature::null(),
        Some(object) => {
            let scheme = signing_scheme(&object, in_scheme)?;
            let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_parameter(1))?;
            let digest = hash::digest(hash_alg, &body)?;
            sign_digest(state, &object, &scheme, &digest)?
        }
    };
    Ok((Tpm2bAttest::new(body)?, signature))
}

/// TPM2_Certify, Part 3 clause 18.2.
pub fn certify(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let object_handle = request.handle(0)?;
    let sign_handle = request.handle(1)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;

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
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)
            .map_err(|e| if e.0 & 0xF00 == 0x100 { e.with_handle(2) } else { e })?;
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
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let creation_hash = Tpm2bDigest::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;
    let creation_ticket = Ticket::unmarshal_tagged(&mut r, &[st::CREATION])?;

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
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)?;
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
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;
    let selection = TpmlPcrSelection::unmarshal(&mut r)?;

    // The digest uses the nameAlg of the signing key, as clause 18.4.3 says.
    let name_alg = if sign_handle == rh::NULL {
        alg::SHA256
    } else {
        signing_object(state, sign_handle)
            .map_err(|e| e.with_handle(1))?
            .public
            .name_alg
    };
    let filtered = state.pcr.filter_selection(&selection);
    let pcr_digest = state.pcr.selection_digest(name_alg, &filtered)?;

    let attested = Attested::Quote {
        pcr_select: filtered,
        pcr_digest: Tpm2bDigest::new(pcr_digest)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)?;
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
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;

    let attested = Attested::Time {
        time: TimeInfo {
            time: state.clock.time,
            clock_info: clock_info(state),
        },
        firmware_version: crate::tpm::config::FIRMWARE_VERSION_1 as u64,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)?;
    respond(move |w| {
        info.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

/// TPM2_NV_Certify, Part 3 clause 31.16.
pub fn nv_certify(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let sign_handle = request.handle(0)?;
    let _auth_handle = request.handle(1)?;
    let nv_handle = request.handle(2)?;
    let mut r = request.reader();
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;
    let size = r.u16()?;
    let offset = r.u16()?;

    let index = state.nv.get(nv_handle).map_err(|e| e.with_handle(3))?;
    if index.read_locked {
        return Err(TpmRc(rc::NV_LOCKED));
    }
    let data = index.read(offset, size)?;
    let index_name = index.name()?;

    let attested = Attested::Nv {
        index_name: Tpm2bName::from_slice(&index_name)?,
        offset,
        nv_contents: Tpm2bMaxNvBuffer::new(data)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)?;
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
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;

    let session = state
        .sessions
        .get(session_handle)
        .map_err(|e| e.with_handle(3))?;
    if !session.audit.is_audit {
        return Err(TpmRc(rc::TYPE).with_handle(3));
    }
    let attested = Attested::SessionAudit {
        exclusive_session: session.audit.is_exclusive,
        session_digest: Tpm2bDigest::from_slice(&session.audit.digest)?,
    };
    let (info, signature) =
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)?;
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
    let qualifying_data = Tpm2bData::unmarshal(&mut r)?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r)?;

    let digest_alg = if state.audit.alg == alg::NULL {
        crate::tpm::config::CONTEXT_INTEGRITY_HASH_ALG
    } else {
        state.audit.alg
    };
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
        attest_and_sign(state, sign_handle, &in_scheme, &qualifying_data, attested)?;
    // Part 3 clause 18.5.2 resets the digest once it has been reported.
    state.audit.digest.clear();
    state.audit.counter = state.audit.counter.wrapping_add(1);
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
    let audit_alg = r.u16()?;
    let set_list = TpmlCc::unmarshal(&mut r)?;
    let clear_list = TpmlCc::unmarshal(&mut r)?;

    if audit_alg != alg::NULL {
        if !hash::is_supported(audit_alg) {
            return Err(TpmRc(rc::HASH).with_parameter(1));
        }
        if audit_alg != state.audit.alg {
            // Changing the algorithm restarts the digest.
            state.audit.alg = audit_alg;
            state.audit.digest.clear();
        }
    }
    for code in &set_list.items {
        if super::table::lookup(*code).is_none() {
            return Err(TpmRc(rc::VALUE).with_parameter(2));
        }
        if !state.audit.commands.contains(code) {
            state.audit.commands.push(*code);
        }
    }
    for code in &clear_list.items {
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
    fn only_a_restricted_signing_key_may_attest() {
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
        assert_eq!(
            signing_object(&state, handle).unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );

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

        // A decryption key cannot attest at all.
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
        assert_eq!(
            signing_object(&state, handle).unwrap_err(),
            TpmRc(rc::ATTRIBUTES)
        );
    }

    #[test]
    fn an_unsigned_attestation_still_carries_the_magic_and_the_values() {
        let mut state = TpmState::manufacture().unwrap();
        let (info, signature) = attest_and_sign(
            &mut state,
            rh::NULL,
            &Scheme::null(),
            &Tpm2bData::from_slice(b"qualifier").unwrap(),
            Attested::Time {
                time: TimeInfo::default(),
                firmware_version: 1,
            },
        )
        .unwrap();
        assert!(signature.is_null());
        let attest = Attest::from_bytes(info.as_slice()).unwrap();
        assert_eq!(attest.magic, TPM_GENERATED_VALUE);
        assert_eq!(attest.extra_data.as_slice(), b"qualifier");
        assert!(attest.qualified_signer.is_empty());
    }
}
