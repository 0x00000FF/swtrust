//! Names and Qualified Names, Part 1 clause 16.
//!
//! The Name of an object is its nameAlg followed by the digest of its public
//! area. The Name of a permanent handle or a PCR is simply the four octets of
//! the handle. The Qualified Name binds an object to its parent:
//! `QN(child) = H(QN(parent) || Name(child))`.

use crate::tpm::constants::{alg, hc, rc};
use crate::tpm::crypto::hash;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::Marshal;
use crate::tpm::structures::base::Tpm2bName;
use crate::tpm::structures::keys::TpmtPublic;
use crate::tpm::structures::nv::NvPublic;

/// The Name of an object with the given public area.
///
/// A public area whose nameAlg is TPM_ALG_NULL has an empty Name, which Part 1
/// clause 16 allows only for an object that cannot be a parent.
pub fn object_name(public: &TpmtPublic) -> TpmResult<Vec<u8>> {
    if public.name_alg == alg::NULL {
        return Ok(Vec::new());
    }
    let body = public.to_bytes();
    let digest = hash::digest(public.name_alg, &body)?;
    let mut out = Vec::with_capacity(2 + digest.len());
    out.extend_from_slice(&public.name_alg.to_be_bytes());
    out.extend_from_slice(&digest);
    Ok(out)
}

/// The Name of an NV Index, computed over its public area.
pub fn nv_name(public: &NvPublic) -> TpmResult<Vec<u8>> {
    let body = public.to_bytes();
    let digest = hash::digest(public.name_alg, &body)?;
    let mut out = Vec::with_capacity(2 + digest.len());
    out.extend_from_slice(&public.name_alg.to_be_bytes());
    out.extend_from_slice(&digest);
    Ok(out)
}

/// The Name of a handle that has no public area: the four handle octets.
pub fn handle_name(handle: u32) -> Vec<u8> {
    handle.to_be_bytes().to_vec()
}

/// True when `handle` names an entity whose Name is the handle itself.
///
/// Part 1 clause 16 lists these as the permanent handles, the PCR and the
/// handles of sessions.
pub fn name_is_handle(handle: u32) -> bool {
    let range = handle >> hc::HR_SHIFT;
    matches!(
        range,
        r if r == (crate::tpm::constants::ht::PCR as u32)
            || r == (crate::tpm::constants::ht::PERMANENT as u32)
            || r == (crate::tpm::constants::ht::HMAC_SESSION as u32)
            || r == (crate::tpm::constants::ht::POLICY_SESSION as u32)
    )
}

/// The Qualified Name of a child under a parent.
///
/// `QN(child) = H_nameAlg(QN(parent) || Name(child))`, where the hash is the
/// child's nameAlg.
pub fn qualified_name(
    child_name_alg: u16,
    parent_qualified_name: &[u8],
    child_name: &[u8],
) -> TpmResult<Vec<u8>> {
    if child_name_alg == alg::NULL {
        return Ok(Vec::new());
    }
    let digest = hash::digest_parts(child_name_alg, &[parent_qualified_name, child_name])?;
    let mut out = Vec::with_capacity(2 + digest.len());
    out.extend_from_slice(&child_name_alg.to_be_bytes());
    out.extend_from_slice(&digest);
    Ok(out)
}

/// Wrap a Name in a TPM2B_NAME, rejecting anything too long for the type.
/// Whether a Name has one of the shapes Part 2 clause 10.4.3 gives it.
///
/// "The type of Name in the structure is determined by context and the size
/// parameter. If size is four, then the Name is a handle. If size is zero, then
/// no Name is present. Otherwise, the size shall be the size of a TPM_ALG_ID
/// plus the size of the digest produced by the indicated hash algorithm." A
/// Name of any other shape stands for no entity, so what is built from it could
/// never be used.
pub fn is_well_formed(name: &[u8]) -> bool {
    if name.is_empty() || name.len() == 4 {
        return true;
    }
    if name.len() < 2 {
        return false;
    }
    // The clause names a TPM_ALG_ID, which is any hash the TCG registry
    // assigns, not only one this TPM implements: the Name may be of an entity
    // on the TPM a policy or a credential is being built for. A hash whose
    // digest size this build does not tabulate is taken at face value, because
    // there is no way to tell it from one the registry has and this table does
    // not; a size that disagrees with a hash the table does have is refused.
    let alg = u16::from_be_bytes([name[0], name[1]]);
    match crate::tpm::structures::base::digest_size(alg) {
        Some(size) => name.len() == 2 + size,
        None => name.len() > 2,
    }
}

pub fn to_tpm2b(name: &[u8]) -> TpmResult<Tpm2bName> {
    Tpm2bName::from_slice(name).map_err(|_| TpmRc(rc::SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{curve, rh};
    use crate::tpm::structures::attributes::{NvAttributes, ObjectAttributes};
    use crate::tpm::structures::base::Tpm2bDigest;
    use crate::tpm::structures::keys::{PublicId, PublicParms};
    use crate::tpm::structures::schemes::{Scheme, SymDef};

    fn ecc_public(name_alg: u16) -> TpmtPublic {
        TpmtPublic {
            object_type: alg::ECC,
            name_alg,
            object_attributes: ObjectAttributes(ObjectAttributes::SIGN_ENCRYPT),
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

    #[test]
    fn a_name_is_the_algorithm_then_the_digest() {
        let p = ecc_public(alg::SHA256);
        let name = object_name(&p).unwrap();
        assert_eq!(name.len(), 2 + 32);
        assert_eq!(&name[0..2], &alg::SHA256.to_be_bytes());
        assert_eq!(&name[2..], &hash::digest(alg::SHA256, &p.to_bytes()).unwrap()[..]);
    }

    #[test]
    fn the_name_changes_with_the_public_area() {
        let a = object_name(&ecc_public(alg::SHA256)).unwrap();
        let mut p = ecc_public(alg::SHA256);
        p.object_attributes = ObjectAttributes(ObjectAttributes::DECRYPT);
        let b = object_name(&p).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_name_changes_with_the_name_algorithm() {
        let a = object_name(&ecc_public(alg::SHA256)).unwrap();
        let b = object_name(&ecc_public(alg::SHA384)).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 34);
        assert_eq!(b.len(), 50);
    }

    #[test]
    fn a_null_name_algorithm_gives_an_empty_name() {
        assert!(object_name(&ecc_public(alg::NULL)).unwrap().is_empty());
    }

    #[test]
    fn permanent_handles_are_named_by_their_handle() {
        assert_eq!(handle_name(rh::OWNER), vec![0x40, 0x00, 0x00, 0x01]);
        assert!(name_is_handle(rh::OWNER));
        assert!(name_is_handle(rh::PLATFORM));
        assert!(name_is_handle(hc::PCR_FIRST));
        assert!(name_is_handle(hc::HMAC_SESSION_FIRST));
        assert!(name_is_handle(hc::POLICY_SESSION_FIRST));
        assert!(!name_is_handle(hc::TRANSIENT_FIRST));
        assert!(!name_is_handle(hc::PERSISTENT_FIRST));
        assert!(!name_is_handle(hc::NV_INDEX_FIRST));
    }

    #[test]
    fn qualified_name_chains_through_the_parent() {
        let parent_qn = handle_name(rh::OWNER);
        let child = object_name(&ecc_public(alg::SHA256)).unwrap();
        let qn = qualified_name(alg::SHA256, &parent_qn, &child).unwrap();
        assert_eq!(qn.len(), 34);
        assert_eq!(&qn[0..2], &alg::SHA256.to_be_bytes());
        assert_eq!(
            &qn[2..],
            &hash::digest_parts(alg::SHA256, &[&parent_qn, &child]).unwrap()[..]
        );

        // A different parent gives a different qualified name for the same
        // child, which is what binds an object to its hierarchy.
        let other = qualified_name(alg::SHA256, &handle_name(rh::PLATFORM), &child).unwrap();
        assert_ne!(qn, other);
    }

    #[test]
    fn nv_index_name_covers_the_public_area() {
        let p = NvPublic {
            nv_index: hc::NV_INDEX_FIRST,
            name_alg: alg::SHA256,
            attributes: NvAttributes(NvAttributes::AUTHREAD | NvAttributes::AUTHWRITE),
            auth_policy: Tpm2bDigest::empty(),
            data_size: 8,
        };
        let name = nv_name(&p).unwrap();
        assert_eq!(name.len(), 34);
        let mut changed = p.clone();
        changed.data_size = 9;
        assert_ne!(nv_name(&changed).unwrap(), name);
    }

    #[test]
    fn a_name_fits_a_tpm2b_name() {
        let name = object_name(&ecc_public(alg::SHA512)).unwrap();
        assert_eq!(name.len(), 66);
        assert_eq!(to_tpm2b(&name).unwrap().len(), 66);
        // Anything longer than a TPMT_HA is refused.
        assert_eq!(to_tpm2b(&vec![0u8; 67]).unwrap_err(), TpmRc(rc::SIZE));
    }
}
