//! Protected storage, Part 1 clause 24.
//!
//! An object leaves the TPM wrapped by its parent: the sensitive area is
//! encrypted with a symmetric key derived from the parent's seed and the
//! child's Name, and the result is covered by an HMAC keyed from the same seed.
//! The same construction protects a credential in TPM2_MakeCredential and a
//! duplication blob in TPM2_Duplicate.

use crate::tpm::constants::rc;
use crate::tpm::crypto::hash;
use crate::tpm::crypto::hmac::{hmac_parts, kdfa};
use crate::tpm::crypto::sym;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::base::Tpm2bDigest;
use crate::tpm::structures::schemes::SymDef;

/// The label of the key that encrypts a protected sensitive area.
pub const LABEL_STORAGE: &str = "STORAGE";
/// The label of the key that covers a protected sensitive area with an HMAC.
pub const LABEL_INTEGRITY: &str = "INTEGRITY";
/// The label used when a seed is carried to another TPM for a credential.
pub const LABEL_IDENTITY: &str = "IDENTITY";
/// The label used when a seed is carried for a duplication.
pub const LABEL_DUPLICATE: &str = "DUPLICATE";
/// The label used when a seed protects a secret in TPM2_StartAuthSession.
pub const LABEL_SECRET: &str = "SECRET";

/// The symmetric key that protects a child of `parent_name_alg`.
///
/// `seed` is the parent's seedValue, `name` the child's Name.
pub fn storage_key(
    parent_name_alg: u16,
    seed: &[u8],
    name: &[u8],
    key_bits: u16,
) -> TpmResult<Vec<u8>> {
    kdfa(
        parent_name_alg,
        seed,
        LABEL_STORAGE,
        name,
        &[],
        key_bits as u32,
    )
}

/// The HMAC key that covers a protected sensitive area.
pub fn integrity_key(parent_name_alg: u16, seed: &[u8]) -> TpmResult<Vec<u8>> {
    let bits = (hash::digest_size(parent_name_alg)? * 8) as u32;
    kdfa(parent_name_alg, seed, LABEL_INTEGRITY, &[], &[], bits)
}

/// The integrity value over an encrypted blob and a Name.
pub fn outer_integrity(
    parent_name_alg: u16,
    seed: &[u8],
    encrypted: &[u8],
    name: &[u8],
) -> TpmResult<Vec<u8>> {
    let key = integrity_key(parent_name_alg, seed)?;
    hmac_parts(parent_name_alg, &key, &[encrypted, name])
}

/// Encrypt `plaintext` with the storage key for `name`.
///
/// Part 1 clause 24.4 fixes the IV to zero because the key is unique to the
/// object being protected.
pub fn symmetric_wrap(
    parent_name_alg: u16,
    seed: &[u8],
    symmetric: &SymDef,
    name: &[u8],
    plaintext: &[u8],
) -> TpmResult<Vec<u8>> {
    if symmetric.is_null() {
        return Err(TpmRc(rc::SYMMETRIC));
    }
    let key = storage_key(parent_name_alg, seed, name, symmetric.key_bits)?;
    let block = sym::block_size(symmetric.algorithm)?;
    let iv = vec![0u8; block];
    sym::cfb_encrypt(&key, &iv, plaintext)
}

/// Undo [`symmetric_wrap`].
pub fn symmetric_unwrap(
    parent_name_alg: u16,
    seed: &[u8],
    symmetric: &SymDef,
    name: &[u8],
    ciphertext: &[u8],
) -> TpmResult<Vec<u8>> {
    if symmetric.is_null() {
        return Err(TpmRc(rc::SYMMETRIC));
    }
    let key = storage_key(parent_name_alg, seed, name, symmetric.key_bits)?;
    let block = sym::block_size(symmetric.algorithm)?;
    let iv = vec![0u8; block];
    sym::cfb_decrypt(&key, &iv, ciphertext)
}

/// Wrap a marshalled sensitive area into a TPM2B_PRIVATE body.
///
/// The result is `TPM2B_DIGEST(outerHMAC) || encryptedSensitive`, which is what
/// a TPM2B_PRIVATE holds.
pub fn wrap_private(
    parent_name_alg: u16,
    parent_seed: &[u8],
    symmetric: &SymDef,
    name: &[u8],
    sensitive: &[u8],
) -> TpmResult<Vec<u8>> {
    // The sensitive area is carried inside a TPM2B so its length is known
    // after decryption.
    let mut inner = Writer::new();
    inner.sized16(sensitive);
    let plaintext = inner.finish()?;

    let encrypted = symmetric_wrap(parent_name_alg, parent_seed, symmetric, name, &plaintext)?;
    let integrity = outer_integrity(parent_name_alg, parent_seed, &encrypted, name)?;

    let mut out = Writer::new();
    Tpm2bDigest::new(integrity)?.marshal(&mut out);
    out.bytes(&encrypted);
    out.finish()
}

/// Undo [`wrap_private`], returning the marshalled sensitive area.
///
/// A wrong parent, a changed Name or any tampering shows up as
/// TPM_RC_INTEGRITY.
pub fn unwrap_private(
    parent_name_alg: u16,
    parent_seed: &[u8],
    symmetric: &SymDef,
    name: &[u8],
    private: &[u8],
) -> TpmResult<Vec<u8>> {
    let mut r = Reader::new(private);
    let integrity = Tpm2bDigest::unmarshal(&mut r).map_err(|_| TpmRc(rc::INTEGRITY))?;
    let encrypted = r.take_rest();
    if encrypted.is_empty() {
        return Err(TpmRc(rc::INTEGRITY));
    }

    let expected = outer_integrity(parent_name_alg, parent_seed, encrypted, name)?;
    if !constant_time_eq(integrity.as_slice(), &expected) {
        return Err(TpmRc(rc::INTEGRITY));
    }

    let plaintext = symmetric_unwrap(parent_name_alg, parent_seed, symmetric, name, encrypted)?;
    let mut r = Reader::new(&plaintext);
    let size = r.u16().map_err(|_| TpmRc(rc::SENSITIVE))? as usize;
    let body = r.take(size).map_err(|_| TpmRc(rc::SENSITIVE))?;
    Ok(body.to_vec())
}

/// Compare two octet strings without an early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Protect a credential for TPM2_MakeCredential, Part 1 clause 24.5.
///
/// The seed is carried to the target TPM separately. This produces the
/// TPMS_ID_OBJECT body: `TPM2B_DIGEST(outerHMAC) || encIdentity`.
pub fn wrap_credential(
    name_alg: u16,
    seed: &[u8],
    symmetric: &SymDef,
    name: &[u8],
    credential: &[u8],
) -> TpmResult<Vec<u8>> {
    let mut inner = Writer::new();
    inner.sized16(credential);
    let plaintext = inner.finish()?;

    let encrypted = symmetric_wrap(name_alg, seed, symmetric, name, &plaintext)?;
    let integrity = outer_integrity(name_alg, seed, &encrypted, name)?;

    let mut out = Writer::new();
    Tpm2bDigest::new(integrity)?.marshal(&mut out);
    out.bytes(&encrypted);
    out.finish()
}

/// Undo [`wrap_credential`] for TPM2_ActivateCredential.
pub fn unwrap_credential(
    name_alg: u16,
    seed: &[u8],
    symmetric: &SymDef,
    name: &[u8],
    id_object: &[u8],
) -> TpmResult<Vec<u8>> {
    unwrap_private(name_alg, seed, symmetric, name, id_object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;

    fn symmetric() -> SymDef {
        SymDef::new(alg::AES, 128, alg::CFB)
    }

    #[test]
    fn derived_keys_depend_on_every_input() {
        let seed = [1u8; 32];
        let name = [2u8; 34];
        let base = storage_key(alg::SHA256, &seed, &name, 128).unwrap();
        assert_eq!(base.len(), 16);
        assert_ne!(base, storage_key(alg::SHA256, &[3u8; 32], &name, 128).unwrap());
        assert_ne!(base, storage_key(alg::SHA256, &seed, &[4u8; 34], 128).unwrap());
        assert_ne!(base, storage_key(alg::SHA384, &seed, &name, 128).unwrap());
        assert_eq!(storage_key(alg::SHA256, &seed, &name, 256).unwrap().len(), 32);

        let ik = integrity_key(alg::SHA256, &seed).unwrap();
        assert_eq!(ik.len(), 32);
        assert_eq!(integrity_key(alg::SHA384, &seed).unwrap().len(), 48);
        assert_ne!(ik, base);
    }

    #[test]
    fn the_storage_key_matches_kdfa_directly() {
        let seed = [7u8; 32];
        let name = [8u8; 34];
        assert_eq!(
            storage_key(alg::SHA256, &seed, &name, 128).unwrap(),
            kdfa(alg::SHA256, &seed, "STORAGE", &name, &[], 128).unwrap()
        );
        assert_eq!(
            integrity_key(alg::SHA256, &seed).unwrap(),
            kdfa(alg::SHA256, &seed, "INTEGRITY", &[], &[], 256).unwrap()
        );
    }

    #[test]
    fn symmetric_wrap_round_trips() {
        let seed = [9u8; 32];
        let name = [5u8; 34];
        for len in [0usize, 1, 16, 17, 200] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = symmetric_wrap(alg::SHA256, &seed, &symmetric(), &name, &data).unwrap();
            assert_eq!(ct.len(), len);
            let pt = symmetric_unwrap(alg::SHA256, &seed, &symmetric(), &name, &ct).unwrap();
            assert_eq!(pt, data);
        }
    }

    #[test]
    fn a_null_symmetric_definition_is_refused() {
        assert_eq!(
            symmetric_wrap(alg::SHA256, &[0u8; 32], &SymDef::null(), &[], b"x").unwrap_err(),
            TpmRc(rc::SYMMETRIC)
        );
    }

    #[test]
    fn private_area_round_trips() {
        let seed = [4u8; 32];
        let name = [6u8; 34];
        let sensitive = vec![0xabu8; 100];
        let private =
            wrap_private(alg::SHA256, &seed, &symmetric(), &name, &sensitive).unwrap();
        // The blob is the integrity digest followed by the ciphertext.
        assert_eq!(&private[0..2], &32u16.to_be_bytes());
        assert_eq!(private.len(), 2 + 32 + 2 + sensitive.len());
        let back =
            unwrap_private(alg::SHA256, &seed, &symmetric(), &name, &private).unwrap();
        assert_eq!(back, sensitive);
    }

    #[test]
    fn a_wrong_parent_seed_fails_the_integrity_check() {
        let name = [6u8; 34];
        let sensitive = vec![1u8; 64];
        let private =
            wrap_private(alg::SHA256, &[4u8; 32], &symmetric(), &name, &sensitive).unwrap();
        assert_eq!(
            unwrap_private(alg::SHA256, &[5u8; 32], &symmetric(), &name, &private).unwrap_err(),
            TpmRc(rc::INTEGRITY)
        );
    }

    #[test]
    fn a_changed_name_fails_the_integrity_check() {
        let seed = [4u8; 32];
        let sensitive = vec![1u8; 64];
        let private =
            wrap_private(alg::SHA256, &seed, &symmetric(), &[6u8; 34], &sensitive).unwrap();
        assert_eq!(
            unwrap_private(alg::SHA256, &seed, &symmetric(), &[7u8; 34], &private).unwrap_err(),
            TpmRc(rc::INTEGRITY)
        );
    }

    #[test]
    fn tampering_with_the_blob_fails_the_integrity_check() {
        let seed = [4u8; 32];
        let name = [6u8; 34];
        let sensitive = vec![1u8; 64];
        let private = wrap_private(alg::SHA256, &seed, &symmetric(), &name, &sensitive).unwrap();

        for at in [0usize, 5, 40, 60] {
            let mut bad = private.clone();
            bad[at] ^= 0x01;
            assert_eq!(
                unwrap_private(alg::SHA256, &seed, &symmetric(), &name, &bad).unwrap_err(),
                TpmRc(rc::INTEGRITY),
                "flipping octet {at}"
            );
        }
    }

    #[test]
    fn a_truncated_private_area_is_rejected() {
        assert_eq!(
            unwrap_private(alg::SHA256, &[0u8; 32], &symmetric(), &[], &[]).unwrap_err(),
            TpmRc(rc::INTEGRITY)
        );
        // A well formed digest with no ciphertext after it.
        let mut raw = 32u16.to_be_bytes().to_vec();
        raw.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            unwrap_private(alg::SHA256, &[0u8; 32], &symmetric(), &[], &raw).unwrap_err(),
            TpmRc(rc::INTEGRITY)
        );
    }

    #[test]
    fn credential_wrapping_round_trips() {
        let seed = [3u8; 32];
        let name = [8u8; 34];
        let credential = vec![0x77u8; 32];
        let blob = wrap_credential(alg::SHA256, &seed, &symmetric(), &name, &credential).unwrap();
        assert_eq!(
            unwrap_credential(alg::SHA256, &seed, &symmetric(), &name, &blob).unwrap(),
            credential
        );
        // A credential made for another Name does not activate.
        assert!(unwrap_credential(alg::SHA256, &seed, &symmetric(), &[9u8; 34], &blob).is_err());
    }

    #[test]
    fn constant_time_comparison_behaves_like_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn wrapping_works_for_every_key_size_and_name_algorithm() {
        let seed = [2u8; 48];
        let name = [3u8; 34];
        let sensitive = vec![0x5au8; 48];
        for (name_alg, bits) in [
            (alg::SHA1, 128u16),
            (alg::SHA256, 128),
            (alg::SHA256, 256),
            (alg::SHA384, 192),
            (alg::SHA512, 256),
        ] {
            let sym = SymDef::new(alg::AES, bits, alg::CFB);
            let private = wrap_private(name_alg, &seed, &sym, &name, &sensitive).unwrap();
            assert_eq!(
                unwrap_private(name_alg, &seed, &sym, &name, &private).unwrap(),
                sensitive
            );
        }
    }
}
