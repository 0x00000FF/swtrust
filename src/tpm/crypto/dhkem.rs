//! The Diffie-Hellman based KEM of RFC 9180, Part 1 clause 44.4.
//!
//! Part 1 clause 44.4.1 says an ECC key whose kdf is not TPM_ALG_NULL "can be
//! used as a Key Encapsulation Mechanism (KEM) key, and the KEM is equivalent
//! to the Diffie-Hellman based KEM (DHKEM) from RFC 9180: Hybrid Public Key
//! Encryption, using the selected KDF". What follows is that construction: the
//! ciphertext is the serialized ephemeral public key and the shared secret
//! comes from RFC 9180's ExtractAndExpand over the Diffie-Hellman result.

use crate::tpm::constants::{alg, curve, rc};
use crate::tpm::crypto::{hash, hmac};
use crate::tpm::error::{TpmRc, TpmResult};

/// RFC 9180 clause 5.1 prefixes every label with the version of the suite.
const VERSION: &[u8] = b"HPKE-v1";

/// What RFC 9180 clause 7.1 registers for the curve, as (kem_id, Nsecret).
///
/// Nsecret is the length of the shared secret the KEM produces, which clause
/// 4.1 fixes for the KEM rather than taking from the KDF.
fn suite(curve_id: u16) -> TpmResult<(u16, usize)> {
    match curve_id {
        curve::NIST_P256 => Ok((0x0010, 32)),
        curve::NIST_P384 => Ok((0x0011, 48)),
        curve::NIST_P521 => Ok((0x0012, 64)),
        _ => Err(TpmRc(rc::CURVE)),
    }
}

/// The suite_id of RFC 9180 clause 5.1: "KEM" followed by the two octet
/// identifier of the KEM.
fn suite_id(kem_id: u16) -> Vec<u8> {
    let mut out = b"KEM".to_vec();
    out.extend_from_slice(&kem_id.to_be_bytes());
    out
}

/// HKDF-Extract of RFC 5869 clause 2.2.
fn extract(hash_alg: u16, salt: &[u8], ikm: &[u8]) -> TpmResult<Vec<u8>> {
    let salt = if salt.is_empty() {
        vec![0u8; hash::digest_size(hash_alg)?]
    } else {
        salt.to_vec()
    };
    hmac::hmac(hash_alg, &salt, ikm)
}

/// HKDF-Expand of RFC 5869 clause 2.3.
fn expand(hash_alg: u16, prk: &[u8], info: &[u8], out_len: usize) -> TpmResult<Vec<u8>> {
    let size = hash::digest_size(hash_alg)?;
    // Clause 2.3 bounds the output at 255 blocks, which is what the one octet
    // counter can reach.
    if out_len > 255 * size {
        return Err(TpmRc(rc::VALUE));
    }
    let mut out = Vec::with_capacity(out_len);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let block = hmac::hmac_parts(hash_alg, prk, &[&previous, info, &[counter]])?;
        out.extend_from_slice(&block);
        previous = block;
        counter += 1;
    }
    out.truncate(out_len);
    Ok(out)
}

/// LabeledExtract of RFC 9180 clause 5.1.
fn labeled_extract(
    hash_alg: u16,
    suite: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> TpmResult<Vec<u8>> {
    let mut labeled = VERSION.to_vec();
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    extract(hash_alg, salt, &labeled)
}

/// LabeledExpand of RFC 9180 clause 5.1.
fn labeled_expand(
    hash_alg: u16,
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out_len: usize,
) -> TpmResult<Vec<u8>> {
    let mut labeled = (out_len as u16).to_be_bytes().to_vec();
    labeled.extend_from_slice(VERSION);
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    expand(hash_alg, prk, &labeled, out_len)
}

/// Serialize a public point, Part 1 clause 44.4.2 item 3.
///
/// "For NIST P-curves, the serialization of a point is (0x04 || X || Y), where
/// X and Y are the big-endian coordinates of the point", which the note beside
/// it calls the uncompressed serialization of SEC 1. Each coordinate is padded
/// to the length of the curve, which clause 44.5.3 requires of every ECC value.
pub fn serialize_point(curve_id: u16, x: &[u8], y: &[u8]) -> TpmResult<Vec<u8>> {
    let size = crate::tpm::crypto::ecc::Curve::new(curve_id)?.coordinate_size();
    if x.len() > size || y.len() > size {
        return Err(TpmRc(rc::ECC_POINT));
    }
    let mut out = Vec::with_capacity(1 + 2 * size);
    out.push(0x04);
    out.resize(1 + size - x.len(), 0);
    out.extend_from_slice(x);
    out.resize(1 + size + size - y.len(), 0);
    out.extend_from_slice(y);
    Ok(out)
}

/// Read a serialized point back, refusing anything but the uncompressed form.
pub fn deserialize_point(curve_id: u16, serialized: &[u8]) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    let size = crate::tpm::crypto::ecc::Curve::new(curve_id)?.coordinate_size();
    if serialized.len() != 1 + 2 * size || serialized[0] != 0x04 {
        return Err(TpmRc(rc::ECC_POINT));
    }
    Ok((
        serialized[1..1 + size].to_vec(),
        serialized[1 + size..].to_vec(),
    ))
}

/// ExtractAndExpand of RFC 9180 clause 4.1.
///
/// Part 1 clause 44.4.2 item 5 and clause 44.4.3 item 4 both name this function
/// and give it the same two inputs, so encapsulation and decapsulation reach
/// the same secret from the two sides of the same Diffie-Hellman.
pub fn extract_and_expand(
    hash_alg: u16,
    curve_id: u16,
    dh: &[u8],
    kem_context: &[u8],
) -> TpmResult<Vec<u8>> {
    let (kem_id, n_secret) = suite(curve_id)?;
    let suite = suite_id(kem_id);
    let prk = labeled_extract(hash_alg, &suite, &[], b"eae_prk", dh)?;
    labeled_expand(
        hash_alg,
        &suite,
        &prk,
        b"shared_secret",
        kem_context,
        n_secret,
    )
}

/// The hash a KEM key derives with, or why the key cannot be used.
///
/// Part 2 Table 229 says of an ECC key's kdf that "currently, TPM_ALG_HKDF is
/// the only supported KDF for DHKEM", and RFC 9180 builds ExtractAndExpand out
/// of HKDF, so another key derivation function has no meaning here.
pub fn kem_hash(kdf: &crate::tpm::structures::schemes::Scheme) -> TpmResult<u16> {
    if kdf.scheme != alg::HKDF {
        return Err(TpmRc(rc::KDF));
    }
    kdf.hash_alg().ok_or(TpmRc(rc::KDF))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc_5869_test_case_one() {
        // RFC 5869 appendix A.1, the SHA-256 case.
        let ikm = vec![0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let prk = extract(alg::SHA256, &salt, &ikm).unwrap();
        assert_eq!(
            prk,
            [
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
                0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
                0xd7, 0xc2, 0xb3, 0xe5,
            ]
        );
        let okm = expand(alg::SHA256, &prk, &info, 42).unwrap();
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_three() {
        // Appendix A.3 uses an empty salt and empty info, which is the shape
        // LabeledExtract takes.
        let ikm = vec![0x0bu8; 22];
        let prk = extract(alg::SHA256, &[], &ikm).unwrap();
        assert_eq!(
            prk,
            [
                0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64,
                0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c,
                0x29, 0x3c, 0xcb, 0x04,
            ]
        );
        let okm = expand(alg::SHA256, &prk, &[], 42).unwrap();
        assert_eq!(
            okm,
            [
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
                0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
            ]
        );
    }

    #[test]
    fn a_point_serializes_uncompressed_and_padded() {
        // Clause 44.4.2 item 3.1: (0x04 || X || Y) with big-endian coordinates,
        // each padded to the size of the curve.
        let s = serialize_point(curve::NIST_P256, &[0x01], &[0x02]).unwrap();
        assert_eq!(s.len(), 65);
        assert_eq!(s[0], 0x04);
        assert_eq!(s[32], 0x01);
        assert_eq!(s[64], 0x02);
        assert!(s[1..32].iter().all(|b| *b == 0));
        let (x, y) = deserialize_point(curve::NIST_P256, &s).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        assert_eq!(x[31], 0x01);
        assert_eq!(y[31], 0x02);
    }

    #[test]
    fn a_compressed_or_short_point_is_refused() {
        let mut s = serialize_point(curve::NIST_P256, &[0x01], &[0x02]).unwrap();
        s[0] = 0x02;
        assert_eq!(
            deserialize_point(curve::NIST_P256, &s).unwrap_err(),
            TpmRc(rc::ECC_POINT)
        );
        assert_eq!(
            deserialize_point(curve::NIST_P256, &s[..64]).unwrap_err(),
            TpmRc(rc::ECC_POINT)
        );
    }

    #[test]
    fn extract_and_expand_follows_rfc_9180_clause_5_1() {
        // Spell the construction out here from the text rather than call the
        // helpers the function calls, so the two agreeing means the labels,
        // the suite identifier and their order are right and not merely
        // consistent with themselves.
        //
        //   suite_id      = "KEM" || I2OSP(kem_id, 2)
        //   LabeledExtract(salt, label, ikm)
        //                 = Extract(salt, "HPKE-v1" || suite_id || label || ikm)
        //   LabeledExpand(prk, label, info, L)
        //                 = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id
        //                          || label || info, L)
        //   eae_prk       = LabeledExtract("", "eae_prk", dh)
        //   shared_secret = LabeledExpand(eae_prk, "shared_secret",
        //                                 kem_context, Nsecret)
        let dh = vec![0x11u8; 32];
        let kem_context = vec![0x22u8; 130];

        // DHKEM(P-256, HKDF-SHA256) is kem_id 0x0010 with Nsecret of 32.
        let mut suite = b"KEM".to_vec();
        suite.extend_from_slice(&[0x00, 0x10]);

        let mut ikm = b"HPKE-v1".to_vec();
        ikm.extend_from_slice(&suite);
        ikm.extend_from_slice(b"eae_prk");
        ikm.extend_from_slice(&dh);
        let prk = hmac::hmac(alg::SHA256, &[0u8; 32], &ikm).unwrap();

        let mut info = vec![0x00, 0x20];
        info.extend_from_slice(b"HPKE-v1");
        info.extend_from_slice(&suite);
        info.extend_from_slice(b"shared_secret");
        info.extend_from_slice(&kem_context);
        let mut block = info.clone();
        block.push(1);
        let expected = hmac::hmac(alg::SHA256, &prk, &block).unwrap();

        assert_eq!(
            extract_and_expand(alg::SHA256, curve::NIST_P256, &dh, &kem_context).unwrap(),
            expected
        );
    }

    #[test]
    fn each_curve_carries_its_own_registered_suite() {
        // RFC 9180 clause 7.1 registers one identifier and one secret length
        // per curve, so two curves cannot reach the same secret from the same
        // inputs.
        let dh = vec![0x11u8; 32];
        let context = vec![0x22u8; 10];
        let p256 = extract_and_expand(alg::SHA256, curve::NIST_P256, &dh, &context).unwrap();
        let p384 = extract_and_expand(alg::SHA256, curve::NIST_P384, &dh, &context).unwrap();
        assert_eq!(p256.len(), 32);
        assert_eq!(p384.len(), 48);
        assert_ne!(p256[..], p384[..32]);
    }

    #[test]
    fn only_hkdf_names_a_kem_key() {
        use crate::tpm::structures::schemes::Scheme;
        assert_eq!(
            kem_hash(&Scheme::hash(alg::HKDF, alg::SHA256)).unwrap(),
            alg::SHA256
        );
        assert_eq!(
            kem_hash(&Scheme::hash(alg::KDF1_SP800_56A, alg::SHA256)).unwrap_err(),
            TpmRc(rc::KDF)
        );
        assert_eq!(kem_hash(&Scheme::null()).unwrap_err(), TpmRc(rc::KDF));
    }
}
