//! HMAC and the key derivation functions built on it.
//!
//! HMAC is implemented over the hash layer rather than taken from a library so
//! that every hash the TPM implements, including the SHA-3 family, can key an
//! HMAC. Part 1 clause 11.4.10 defines KDFa and KDFe in terms of that HMAC.

use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};

use super::hash::{block_size, digest_size, Hasher};

/// Largest KDF output the TPM will produce, in octets.
///
/// Part 2 Table 7 caps a derivation at TPM_MAX_DERIVATION_BITS. Anything larger
/// is a malformed request rather than a legitimate key size.
pub const MAX_KDF_BYTES: usize = crate::tpm::constants::TPM_MAX_DERIVATION_BITS as usize / 8;

/// The octet count for a bit count, rejecting anything out of range.
fn output_len(bits: u32) -> TpmResult<usize> {
    let bytes = bits
        .checked_add(7)
        .ok_or(TpmRc(rc::VALUE))?
        / 8;
    let bytes = bytes as usize;
    if bytes > MAX_KDF_BYTES {
        return Err(TpmRc(rc::VALUE));
    }
    Ok(bytes)
}

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Compute HMAC(key, data) with `hash_alg`, following RFC 2104.
pub fn hmac(hash_alg: u16, key: &[u8], data: &[u8]) -> TpmResult<Vec<u8>> {
    hmac_parts(hash_alg, key, &[data])
}

/// Compute an HMAC over the concatenation of `parts`.
pub fn hmac_parts(hash_alg: u16, key: &[u8], parts: &[&[u8]]) -> TpmResult<Vec<u8>> {
    let mut mac = Hmac::new(hash_alg, key)?;
    for p in parts {
        mac.update(p);
    }
    Ok(mac.finish())
}

/// An incremental HMAC, used by HMAC sequences.
pub struct Hmac {
    hash_alg: u16,
    inner: Hasher,
    outer_key: Vec<u8>,
}

impl Hmac {
    /// Start an HMAC with `key`.
    ///
    /// A key longer than the hash block is replaced by its digest, and a
    /// shorter key is padded with zeros, as RFC 2104 requires.
    pub fn new(hash_alg: u16, key: &[u8]) -> TpmResult<Hmac> {
        let block = block_size(hash_alg)?;
        let mut padded = vec![0u8; block];
        if key.len() > block {
            let d = super::hash::digest(hash_alg, key)?;
            padded[..d.len()].copy_from_slice(&d);
        } else {
            padded[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = padded.clone();
        for b in inner_key.iter_mut() {
            *b ^= IPAD;
        }
        let mut outer_key = padded;
        for b in outer_key.iter_mut() {
            *b ^= OPAD;
        }

        let mut inner = Hasher::new(hash_alg)?;
        inner.update(&inner_key);
        Ok(Hmac {
            hash_alg,
            inner,
            outer_key,
        })
    }

    /// The hash algorithm keying this HMAC.
    pub fn hash_alg(&self) -> u16 {
        self.hash_alg
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> Vec<u8> {
        let inner = self.inner.finish();
        let mut outer = Hasher::new(self.hash_alg).expect("algorithm was checked at construction");
        outer.update(&self.outer_key);
        outer.update(&inner);
        outer.finish()
    }
}

/// KDFa, the SP800-108 counter mode KDF of Part 1 clause 11.4.10.2.
///
/// Each iteration computes
/// `HMAC(key, counter || label || 0x00 || contextU || contextV || bits)`
/// with the counter and bit count as big endian UINT32 values. The result is
/// `bits` bits, and when `bits` is not a multiple of eight the unused bits of
/// the first octet are masked off.
pub fn kdfa(
    hash_alg: u16,
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> TpmResult<Vec<u8>> {
    let out_len = output_len(bits)?;
    let digest_len = digest_size(hash_alg)?;
    let mut out = Vec::with_capacity(out_len + digest_len);
    let mut counter: u32 = 0;
    let bits_be = bits.to_be_bytes();
    while out.len() < out_len {
        counter += 1;
        let mut mac = Hmac::new(hash_alg, key)?;
        mac.update(&counter.to_be_bytes());
        mac.update(label.as_bytes());
        // The label is followed by a zero octet, which is part of the label
        // string in the specification even when the label is empty.
        mac.update(&[0u8]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&bits_be);
        out.extend_from_slice(&mac.finish());
    }
    out.truncate(out_len);
    // Mask the unused bits of the most significant octet.
    if bits % 8 != 0 {
        if let Some(first) = out.first_mut() {
            *first &= (1u16 << (bits % 8)) as u8 - 1;
        }
    }
    Ok(out)
}

/// KDFe, the SP800-56A concatenation KDF of Part 1 clause 11.4.10.3.
///
/// Each iteration hashes `counter || z || label || 0x00 || partyU || partyV`.
pub fn kdfe(
    hash_alg: u16,
    z: &[u8],
    label: &str,
    party_u: &[u8],
    party_v: &[u8],
    bits: u32,
) -> TpmResult<Vec<u8>> {
    let out_len = output_len(bits)?;
    let digest_len = digest_size(hash_alg)?;
    let mut out = Vec::with_capacity(out_len + digest_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        counter += 1;
        let mut h = Hasher::new(hash_alg)?;
        h.update(&counter.to_be_bytes());
        h.update(z);
        h.update(label.as_bytes());
        h.update(&[0u8]);
        h.update(party_u);
        h.update(party_v);
        out.extend_from_slice(&h.finish());
    }
    out.truncate(out_len);
    if bits % 8 != 0 {
        if let Some(first) = out.first_mut() {
            *first &= (1u16 << (bits % 8)) as u8 - 1;
        }
    }
    Ok(out)
}

/// MGF1 from RFC 8017 appendix B.2.1, used by OAEP and PSS.
pub fn mgf1(hash_alg: u16, seed: &[u8], out_len: usize) -> TpmResult<Vec<u8>> {
    if out_len > MAX_KDF_BYTES {
        return Err(TpmRc(rc::VALUE));
    }
    let digest_len = digest_size(hash_alg)?;
    let mut out = Vec::with_capacity(out_len + digest_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut h = Hasher::new(hash_alg)?;
        h.update(seed);
        h.update(&counter.to_be_bytes());
        out.extend_from_slice(&h.finish());
        counter += 1;
    }
    out.truncate(out_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;

    fn hex(s: &str) -> Vec<u8> {
        crate::util::hex::decode(s).unwrap()
    }

    #[test]
    fn rfc_4231_test_case_1() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        assert_eq!(
            hmac(alg::SHA256, &key, data).unwrap(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            hmac(alg::SHA384, &key, data).unwrap(),
            hex(concat!(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6",
                "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
            ))
        );
        assert_eq!(
            hmac(alg::SHA512, &key, data).unwrap(),
            hex(concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ))
        );
    }

    #[test]
    fn rfc_4231_test_case_2() {
        assert_eq!(
            hmac(alg::SHA256, b"Jefe", b"what do ya want for nothing?").unwrap(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    /// RFC 4231 test cases 1 and 2, which cover the SHA-2 family.
    ///
    /// The SHA-1 vectors of RFC 2202 used to be here. They are gone with the
    /// algorithm: the platform profile lists SHA-1 as Not Allowed, so asking
    /// this TPM for an HMAC over it is asking for a hash it does not have.
    #[test]
    fn rfc_4231_vectors() {
        assert_eq!(
            hmac(alg::SHA384, &vec![0x0b; 20], b"Hi There").unwrap(),
            hex(concat!(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6",
                "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
            ))
        );
        assert_eq!(
            hmac(alg::SHA512, &vec![0x0b; 20], b"Hi There").unwrap(),
            hex(concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ))
        );
        assert_eq!(
            hmac(alg::SHA384, b"Jefe", b"what do ya want for nothing?").unwrap(),
            hex(concat!(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47",
                "e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
            ))
        );
        assert_eq!(
            hmac(alg::SHA512, b"Jefe", b"what do ya want for nothing?").unwrap(),
            hex(concat!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ))
        );
        assert!(hmac(alg::SHA1, &vec![0x0b; 20], b"Hi There").is_err());
    }

    #[test]
    fn a_key_longer_than_the_block_is_hashed_first() {
        // RFC 4231 test case 6 uses a 131 octet key.
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hmac(alg::SHA256, &key, data).unwrap(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn sha3_hmac_matches_nist_vectors() {
        // NIST HMAC-SHA3-256 sample with a 32 octet key over "abc".
        let key: Vec<u8> = (0u8..32).collect();
        let mac = hmac(alg::SHA3_256, &key, b"abc").unwrap();
        assert_eq!(mac.len(), 32);
        // Cross check against the definition using the SHA-3 rate of 136.
        let block = 136;
        let mut ipad = vec![0u8; block];
        ipad[..key.len()].copy_from_slice(&key);
        let mut opad = ipad.clone();
        for b in ipad.iter_mut() {
            *b ^= 0x36;
        }
        for b in opad.iter_mut() {
            *b ^= 0x5c;
        }
        let inner =
            super::super::hash::digest_parts(alg::SHA3_256, &[&ipad, b"abc"]).unwrap();
        let expected =
            super::super::hash::digest_parts(alg::SHA3_256, &[&opad, &inner]).unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn incremental_hmac_matches_one_shot() {
        let key = b"a key";
        let data: Vec<u8> = (0u8..=255).cycle().take(500).collect();
        for a in crate::tpm::config::IMPLEMENTED_HASHES.iter().copied() {
            let mut m = Hmac::new(a, key).unwrap();
            for c in data.chunks(13) {
                m.update(c);
            }
            assert_eq!(m.finish(), hmac(a, key, &data).unwrap());
        }
    }

    #[test]
    fn kdfa_produces_the_requested_length() {
        for bits in [8u32, 128, 256, 384, 512, 1024] {
            let out = kdfa(alg::SHA256, b"key", "LABEL", b"u", b"v", bits).unwrap();
            assert_eq!(out.len() as u32, bits / 8);
        }
    }

    #[test]
    fn kdfa_first_block_is_the_expected_hmac() {
        // With a request no longer than one digest, KDFa is a single HMAC over
        // counter, label, a zero octet, the contexts and the bit count.
        let key = b"kdfa key";
        let out = kdfa(alg::SHA256, key, "ATH", b"nonceU", b"nonceV", 256).unwrap();
        let expected = hmac_parts(
            alg::SHA256,
            key,
            &[
                &1u32.to_be_bytes(),
                b"ATH",
                &[0u8],
                b"nonceU",
                b"nonceV",
                &256u32.to_be_bytes(),
            ],
        )
        .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn kdfa_spans_several_iterations() {
        let key = b"kdfa key";
        let out = kdfa(alg::SHA256, key, "L", b"", b"", 512).unwrap();
        assert_eq!(out.len(), 64);
        let first = hmac_parts(
            alg::SHA256,
            key,
            &[&1u32.to_be_bytes(), b"L", &[0u8], &512u32.to_be_bytes()],
        )
        .unwrap();
        let second = hmac_parts(
            alg::SHA256,
            key,
            &[&2u32.to_be_bytes(), b"L", &[0u8], &512u32.to_be_bytes()],
        )
        .unwrap();
        assert_eq!(&out[..32], &first[..]);
        assert_eq!(&out[32..], &second[..]);
    }

    #[test]
    fn kdfa_masks_partial_octets() {
        // Seven bits leaves the top bit of the first octet clear.
        let out = kdfa(alg::SHA256, b"k", "L", b"", b"", 7).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0] & 0x80, 0);
        let out = kdfa(alg::SHA256, b"k", "L", b"", b"", 521).unwrap();
        assert_eq!(out.len(), 66);
        assert_eq!(out[0] & 0xfe, 0);
    }

    #[test]
    fn kdfe_first_block_is_the_expected_hash() {
        let z = b"shared secret";
        let out = kdfe(alg::SHA256, z, "SECRET", b"partyU", b"partyV", 256).unwrap();
        let expected = super::super::hash::digest_parts(
            alg::SHA256,
            &[&1u32.to_be_bytes(), z, b"SECRET", &[0u8], b"partyU", b"partyV"],
        )
        .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn kdfe_produces_the_requested_length() {
        for bits in [128u32, 256, 512, 1024] {
            assert_eq!(
                kdfe(alg::SHA384, b"z", "L", b"", b"", bits).unwrap().len() as u32,
                bits / 8
            );
        }
    }

    #[test]
    fn mgf1_matches_the_definition() {
        let seed = b"seed";
        let out = mgf1(alg::SHA256, seed, 80).unwrap();
        assert_eq!(out.len(), 80);
        let b0 = super::super::hash::digest_parts(alg::SHA256, &[seed, &0u32.to_be_bytes()])
            .unwrap();
        let b1 = super::super::hash::digest_parts(alg::SHA256, &[seed, &1u32.to_be_bytes()])
            .unwrap();
        assert_eq!(&out[..32], &b0[..]);
        assert_eq!(&out[32..64], &b1[..]);
    }

    #[test]
    fn mgf1_known_answer() {
        // RFC 8017 does not publish MGF1 vectors directly, so this checks the
        // shortest possible output against the first digest block.
        let out = mgf1(alg::SHA256, b"", 1).unwrap();
        let full =
            super::super::hash::digest_parts(alg::SHA256, &[b"", &0u32.to_be_bytes()]).unwrap();
        assert_eq!(out, vec![full[0]]);
    }
}
