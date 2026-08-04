//! Hash algorithms.
//!
//! The TPM selects a hash by TPM_ALG_ID, so this module maps those identifiers
//! onto the aws-lc-rs digest algorithms and exposes both one shot and
//! incremental hashing.

use aws_lc_rs::digest;

use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};

/// The aws-lc-rs algorithm for a TPM_ALG_ID.
///
/// Whether SHA-1 is here depends on the profile, and this function is what
/// makes the choice real: every use of a hash in this TPM goes through it, so
/// a hash refused here is refused everywhere. See `crate::tpm::profile`.
///
/// SHA-1 is never among the PCR banks allocated by default whichever profile
/// is in force, because clause 4.7 item 3 fixes those as SHA-256 and SHA-384.
pub fn algorithm(hash_alg: u16) -> TpmResult<&'static digest::Algorithm> {
    if hash_alg == alg::SHA1 && crate::tpm::profile::is_strict() {
        return Err(TpmRc(rc::HASH));
    }
    Ok(match hash_alg {
        alg::SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        alg::SHA256 => &digest::SHA256,
        alg::SHA384 => &digest::SHA384,
        alg::SHA512 => &digest::SHA512,
        alg::SHA3_256 => &digest::SHA3_256,
        alg::SHA3_384 => &digest::SHA3_384,
        alg::SHA3_512 => &digest::SHA3_512,
        _ => return Err(TpmRc(rc::HASH)),
    })
}

/// Digest size in octets, or TPM_RC_HASH when the algorithm is not a hash the
/// TPM implements.
pub fn digest_size(hash_alg: u16) -> TpmResult<usize> {
    Ok(algorithm(hash_alg)?.output_len())
}

/// Input block size in octets, which HMAC and the KDFs need.
///
/// For the SHA-3 family this is the sponge rate.
pub fn block_size(hash_alg: u16) -> TpmResult<usize> {
    if hash_alg == alg::SHA1 && crate::tpm::profile::is_strict() {
        return Err(TpmRc(rc::HASH));
    }
    Ok(match hash_alg {
        alg::SHA1 | alg::SHA256 => 64,
        alg::SHA384 | alg::SHA512 => 128,
        alg::SHA3_256 => 136,
        alg::SHA3_384 => 104,
        alg::SHA3_512 => 72,
        _ => return Err(TpmRc(rc::HASH)),
    })
}

/// True when the TPM implements `hash_alg` as a hash.
pub fn is_supported(hash_alg: u16) -> bool {
    algorithm(hash_alg).is_ok()
}

/// Hash `data` with `hash_alg`.
pub fn digest(hash_alg: u16, data: &[u8]) -> TpmResult<Vec<u8>> {
    let alg = algorithm(hash_alg)?;
    Ok(digest::digest(alg, data).as_ref().to_vec())
}

/// Hash the concatenation of `parts` without building the joined buffer.
pub fn digest_parts(hash_alg: u16, parts: &[&[u8]]) -> TpmResult<Vec<u8>> {
    let mut h = Hasher::new(hash_alg)?;
    for p in parts {
        h.update(p);
    }
    Ok(h.finish())
}

/// An incremental hash.
pub struct Hasher {
    hash_alg: u16,
    ctx: digest::Context,
}

impl Hasher {
    pub fn new(hash_alg: u16) -> TpmResult<Hasher> {
        Ok(Hasher {
            hash_alg,
            ctx: digest::Context::new(algorithm(hash_alg)?),
        })
    }

    /// The algorithm this hasher was created with.
    pub fn hash_alg(&self) -> u16 {
        self.hash_alg
    }

    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    pub fn finish(self) -> Vec<u8> {
        self.ctx.finish().as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert a hex string to octets for the known answer tests.
    fn hex(s: &str) -> Vec<u8> {
        crate::util::hex::decode(s).unwrap()
    }

    #[test]
    fn digest_sizes_match_the_specification() {
        assert_eq!(digest_size(alg::SHA1).unwrap(), 20);
        assert_eq!(digest_size(alg::SHA256).unwrap(), 32);
        assert_eq!(digest_size(alg::SHA384).unwrap(), 48);
        assert_eq!(digest_size(alg::SHA512).unwrap(), 64);
        assert_eq!(digest_size(alg::SHA3_256).unwrap(), 32);
        assert_eq!(digest_size(alg::SHA3_384).unwrap(), 48);
        assert_eq!(digest_size(alg::SHA3_512).unwrap(), 64);
        assert_eq!(digest_size(alg::NULL).unwrap_err(), TpmRc(rc::HASH));
        assert_eq!(digest_size(alg::AES).unwrap_err(), TpmRc(rc::HASH));
    }

    #[test]
    fn block_sizes_match_the_standards() {
        assert_eq!(block_size(alg::SHA1).unwrap(), 64);
        assert_eq!(block_size(alg::SHA256).unwrap(), 64);
        assert_eq!(block_size(alg::SHA384).unwrap(), 128);
        assert_eq!(block_size(alg::SHA512).unwrap(), 128);
        // FIPS 202 rates.
        assert_eq!(block_size(alg::SHA3_256).unwrap(), 136);
        assert_eq!(block_size(alg::SHA3_384).unwrap(), 104);
        assert_eq!(block_size(alg::SHA3_512).unwrap(), 72);
        assert!(block_size(alg::RSA).is_err());
    }

    #[test]
    fn known_answers_for_the_empty_message() {
        assert_eq!(
            digest(alg::SHA1, b"").unwrap(),
            hex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            digest(alg::SHA256, b"").unwrap(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            digest(alg::SHA384, b"").unwrap(),
            hex(concat!(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743",
                "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            ))
        );
        assert_eq!(
            digest(alg::SHA512, b"").unwrap(),
            hex(concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ))
        );
        assert_eq!(
            digest(alg::SHA3_256, b"").unwrap(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
    }

    #[test]
    fn known_answers_for_abc() {
        assert_eq!(
            digest(alg::SHA256, b"abc").unwrap(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            digest(alg::SHA3_256, b"abc").unwrap(),
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
        assert_eq!(
            digest(alg::SHA3_384, b"abc").unwrap(),
            hex(concat!(
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c25",
                "96da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
            ))
        );
        assert_eq!(
            digest(alg::SHA3_512, b"abc").unwrap(),
            hex(concat!(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            ))
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        for a in crate::tpm::config::implemented_hashes().iter().copied() {
            let mut h = Hasher::new(a).unwrap();
            for chunk in data.chunks(37) {
                h.update(chunk);
            }
            assert_eq!(h.finish(), digest(a, &data).unwrap(), "alg {a:#06x}");
        }
    }

    #[test]
    fn digest_parts_matches_the_joined_input() {
        let joined = [b"abc".as_slice(), b"def".as_slice(), b"".as_slice()].concat();
        assert_eq!(
            digest_parts(alg::SHA256, &[b"abc", b"def", b""]).unwrap(),
            digest(alg::SHA256, &joined).unwrap()
        );
    }

    #[test]
    fn unsupported_algorithms_are_reported() {
        assert!(!is_supported(alg::SM3_256));
        assert!(!is_supported(alg::NULL));
        assert!(is_supported(alg::SHA256));
        assert_eq!(digest(alg::SM3_256, b"").unwrap_err(), TpmRc(rc::HASH));
        assert!(Hasher::new(alg::NULL).is_err());
    }
}
