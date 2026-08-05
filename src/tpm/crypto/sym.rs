//! Symmetric block ciphers.
//!
//! Part 1 clause 11.4.6 requires unpadded encryption with a caller supplied IV
//! in CTR, OFB, CBC, CFB and ECB. The aws-lc-rs cipher interface manages
//! padding and IV generation on the caller's behalf, so the raw AES functions
//! of aws-lc-sys are used instead to keep the octet layout under the TPM's
//! control. CFB is the default mode for TPM protection values, and it is the
//! only mode where the IV is updated and handed back to the caller.

use std::os::raw::{c_int, c_uint};

use aws_lc_sys::{
    AES_cbc_encrypt, AES_cfb128_encrypt, AES_ctr128_encrypt, AES_ecb_encrypt, AES_ofb128_encrypt,
    AES_set_decrypt_key, AES_set_encrypt_key, AES_KEY,
};

use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};

/// AES block size in octets.
pub const AES_BLOCK_SIZE: usize = 16;

/// Block size of `algorithm` in octets.
pub fn block_size(algorithm: u16) -> TpmResult<usize> {
    match algorithm {
        alg::AES => Ok(AES_BLOCK_SIZE),
        _ => Err(TpmRc(rc::SYMMETRIC)),
    }
}

/// True when the TPM implements `algorithm` as a block cipher.
pub fn is_supported(algorithm: u16, key_bits: u16) -> bool {
    algorithm == alg::AES && matches!(key_bits, 128 | 192 | 256)
}

/// True when the TPM implements `mode`.
pub fn is_supported_mode(mode: u16) -> bool {
    matches!(mode, alg::CTR | alg::OFB | alg::CBC | alg::CFB | alg::ECB)
}

/// Direction of a symmetric operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

fn expanded_key(key: &[u8], direction: Direction, mode: u16) -> TpmResult<AES_KEY> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(TpmRc(rc::KEY_SIZE));
    }
    // CFB, CTR and OFB only ever run the cipher forwards, so they need the
    // encryption key schedule even when decrypting.
    let forward = matches!(direction, Direction::Encrypt)
        || matches!(mode, alg::CFB | alg::CTR | alg::OFB);
    let mut aes_key = AES_KEY {
        rd_key: [0u32; 60],
        rounds: 0,
    };
    let bits = (key.len() * 8) as c_uint;
    let rc_code = unsafe {
        if forward {
            AES_set_encrypt_key(key.as_ptr(), bits, &mut aes_key)
        } else {
            AES_set_decrypt_key(key.as_ptr(), bits, &mut aes_key)
        }
    };
    if rc_code != 0 {
        return Err(TpmRc(rc::KEY_SIZE));
    }
    Ok(aes_key)
}

/// Encrypt or decrypt `data` in place of returning a new buffer.
///
/// `iv` is updated for the chaining modes so a caller can continue a stream
/// across calls, which TPM2_EncryptDecrypt requires. ECB ignores the IV.
pub fn crypt(
    algorithm: u16,
    mode: u16,
    key: &[u8],
    iv: &mut [u8],
    data: &[u8],
    direction: Direction,
) -> TpmResult<Vec<u8>> {
    if algorithm != alg::AES {
        return Err(TpmRc(rc::SYMMETRIC));
    }
    if !is_supported_mode(mode) {
        return Err(TpmRc(rc::MODE));
    }
    // Every chaining mode needs an IV of exactly one block. ECB has no IV at
    // all, and Part 3 Table 64 requires its ivIn and ivOut to be empty.
    if mode == alg::ECB {
        if !iv.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
    } else if iv.len() != AES_BLOCK_SIZE {
        return Err(TpmRc(rc::SIZE));
    }
    if matches!(mode, alg::CBC | alg::ECB) && data.len() % AES_BLOCK_SIZE != 0 {
        return Err(TpmRc(rc::SIZE));
    }

    let aes_key = expanded_key(key, direction, mode)?;
    let mut out = vec![0u8; data.len()];
    let enc = c_int::from(matches!(direction, Direction::Encrypt));

    if data.is_empty() {
        return Ok(out);
    }

    match mode {
        alg::CFB => {
            let mut num: c_int = 0;
            unsafe {
                AES_cfb128_encrypt(
                    data.as_ptr(),
                    out.as_mut_ptr(),
                    data.len(),
                    &aes_key,
                    iv.as_mut_ptr(),
                    &mut num,
                    enc,
                );
            }
        }
        alg::OFB => {
            let mut num: c_int = 0;
            unsafe {
                AES_ofb128_encrypt(
                    data.as_ptr(),
                    out.as_mut_ptr(),
                    data.len(),
                    &aes_key,
                    iv.as_mut_ptr(),
                    &mut num,
                );
            }
        }
        alg::CTR => {
            let mut num: c_uint = 0;
            let mut ecount = [0u8; AES_BLOCK_SIZE];
            unsafe {
                AES_ctr128_encrypt(
                    data.as_ptr(),
                    out.as_mut_ptr(),
                    data.len(),
                    &aes_key,
                    iv.as_mut_ptr(),
                    ecount.as_mut_ptr(),
                    &mut num,
                );
            }
        }
        alg::CBC => unsafe {
            AES_cbc_encrypt(
                data.as_ptr(),
                out.as_mut_ptr(),
                data.len(),
                &aes_key,
                iv.as_mut_ptr(),
                enc,
            );
        },
        alg::ECB => {
            for (i, block) in data.chunks(AES_BLOCK_SIZE).enumerate() {
                unsafe {
                    AES_ecb_encrypt(
                        block.as_ptr(),
                        out[i * AES_BLOCK_SIZE..].as_mut_ptr(),
                        &aes_key,
                        enc,
                    );
                }
            }
        }
        _ => return Err(TpmRc(rc::MODE)),
    }
    Ok(out)
}

/// Encrypt with the given mode.
pub fn encrypt(
    algorithm: u16,
    mode: u16,
    key: &[u8],
    iv: &mut [u8],
    data: &[u8],
) -> TpmResult<Vec<u8>> {
    crypt(algorithm, mode, key, iv, data, Direction::Encrypt)
}

/// Decrypt with the given mode.
pub fn decrypt(
    algorithm: u16,
    mode: u16,
    key: &[u8],
    iv: &mut [u8],
    data: &[u8],
) -> TpmResult<Vec<u8>> {
    crypt(algorithm, mode, key, iv, data, Direction::Decrypt)
}

/// Encrypt with CFB and a zero IV that the caller does not need back.
///
/// This is the shape most TPM protection values use: a key and IV derived by
/// KDFa, then one CFB pass over the protected octets.
pub fn cfb_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> TpmResult<Vec<u8>> {
    let mut iv = iv.to_vec();
    encrypt(alg::AES, alg::CFB, key, &mut iv, data)
}

/// Decrypt a value produced by [`cfb_encrypt`].
pub fn cfb_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> TpmResult<Vec<u8>> {
    let mut iv = iv.to_vec();
    decrypt(alg::AES, alg::CFB, key, &mut iv, data)
}

/// The XOR obfuscation of Part 1 clause 11.4.6.3.
///
/// A mask of `data.len()` octets is produced by KDFa and combined with the
/// data. The operation is its own inverse.
pub fn xor_obfuscate(
    hash_alg: u16,
    key: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    data: &mut [u8],
) -> TpmResult<()> {
    let mask = super::hmac::kdfa(
        hash_alg,
        key,
        "XOR",
        nonce_newer,
        nonce_older,
        (data.len() * 8) as u32,
    )?;
    for (d, m) in data.iter_mut().zip(mask.iter()) {
        *d ^= m;
    }
    Ok(())
}

/// True when `key` is one the specification will not have.
///
/// Part 1 clause 8.4.10.4: "in the case of DES, there are 64 known weak or
/// semi-weak keys. None of them are allowed. In the case of AES, at least one
/// bit in the upper half of the key must be set."
pub fn is_weak_key(algorithm: u16, key: &[u8]) -> bool {
    match algorithm {
        alg::AES | alg::SM4 | alg::CAMELLIA => {
            let upper = &key[..key.len() / 2];
            upper.iter().all(|b| *b == 0)
        }
        alg::TDES => key.chunks(8).any(is_weak_des_key),
        _ => false,
    }
}

/// The weak and semi-weak DES keys, which clause 8.4.10.4 refuses.
///
/// A key is one of them when the two halves its schedule starts from, C0 and
/// D0, are each all zeros, all ones, or one of the two alternating patterns.
/// Those are the halves that survive every rotation the schedule applies, so
/// the sixteen round keys repeat instead of differing, which is what makes the
/// key weak. Deriving them is exact where a copied list could be mistyped.
fn is_weak_des_key(key: &[u8]) -> bool {
    /// PC-1 of FIPS 46-3, as one based positions in the 64 bit key counting
    /// from the most significant. The first 28 make C0 and the rest D0.
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
        37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    const HALVES: [u32; 4] = [0x000_0000, 0xfff_ffff, 0x555_5555, 0xaaa_aaaa];
    if key.len() != 8 {
        return false;
    }
    let whole = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let mut c0: u32 = 0;
    let mut d0: u32 = 0;
    for (i, position) in PC1.iter().enumerate() {
        let bit = ((whole >> (64 - position)) & 1) as u32;
        if i < 28 {
            c0 = (c0 << 1) | bit;
        } else {
            d0 = (d0 << 1) | bit;
        }
    }
    HALVES.contains(&c0) && HALVES.contains(&d0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_weak_key_is_recognised() {
        // Part 1 clause 8.4.10.4: of an AES key "at least one bit in the upper
        // half of the key must be set".
        assert!(is_weak_key(alg::AES, &[0u8; 16]));
        let mut k = [0u8; 16];
        k[15] = 1;
        assert!(is_weak_key(alg::AES, &k), "only the lower half was set");
        k[0] = 1;
        assert!(!is_weak_key(alg::AES, &k));

        // The same clause refuses the 64 weak and semi-weak DES keys. The
        // all-zero key and the alternating pattern are two of them.
        assert!(is_weak_key(alg::TDES, &[0x01u8; 8]));
        assert!(is_weak_key(
            alg::TDES,
            &[0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e]
        ));
        assert!(!is_weak_key(
            alg::TDES,
            &[0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]
        ));

        // The four patterns for each half give sixteen keys once the parity
        // bits are filled in, which is the published set of four weak and
        // twelve semi-weak keys. Counting them checks the derivation against
        // something known rather than against itself.
        let patterns: [u64; 4] = [0x000_0000, 0xfff_ffff, 0x555_5555, 0xaaa_aaaa];
        let mut found = 0;
        for c in patterns {
            for d in patterns {
                let key = des_key_from_halves(c, d);
                assert!(is_weak_key(alg::TDES, &key), "{key:02x?} was not refused");
                found += 1;
            }
        }
        assert_eq!(found, 16);
    }

    /// Put C0 and D0 back through PC-1 to get the key they came from, with
    /// odd parity in the low bit of each octet.
    fn des_key_from_halves(c0: u64, d0: u64) -> [u8; 8] {
        const PC1: [u8; 56] = [
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19,
            11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
            61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
        ];
        let joined = (c0 << 28) | d0;
        let mut whole: u64 = 0;
        for (i, position) in PC1.iter().enumerate() {
            let bit = (joined >> (55 - i)) & 1;
            whole |= bit << (64 - position);
        }
        let mut key = whole.to_be_bytes();
        for b in key.iter_mut() {
            *b &= 0xfe;
            if (b.count_ones() % 2) == 0 {
                *b |= 1;
            }
        }
        key
    }

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        crate::util::hex::decode(s).unwrap()
    }

    #[test]
    fn ecb_matches_fips_197() {
        // FIPS 197 appendix C.1, AES-128.
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let plain = hex("00112233445566778899aabbccddeeff");
        let mut iv = Vec::new();
        let ct = encrypt(alg::AES, alg::ECB, &key, &mut iv, &plain).unwrap();
        assert_eq!(ct, hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        let back = decrypt(alg::AES, alg::ECB, &key, &mut iv, &ct).unwrap();
        assert_eq!(back, plain);

        // FIPS 197 appendix C.2, AES-192.
        let key = hex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let ct = encrypt(alg::AES, alg::ECB, &key, &mut iv, &plain).unwrap();
        assert_eq!(ct, hex("dda97ca4864cdfe06eaf70a0ec0d7191"));

        // FIPS 197 appendix C.3, AES-256.
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ct = encrypt(alg::AES, alg::ECB, &key, &mut iv, &plain).unwrap();
        assert_eq!(ct, hex("8ea2b7ca516745bfeafc49904b496089"));
    }

    #[test]
    fn cbc_matches_sp800_38a() {
        // SP800-38A F.2.1, AES-128-CBC.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv0 = hex("000102030405060708090a0b0c0d0e0f");
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let mut iv = iv0.clone();
        let ct = encrypt(alg::AES, alg::CBC, &key, &mut iv, &plain).unwrap();
        assert_eq!(
            ct,
            hex(concat!(
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2",
                "73bed6b8e3c1743b7116e69e22229516",
                "3ff1caa1681fac09120eca307586e1a7"
            ))
        );
        let mut iv = iv0;
        assert_eq!(decrypt(alg::AES, alg::CBC, &key, &mut iv, &ct).unwrap(), plain);
    }

    #[test]
    fn cfb128_matches_sp800_38a() {
        // SP800-38A F.3.13, AES-128-CFB128.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv0 = hex("000102030405060708090a0b0c0d0e0f");
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ));
        let mut iv = iv0.clone();
        let ct = encrypt(alg::AES, alg::CFB, &key, &mut iv, &plain).unwrap();
        assert_eq!(
            ct,
            hex(concat!(
                "3b3fd92eb72dad20333449f8e83cfb4a",
                "c8a64537a0b3a93fcde3cdad9f1ce58b"
            ))
        );
        let mut iv = iv0;
        assert_eq!(decrypt(alg::AES, alg::CFB, &key, &mut iv, &ct).unwrap(), plain);
    }

    #[test]
    fn ofb_matches_sp800_38a() {
        // SP800-38A F.4.1, AES-128-OFB.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv0 = hex("000102030405060708090a0b0c0d0e0f");
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ));
        let mut iv = iv0.clone();
        let ct = encrypt(alg::AES, alg::OFB, &key, &mut iv, &plain).unwrap();
        assert_eq!(
            ct,
            hex(concat!(
                "3b3fd92eb72dad20333449f8e83cfb4a",
                "7789508d16918f03f53c52dac54ed825"
            ))
        );
        let mut iv = iv0;
        assert_eq!(decrypt(alg::AES, alg::OFB, &key, &mut iv, &ct).unwrap(), plain);
    }

    #[test]
    fn ctr_matches_sp800_38a() {
        // SP800-38A F.5.1, AES-128-CTR.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv0 = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ));
        let mut iv = iv0.clone();
        let ct = encrypt(alg::AES, alg::CTR, &key, &mut iv, &plain).unwrap();
        assert_eq!(
            ct,
            hex(concat!(
                "874d6191b620e3261bef6864990db6ce",
                "9806f66b7970fdff8617187bb9fffdff"
            ))
        );
        let mut iv = iv0;
        assert_eq!(decrypt(alg::AES, alg::CTR, &key, &mut iv, &ct).unwrap(), plain);
    }

    #[test]
    fn cfb_updates_the_iv_so_a_stream_can_continue() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv0 = hex("000102030405060708090a0b0c0d0e0f");
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ));

        let mut iv = iv0.clone();
        let whole = encrypt(alg::AES, alg::CFB, &key, &mut iv, &plain).unwrap();

        let mut iv = iv0;
        let mut split = encrypt(alg::AES, alg::CFB, &key, &mut iv, &plain[..16]).unwrap();
        split.extend(encrypt(alg::AES, alg::CFB, &key, &mut iv, &plain[16..]).unwrap());
        assert_eq!(split, whole);
    }

    #[test]
    fn cfb_helpers_round_trip_any_length() {
        let key = [7u8; 32];
        let iv = [3u8; 16];
        for len in [0usize, 1, 15, 16, 17, 100] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = cfb_encrypt(&key, &iv, &data).unwrap();
            assert_eq!(ct.len(), len);
            assert_eq!(cfb_decrypt(&key, &iv, &ct).unwrap(), data);
        }
    }

    #[test]
    fn block_modes_require_whole_blocks() {
        let key = [0u8; 16];
        let mut iv = [0u8; 16];
        assert_eq!(
            encrypt(alg::AES, alg::CBC, &key, &mut iv, &[0u8; 17]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        let mut none: Vec<u8> = Vec::new();
        assert_eq!(
            encrypt(alg::AES, alg::ECB, &key, &mut none, &[0u8; 3]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        // A stream mode accepts any length.
        assert!(encrypt(alg::AES, alg::CFB, &key, &mut iv, &[0u8; 17]).is_ok());
    }

    #[test]
    fn bad_parameters_are_rejected() {
        let mut iv = [0u8; 16];
        assert_eq!(
            encrypt(alg::AES, alg::CFB, &[0u8; 17], &mut iv, b"x").unwrap_err(),
            TpmRc(rc::KEY_SIZE)
        );
        assert_eq!(
            encrypt(alg::SM4, alg::CFB, &[0u8; 16], &mut iv, b"x").unwrap_err(),
            TpmRc(rc::SYMMETRIC)
        );
        assert_eq!(
            encrypt(alg::AES, alg::NULL, &[0u8; 16], &mut iv, b"x").unwrap_err(),
            TpmRc(rc::MODE)
        );
        let mut short = [0u8; 8];
        assert_eq!(
            encrypt(alg::AES, alg::CFB, &[0u8; 16], &mut short, b"x").unwrap_err(),
            TpmRc(rc::SIZE)
        );
    }

    #[test]
    fn supported_sizes_and_modes() {
        assert!(is_supported(alg::AES, 128));
        assert!(is_supported(alg::AES, 192));
        assert!(is_supported(alg::AES, 256));
        assert!(!is_supported(alg::AES, 64));
        assert!(!is_supported(alg::SM4, 128));
        for m in [alg::CTR, alg::OFB, alg::CBC, alg::CFB, alg::ECB] {
            assert!(is_supported_mode(m));
        }
        assert!(!is_supported_mode(alg::NULL));
        assert_eq!(block_size(alg::AES).unwrap(), 16);
        assert!(block_size(alg::SM4).is_err());
    }

    #[test]
    fn xor_obfuscation_is_its_own_inverse() {
        let key = b"session key";
        let mut data = b"the quick brown fox".to_vec();
        let original = data.clone();
        xor_obfuscate(alg::SHA256, key, b"newer", b"older", &mut data).unwrap();
        assert_ne!(data, original);
        xor_obfuscate(alg::SHA256, key, b"newer", b"older", &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn xor_obfuscation_uses_the_kdfa_mask() {
        let key = b"k";
        let mut data = vec![0u8; 8];
        xor_obfuscate(alg::SHA256, key, b"u", b"v", &mut data).unwrap();
        let mask = super::super::hmac::kdfa(alg::SHA256, key, "XOR", b"u", b"v", 64).unwrap();
        assert_eq!(data, mask);
    }
}
