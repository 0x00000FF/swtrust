//! RSA.
//!
//! Part 1 clause 11.2.4 describes what the TPM needs: key generation that can
//! be repeated from a seed, the raw RSAEP and RSADP primitives, and the OAEP,
//! PKCS#1 v1.5 and PSS paddings of RFC 8017. The TPM stores only one prime in
//! the private area and recovers the rest, so this module works from `(n, e,
//! p)` throughout.

use crate::tpm::config;
use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};

use super::bn::{BigNum, BnCtx};
use super::hash::{digest, digest_size};
use super::hmac::mgf1;
use super::rand::Rng;

/// Rounds of Miller-Rabin applied to a candidate prime.
///
/// FIPS 186-5 table B.1 asks for 4 rounds at 2048 bits and 3 at 3072. The
/// library also runs trial division first, and a higher count costs little
/// during key generation, so the margin is generous.
const PRIMALITY_CHECKS: u32 = 64;

/// The default public exponent when a template asks for zero.
pub const DEFAULT_EXPONENT: u32 = config::RSA_DEFAULT_PUBLIC_EXPONENT;

/// An RSA public key.
#[derive(Debug)]
pub struct RsaPublic {
    pub n: BigNum,
    pub e: BigNum,
}

impl RsaPublic {
    /// Build from a big endian modulus and an exponent, where zero selects the
    /// default exponent of 65537.
    pub fn new(modulus: &[u8], exponent: u32) -> TpmResult<RsaPublic> {
        let n = BigNum::from_bytes(modulus)?;
        if n.is_zero() {
            return Err(TpmRc(rc::KEY));
        }
        let e = BigNum::from_u64(effective_exponent(exponent) as u64)?;
        Ok(RsaPublic { n, e })
    }

    /// Size of the modulus in octets, which is the size of every ciphertext
    /// and signature.
    pub fn size(&self) -> usize {
        (self.n.bits() + 7) / 8
    }

    /// Number of bits in the modulus.
    pub fn bits(&self) -> usize {
        self.n.bits()
    }
}

/// An RSA private key, held as the public key plus one prime.
///
/// The TPM stores only `p` in the sensitive area; `q` and `d` are recovered
/// from the modulus and the public exponent whenever the key is loaded.
#[derive(Debug)]
pub struct RsaPrivate {
    pub public: RsaPublic,
    pub p: BigNum,
    pub q: BigNum,
    d: BigNum,
}

/// The exponent actually used: zero means the default.
pub fn effective_exponent(exponent: u32) -> u32 {
    if exponent == 0 {
        DEFAULT_EXPONENT
    } else {
        exponent
    }
}

impl RsaPrivate {
    /// Rebuild a private key from the public area and the stored prime.
    ///
    /// The second prime is `n / p` and the private exponent is the inverse of
    /// `e` modulo `lcm(p-1, q-1)`.
    pub fn from_prime(modulus: &[u8], exponent: u32, prime: &[u8]) -> TpmResult<RsaPrivate> {
        let public = RsaPublic::new(modulus, exponent)?;
        let ctx = BnCtx::new()?;
        let p = BigNum::from_bytes(prime)?;
        if p.is_zero() || p.is_one() {
            return Err(TpmRc(rc::KEY));
        }
        let (q, r) = public.n.div_rem(&p, &ctx)?;
        if !r.is_zero() || q.is_zero() || q.is_one() {
            return Err(TpmRc(rc::KEY));
        }
        let d = private_exponent(&public.e, &p, &q, &ctx)?;
        Ok(RsaPrivate { public, p, q, d })
    }

    /// Build from two primes, computing the modulus.
    pub fn from_primes(p: BigNum, q: BigNum, exponent: u32, ctx: &BnCtx) -> TpmResult<RsaPrivate> {
        let n = p.mul(&q, ctx)?;
        let e = BigNum::from_u64(effective_exponent(exponent) as u64)?;
        let d = private_exponent(&e, &p, &q, ctx)?;
        Ok(RsaPrivate {
            public: RsaPublic { n, e },
            p,
            q,
            d,
        })
    }

    /// Size of the modulus in octets.
    pub fn size(&self) -> usize {
        self.public.size()
    }

    /// The stored prime as octets, padded to half the modulus size.
    pub fn prime_bytes(&self) -> TpmResult<Vec<u8>> {
        self.p.to_bytes_padded(self.size() / 2)
    }

    /// The modulus as octets, padded to the key size.
    pub fn modulus_bytes(&self) -> TpmResult<Vec<u8>> {
        self.public.n.to_bytes_padded(self.size())
    }
}

/// `d = e^-1 mod lcm(p-1, q-1)`.
fn private_exponent(e: &BigNum, p: &BigNum, q: &BigNum, ctx: &BnCtx) -> TpmResult<BigNum> {
    let p1 = p.sub_word(1)?;
    let q1 = q.sub_word(1)?;
    let product = p1.mul(&q1, ctx)?;
    let g = p1.gcd(&q1, ctx)?;
    let (lambda, rem) = product.div_rem(&g, ctx)?;
    if !rem.is_zero() {
        return Err(TpmRc(rc::FAILURE));
    }
    e.mod_inverse(&lambda, ctx)
}

/// Generate a key of `key_bits` bits, taking every octet from `rng`.
///
/// Passing a deterministic generator makes the key reproducible, which is what
/// TPM2_CreatePrimary needs. Each prime is drawn with its top two bits set so
/// the product always has exactly `key_bits` bits, following FIPS 186-5
/// appendix A.1.3.
pub fn generate(rng: &mut dyn Rng, key_bits: u16, exponent: u32) -> TpmResult<RsaPrivate> {
    if key_bits < 1024 || key_bits > config::MAX_RSA_KEY_BITS || key_bits % 8 != 0 {
        return Err(TpmRc(rc::KEY_SIZE));
    }
    let e_value = effective_exponent(exponent);
    if e_value < 3 || e_value % 2 == 0 {
        return Err(TpmRc(rc::VALUE));
    }
    let ctx = BnCtx::new()?;
    let e = BigNum::from_u64(e_value as u64)?;
    let prime_bits = key_bits as usize / 2;

    let p = generate_prime(rng, prime_bits, &e, &ctx)?;
    // The second prime must differ from the first, and the product must have
    // the full modulus width.
    loop {
        let q = generate_prime(rng, prime_bits, &e, &ctx)?;
        if q.cmp(&p) == 0 {
            continue;
        }
        let n = p.mul(&q, &ctx)?;
        if n.bits() != key_bits as usize {
            continue;
        }
        let d = private_exponent(&e, &p, &q, &ctx)?;
        // A private exponent that is too small is weak, so it is rejected and
        // a fresh prime is drawn.
        if d.bits() * 4 < key_bits as usize {
            continue;
        }
        return Ok(RsaPrivate {
            public: RsaPublic { n, e: e.duplicate()? },
            p,
            q,
            d,
        });
    }
}

/// Draw candidates from `rng` until one is prime and coprime with `e`.
fn generate_prime(
    rng: &mut dyn Rng,
    bits: usize,
    e: &BigNum,
    ctx: &BnCtx,
) -> TpmResult<BigNum> {
    let bytes = bits / 8;
    let one = BigNum::from_u64(1)?;
    loop {
        let mut candidate = rng.bytes(bytes)?;
        // Set the top two bits so the product of two primes has the full
        // width, and set the low bit so the candidate is odd.
        candidate[0] |= 0xC0;
        let last = bytes - 1;
        candidate[last] |= 0x01;
        let n = BigNum::from_bytes(&candidate)?;
        if n.bits() != bits {
            continue;
        }
        // gcd(p - 1, e) must be one or e has no inverse.
        let n1 = n.sub_word(1)?;
        if n1.gcd(e, ctx)?.cmp(&one) != 0 {
            continue;
        }
        if n.is_probably_prime(PRIMALITY_CHECKS, ctx)? {
            return Ok(n);
        }
    }
}

/// RSAEP: `m^e mod n`, with no padding.
///
/// The input must be exactly the modulus size and numerically below the
/// modulus, which is what Part 3 TPM2_RSA_Encrypt with TPM_ALG_NULL requires.
pub fn public_op(key: &RsaPublic, input: &[u8]) -> TpmResult<Vec<u8>> {
    let size = key.size();
    if input.len() != size {
        return Err(TpmRc(rc::SIZE));
    }
    let m = BigNum::from_bytes(input)?;
    if m.cmp(&key.n) >= 0 {
        return Err(TpmRc(rc::VALUE));
    }
    let ctx = BnCtx::new()?;
    m.mod_exp(&key.e, &key.n, &ctx)?.to_bytes_padded(size)
}

/// RSADP: `c^d mod n`, with no padding.
pub fn private_op(key: &RsaPrivate, input: &[u8]) -> TpmResult<Vec<u8>> {
    let size = key.size();
    if input.len() != size {
        return Err(TpmRc(rc::SIZE));
    }
    let c = BigNum::from_bytes(input)?;
    if c.cmp(&key.public.n) >= 0 {
        return Err(TpmRc(rc::VALUE));
    }
    let ctx = BnCtx::new()?;
    c.mod_exp(&key.d, &key.public.n, &ctx)?
        .to_bytes_padded(size)
}

/// OAEP encoding from RFC 8017 section 7.1.1.
///
/// The TPM appends a zero octet to the label, so `label` here is the raw label
/// text without that terminator.
pub fn oaep_encode(
    hash_alg: u16,
    key_size: usize,
    message: &[u8],
    label: &[u8],
    rng: &mut dyn Rng,
) -> TpmResult<Vec<u8>> {
    let h_len = digest_size(hash_alg)?;
    if key_size < 2 * h_len + 2 {
        return Err(TpmRc(rc::KEY_SIZE));
    }
    if message.len() > key_size - 2 * h_len - 2 {
        return Err(TpmRc(rc::VALUE));
    }
    let l_hash = digest(hash_alg, label)?;
    let ps_len = key_size - message.len() - 2 * h_len - 2;

    let mut db = Vec::with_capacity(key_size - h_len - 1);
    db.extend_from_slice(&l_hash);
    db.extend(std::iter::repeat(0u8).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(message);

    let seed = rng.bytes(h_len)?;
    let db_mask = mgf1(hash_alg, &seed, db.len())?;
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= m;
    }
    let seed_mask = mgf1(hash_alg, &db, h_len)?;
    let mut masked_seed = seed;
    for (s, m) in masked_seed.iter_mut().zip(seed_mask.iter()) {
        *s ^= m;
    }

    let mut out = Vec::with_capacity(key_size);
    out.push(0x00);
    out.extend_from_slice(&masked_seed);
    out.extend_from_slice(&db);
    Ok(out)
}

/// OAEP decoding from RFC 8017 section 7.1.2.
///
/// Every failure returns the same response code so the reason cannot be told
/// apart, which RFC 8017 section 7.1.2 note 1 requires.
pub fn oaep_decode(hash_alg: u16, encoded: &[u8], label: &[u8]) -> TpmResult<Vec<u8>> {
    let h_len = digest_size(hash_alg)?;
    let key_size = encoded.len();
    if key_size < 2 * h_len + 2 {
        return Err(TpmRc(rc::VALUE));
    }
    let l_hash = digest(hash_alg, label)?;

    let masked_seed = &encoded[1..1 + h_len];
    let masked_db = &encoded[1 + h_len..];

    let seed_mask = mgf1(hash_alg, masked_db, h_len)?;
    let mut seed = masked_seed.to_vec();
    for (s, m) in seed.iter_mut().zip(seed_mask.iter()) {
        *s ^= m;
    }
    let db_mask = mgf1(hash_alg, &seed, masked_db.len())?;
    let mut db = masked_db.to_vec();
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= m;
    }

    // Collect every failure into one flag before deciding, so the work done is
    // the same whichever check fails.
    let mut bad = encoded[0] != 0x00;
    let mut hash_mismatch = 0u8;
    for (a, b) in db[..h_len].iter().zip(l_hash.iter()) {
        hash_mismatch |= a ^ b;
    }
    bad |= hash_mismatch != 0;

    let mut separator: Option<usize> = None;
    for (i, b) in db.iter().enumerate().skip(h_len) {
        match *b {
            0x00 => {}
            0x01 if separator.is_none() => separator = Some(i),
            _ if separator.is_none() => {
                bad = true;
                break;
            }
            _ => {}
        }
    }
    match separator {
        Some(i) if !bad => Ok(db[i + 1..].to_vec()),
        _ => Err(TpmRc(rc::VALUE)),
    }
}

/// PKCS#1 v1.5 encryption padding, RFC 8017 section 7.2.1.
pub fn pkcs1v15_encrypt_pad(
    key_size: usize,
    message: &[u8],
    rng: &mut dyn Rng,
) -> TpmResult<Vec<u8>> {
    if key_size < 11 || message.len() > key_size - 11 {
        return Err(TpmRc(rc::VALUE));
    }
    let ps_len = key_size - message.len() - 3;
    let mut ps = Vec::with_capacity(ps_len);
    // Every padding octet must be non-zero, so zeros drawn from the generator
    // are replaced rather than kept.
    while ps.len() < ps_len {
        for b in rng.bytes(ps_len - ps.len() + 8)? {
            if b != 0 {
                ps.push(b);
                if ps.len() == ps_len {
                    break;
                }
            }
        }
    }
    let mut out = Vec::with_capacity(key_size);
    out.push(0x00);
    out.push(0x02);
    out.extend_from_slice(&ps);
    out.push(0x00);
    out.extend_from_slice(message);
    Ok(out)
}

/// Remove PKCS#1 v1.5 encryption padding.
pub fn pkcs1v15_encrypt_unpad(encoded: &[u8]) -> TpmResult<Vec<u8>> {
    if encoded.len() < 11 || encoded[0] != 0x00 || encoded[1] != 0x02 {
        return Err(TpmRc(rc::VALUE));
    }
    // The separator must come after at least eight padding octets.
    match encoded[2..].iter().position(|b| *b == 0x00) {
        Some(i) if i >= 8 => Ok(encoded[2 + i + 1..].to_vec()),
        _ => Err(TpmRc(rc::VALUE)),
    }
}

/// The DER prefix of a DigestInfo for `hash_alg`, RFC 8017 section 9.2 note 1.
fn digest_info_prefix(hash_alg: u16) -> TpmResult<&'static [u8]> {
    use crate::tpm::constants::alg;
    Ok(match hash_alg {
        alg::SHA1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        alg::SHA256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        alg::SHA384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        alg::SHA512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        alg::SHA3_256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ],
        alg::SHA3_384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00, 0x04, 0x30,
        ],
        alg::SHA3_512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00, 0x04, 0x40,
        ],
        _ => return Err(TpmRc(rc::HASH)),
    })
}

/// EMSA-PKCS1-v1_5 encoding, RFC 8017 section 9.2, used by TPM_ALG_RSASSA.
pub fn pkcs1v15_sign_encode(hash_alg: u16, digest: &[u8], key_size: usize) -> TpmResult<Vec<u8>> {
    let h_len = digest_size(hash_alg)?;
    if digest.len() != h_len {
        return Err(TpmRc(rc::SIZE));
    }
    let prefix = digest_info_prefix(hash_alg)?;
    let t_len = prefix.len() + h_len;
    if key_size < t_len + 11 {
        return Err(TpmRc(rc::KEY_SIZE));
    }
    let mut out = Vec::with_capacity(key_size);
    out.push(0x00);
    out.push(0x01);
    out.extend(std::iter::repeat(0xffu8).take(key_size - t_len - 3));
    out.push(0x00);
    out.extend_from_slice(prefix);
    out.extend_from_slice(digest);
    Ok(out)
}

/// EMSA-PSS encoding, RFC 8017 section 9.1.1.
///
/// Part 1 clause 11.2.4.5 says the TPM uses the largest salt the key allows,
/// so `sLen = emLen - hLen - 2`.
pub fn pss_encode(
    hash_alg: u16,
    digest_value: &[u8],
    key_bits: usize,
    rng: &mut dyn Rng,
) -> TpmResult<Vec<u8>> {
    let h_len = digest_size(hash_alg)?;
    if digest_value.len() != h_len {
        return Err(TpmRc(rc::SIZE));
    }
    // emBits is one less than the modulus bit length.
    let em_bits = key_bits - 1;
    let em_len = (em_bits + 7) / 8;
    if em_len < h_len + 2 {
        return Err(TpmRc(rc::KEY_SIZE));
    }
    let salt_len = em_len - h_len - 2;
    let salt = rng.bytes(salt_len)?;

    let mut m_prime = Vec::with_capacity(8 + h_len + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest_value);
    m_prime.extend_from_slice(&salt);
    let h = digest(hash_alg, &m_prime)?;

    let ps_len = em_len - salt_len - h_len - 2;
    let mut db = Vec::with_capacity(em_len - h_len - 1);
    db.extend(std::iter::repeat(0u8).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(&salt);

    let db_mask = mgf1(hash_alg, &h, db.len())?;
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= m;
    }
    // Clear the leading bits that fall outside emBits.
    let clear = 8 * em_len - em_bits;
    if clear > 0 {
        db[0] &= 0xffu8 >> clear;
    }

    let mut out = Vec::with_capacity(em_len);
    out.extend_from_slice(&db);
    out.extend_from_slice(&h);
    out.push(0xbc);
    Ok(out)
}

/// EMSA-PSS verification, RFC 8017 section 9.1.2, accepting any salt length.
pub fn pss_verify(
    hash_alg: u16,
    digest_value: &[u8],
    encoded: &[u8],
    key_bits: usize,
) -> TpmResult<()> {
    let h_len = digest_size(hash_alg)?;
    if digest_value.len() != h_len {
        return Err(TpmRc(rc::SIZE));
    }
    let em_bits = key_bits - 1;
    let em_len = (em_bits + 7) / 8;
    if encoded.len() != em_len || em_len < h_len + 2 {
        return Err(TpmRc(rc::SIGNATURE));
    }
    if *encoded.last().unwrap() != 0xbc {
        return Err(TpmRc(rc::SIGNATURE));
    }
    let db_len = em_len - h_len - 1;
    let masked_db = &encoded[..db_len];
    let h = &encoded[db_len..db_len + h_len];

    let clear = 8 * em_len - em_bits;
    if clear > 0 && masked_db[0] & !(0xffu8 >> clear) != 0 {
        return Err(TpmRc(rc::SIGNATURE));
    }

    let db_mask = mgf1(hash_alg, h, db_len)?;
    let mut db = masked_db.to_vec();
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= m;
    }
    if clear > 0 {
        db[0] &= 0xffu8 >> clear;
    }

    // Find the 0x01 separator that follows the zero padding.
    let sep = match db.iter().position(|b| *b != 0x00) {
        Some(i) if db[i] == 0x01 => i,
        _ => return Err(TpmRc(rc::SIGNATURE)),
    };
    let salt = &db[sep + 1..];

    let mut m_prime = Vec::with_capacity(8 + h_len + salt.len());
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest_value);
    m_prime.extend_from_slice(salt);
    if digest(hash_alg, &m_prime)? != h {
        return Err(TpmRc(rc::SIGNATURE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;
    use crate::tpm::crypto::rand::{Drbg, SeededRng};

    fn rng() -> Drbg {
        Drbg::new(&[0x5au8; 48], b"rsa").unwrap()
    }

    /// A 1024 bit key, which is the smallest the TPM accepts, generated once
    /// per test to keep the suite quick.
    fn small_key() -> RsaPrivate {
        let mut r = SeededRng::new(alg::SHA256, &[7u8; 32], "TEST", b"rsa");
        generate(&mut r, 1024, 0).unwrap()
    }

    #[test]
    fn generation_produces_a_usable_key() {
        let key = small_key();
        assert_eq!(key.public.bits(), 1024);
        assert_eq!(key.size(), 128);
        assert_eq!(key.prime_bytes().unwrap().len(), 64);
        assert_eq!(key.modulus_bytes().unwrap().len(), 128);

        // n = p * q with both primes odd and greater than one.
        let ctx = BnCtx::new().unwrap();
        let (q, r) = key.public.n.div_rem(&key.p, &ctx).unwrap();
        assert!(r.is_zero());
        assert!(key.p.is_odd() && q.is_odd());
    }

    #[test]
    fn generation_is_deterministic_for_a_seed() {
        let a = small_key();
        let b = small_key();
        assert_eq!(a.modulus_bytes().unwrap(), b.modulus_bytes().unwrap());
        assert_eq!(a.prime_bytes().unwrap(), b.prime_bytes().unwrap());
    }

    #[test]
    fn generation_differs_for_a_different_seed() {
        let mut r = SeededRng::new(alg::SHA256, &[8u8; 32], "TEST", b"rsa");
        let other = generate(&mut r, 1024, 0).unwrap();
        assert_ne!(
            other.modulus_bytes().unwrap(),
            small_key().modulus_bytes().unwrap()
        );
    }

    #[test]
    fn generation_rejects_bad_parameters() {
        let mut r = rng();
        assert_eq!(generate(&mut r, 512, 0).unwrap_err(), TpmRc(rc::KEY_SIZE));
        assert_eq!(
            generate(&mut r, 8192, 0).unwrap_err(),
            TpmRc(rc::KEY_SIZE)
        );
        assert_eq!(generate(&mut r, 1023, 0).unwrap_err(), TpmRc(rc::KEY_SIZE));
        assert_eq!(generate(&mut r, 1024, 4).unwrap_err(), TpmRc(rc::VALUE));
        assert_eq!(generate(&mut r, 1024, 1).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn private_key_can_be_rebuilt_from_the_stored_prime() {
        let key = small_key();
        let rebuilt = RsaPrivate::from_prime(
            &key.modulus_bytes().unwrap(),
            0,
            &key.prime_bytes().unwrap(),
        )
        .unwrap();
        // Both keys must agree on every operation.
        let msg = vec![0x01u8; 128];
        let a = private_op(&key, &msg).unwrap();
        let b = private_op(&rebuilt, &msg).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rebuilding_rejects_a_prime_that_does_not_divide_the_modulus() {
        let key = small_key();
        let mut bad = key.prime_bytes().unwrap();
        bad[63] ^= 0x02;
        assert_eq!(
            RsaPrivate::from_prime(&key.modulus_bytes().unwrap(), 0, &bad).unwrap_err(),
            TpmRc(rc::KEY)
        );
    }

    #[test]
    fn raw_operations_are_inverses() {
        let key = small_key();
        let mut message = vec![0u8; 128];
        message[1..].copy_from_slice(&[0x42u8; 127]);
        let c = public_op(&key.public, &message).unwrap();
        assert_eq!(c.len(), 128);
        assert_eq!(private_op(&key, &c).unwrap(), message);

        // And in the other order, which is what signing does.
        let s = private_op(&key, &message).unwrap();
        assert_eq!(public_op(&key.public, &s).unwrap(), message);
    }

    #[test]
    fn raw_operations_check_their_input() {
        let key = small_key();
        assert_eq!(
            public_op(&key.public, &[0u8; 127]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        // A value at or above the modulus is out of range.
        let n = key.modulus_bytes().unwrap();
        assert_eq!(public_op(&key.public, &n).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn oaep_round_trip() {
        let mut r = rng();
        for hash in [alg::SHA1, alg::SHA256, alg::SHA384] {
            let msg = b"a short message";
            let encoded = oaep_encode(hash, 128, msg, b"LABEL\0", &mut r).unwrap();
            assert_eq!(encoded.len(), 128);
            assert_eq!(encoded[0], 0x00);
            assert_eq!(oaep_decode(hash, &encoded, b"LABEL\0").unwrap(), msg);
        }
    }

    #[test]
    fn oaep_rejects_a_wrong_label_or_corrupt_block() {
        let mut r = rng();
        let encoded = oaep_encode(alg::SHA256, 128, b"msg", b"A\0", &mut r).unwrap();
        assert_eq!(
            oaep_decode(alg::SHA256, &encoded, b"B\0").unwrap_err(),
            TpmRc(rc::VALUE)
        );
        let mut bad = encoded.clone();
        bad[40] ^= 0xff;
        assert_eq!(
            oaep_decode(alg::SHA256, &bad, b"A\0").unwrap_err(),
            TpmRc(rc::VALUE)
        );
        let mut bad = encoded;
        bad[0] = 0x01;
        assert_eq!(
            oaep_decode(alg::SHA256, &bad, b"A\0").unwrap_err(),
            TpmRc(rc::VALUE)
        );
    }

    #[test]
    fn oaep_message_length_is_bounded() {
        let mut r = rng();
        let h_len = 32;
        let max = 128 - 2 * h_len - 2;
        assert!(oaep_encode(alg::SHA256, 128, &vec![0u8; max], b"", &mut r).is_ok());
        assert_eq!(
            oaep_encode(alg::SHA256, 128, &vec![0u8; max + 1], b"", &mut r).unwrap_err(),
            TpmRc(rc::VALUE)
        );
        // A key too small for the hash is refused.
        assert_eq!(
            oaep_encode(alg::SHA512, 64, b"x", b"", &mut r).unwrap_err(),
            TpmRc(rc::KEY_SIZE)
        );
    }

    #[test]
    fn oaep_empty_message_round_trips() {
        let mut r = rng();
        let encoded = oaep_encode(alg::SHA256, 128, b"", b"", &mut r).unwrap();
        assert_eq!(oaep_decode(alg::SHA256, &encoded, b"").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn pkcs1v15_encryption_round_trip() {
        let mut r = rng();
        let padded = pkcs1v15_encrypt_pad(128, b"secret", &mut r).unwrap();
        assert_eq!(padded.len(), 128);
        assert_eq!(padded[0], 0x00);
        assert_eq!(padded[1], 0x02);
        // The padding string has no zero octet.
        let sep = padded[2..].iter().position(|b| *b == 0).unwrap();
        assert!(sep >= 8);
        assert_eq!(pkcs1v15_encrypt_unpad(&padded).unwrap(), b"secret");
    }

    #[test]
    fn pkcs1v15_encryption_rejects_bad_blocks() {
        assert!(pkcs1v15_encrypt_unpad(&[0u8; 5]).is_err());
        let mut block = vec![0u8; 128];
        block[1] = 0x01;
        assert!(pkcs1v15_encrypt_unpad(&block).is_err());
        // Fewer than eight padding octets before the separator.
        let mut block = vec![0xffu8; 128];
        block[0] = 0x00;
        block[1] = 0x02;
        block[5] = 0x00;
        assert!(pkcs1v15_encrypt_unpad(&block).is_err());
    }

    #[test]
    fn pkcs1v15_signature_encoding_matches_the_standard() {
        let d = vec![0xabu8; 32];
        let em = pkcs1v15_sign_encode(alg::SHA256, &d, 128).unwrap();
        assert_eq!(em.len(), 128);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        // The padding is all 0xff up to a single zero separator.
        let sep = em.iter().position(|b| *b == 0x00 && *b != em[0]).unwrap_or(0);
        let _ = sep;
        let zero = 2 + em[2..].iter().position(|b| *b == 0x00).unwrap();
        assert!(em[2..zero].iter().all(|b| *b == 0xff));
        assert!(zero - 2 >= 8);
        // The DigestInfo prefix and digest follow.
        assert_eq!(&em[zero + 1..zero + 20], digest_info_prefix(alg::SHA256).unwrap());
        assert_eq!(&em[em.len() - 32..], &d[..]);
    }

    #[test]
    fn pkcs1v15_signature_encoding_checks_sizes() {
        assert_eq!(
            pkcs1v15_sign_encode(alg::SHA256, &[0u8; 31], 128).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        assert_eq!(
            pkcs1v15_sign_encode(alg::SHA512, &[0u8; 64], 64).unwrap_err(),
            TpmRc(rc::KEY_SIZE)
        );
        assert_eq!(
            pkcs1v15_sign_encode(alg::NULL, &[0u8; 32], 128).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }

    #[test]
    fn pss_round_trip() {
        let mut r = rng();
        for hash in [alg::SHA1, alg::SHA256, alg::SHA384] {
            let h_len = digest_size(hash).unwrap();
            let d = vec![0x5au8; h_len];
            let em = pss_encode(hash, &d, 1024, &mut r).unwrap();
            assert_eq!(em.len(), 128);
            assert_eq!(*em.last().unwrap(), 0xbc);
            pss_verify(hash, &d, &em, 1024).unwrap();
        }
    }

    #[test]
    fn pss_uses_the_largest_salt() {
        let mut r = rng();
        let d = vec![0x11u8; 32];
        let em = pss_encode(alg::SHA256, &d, 1024, &mut r).unwrap();
        // emLen is 128, so the salt is 128 - 32 - 2 = 94 octets and the
        // padding string is empty, leaving 0x01 as the first octet of DB.
        let db_len = 128 - 32 - 1;
        let db_mask = mgf1(alg::SHA256, &em[db_len..db_len + 32], db_len).unwrap();
        let mut db = em[..db_len].to_vec();
        for (a, b) in db.iter_mut().zip(db_mask.iter()) {
            *a ^= b;
        }
        db[0] &= 0x7f;
        assert_eq!(db[0], 0x01);
    }

    #[test]
    fn pss_rejects_corrupt_encodings() {
        let mut r = rng();
        let d = vec![0x22u8; 32];
        let em = pss_encode(alg::SHA256, &d, 1024, &mut r).unwrap();

        let mut bad = em.clone();
        *bad.last_mut().unwrap() = 0xbb;
        assert!(pss_verify(alg::SHA256, &d, &bad, 1024).is_err());

        let mut bad = em.clone();
        bad[0] ^= 0x80;
        assert!(pss_verify(alg::SHA256, &d, &bad, 1024).is_err());

        let mut bad = em.clone();
        bad[50] ^= 0x01;
        assert!(pss_verify(alg::SHA256, &d, &bad, 1024).is_err());

        // A different digest does not verify.
        assert!(pss_verify(alg::SHA256, &vec![0x23u8; 32], &em, 1024).is_err());
        // The wrong length is refused.
        assert!(pss_verify(alg::SHA256, &d, &em[..127], 1024).is_err());
    }

    #[test]
    fn signature_over_a_generated_key_verifies() {
        let key = small_key();
        let mut r = rng();
        let d = digest(alg::SHA256, b"message to sign").unwrap();

        // RSASSA
        let em = pkcs1v15_sign_encode(alg::SHA256, &d, key.size()).unwrap();
        let sig = private_op(&key, &em).unwrap();
        let recovered = public_op(&key.public, &sig).unwrap();
        assert_eq!(recovered, em);

        // RSAPSS
        let em = pss_encode(alg::SHA256, &d, key.public.bits(), &mut r).unwrap();
        let mut block = vec![0u8; key.size() - em.len()];
        block.extend_from_slice(&em);
        let sig = private_op(&key, &block).unwrap();
        let recovered = public_op(&key.public, &sig).unwrap();
        pss_verify(
            alg::SHA256,
            &d,
            &recovered[recovered.len() - em.len()..],
            key.public.bits(),
        )
        .unwrap();
    }

    #[test]
    fn oaep_encryption_over_a_generated_key() {
        let key = small_key();
        let mut r = rng();
        let msg = b"credential";
        let em = oaep_encode(alg::SHA256, key.size(), msg, b"IDENTITY\0", &mut r).unwrap();
        let ct = public_op(&key.public, &em).unwrap();
        let pt = private_op(&key, &ct).unwrap();
        assert_eq!(oaep_decode(alg::SHA256, &pt, b"IDENTITY\0").unwrap(), msg);
    }
}
