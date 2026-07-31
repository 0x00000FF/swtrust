//! Elliptic curve cryptography over prime fields.
//!
//! Part 1 clause 11.2.5 defines what the TPM needs from ECC: key generation
//! that can be repeated from a seed, ECDH point multiplication, ECDSA, EC
//! Schnorr and ECDAA. The curve arithmetic comes from the aws-lc-sys EC
//! interface so the TPM keeps control of scalar selection and octet layout.

use std::ptr;

use aws_lc_sys::{
    EC_GROUP_free, EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get_curve_GFp,
    EC_GROUP_get_degree, EC_GROUP_new_by_curve_name, EC_POINT_add, EC_POINT_free,
    EC_POINT_get_affine_coordinates, EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_mul,
    EC_POINT_new, EC_POINT_set_affine_coordinates_GFp, EC_GROUP, EC_POINT,
    NID_X9_62_prime256v1, NID_secp224r1, NID_secp384r1, NID_secp521r1,
};

use crate::tpm::constants::{curve, rc};
use crate::tpm::error::{TpmRc, TpmResult};

use super::bn::{BigNum, BnCtx};
use super::hash::digest_size;
use super::rand::Rng;

fn failure() -> TpmRc {
    TpmRc(rc::FAILURE)
}

/// The OpenSSL curve identifier for a TPM_ECC_CURVE.
///
/// NIST P-192 is not offered: aws-lc does not build the group, and Part 2
/// leaves the curve set to the implementation.
fn curve_nid(curve_id: u16) -> TpmResult<i32> {
    Ok(match curve_id {
        curve::NIST_P224 => NID_secp224r1,
        curve::NIST_P256 => NID_X9_62_prime256v1,
        curve::NIST_P384 => NID_secp384r1,
        curve::NIST_P521 => NID_secp521r1,
        _ => return Err(TpmRc(rc::CURVE)),
    })
}

/// True when the TPM implements `curve_id`.
pub fn is_supported(curve_id: u16) -> bool {
    curve_nid(curve_id).is_ok()
}

/// An owned curve group.
pub struct Curve {
    group: *mut EC_GROUP,
    curve_id: u16,
}

unsafe impl Send for Curve {}

impl Curve {
    /// Load the group for a TPM_ECC_CURVE.
    pub fn new(curve_id: u16) -> TpmResult<Curve> {
        let nid = curve_nid(curve_id)?;
        let group = unsafe { EC_GROUP_new_by_curve_name(nid) };
        if group.is_null() {
            return Err(TpmRc(rc::CURVE));
        }
        Ok(Curve { group, curve_id })
    }

    /// The TPM_ECC_CURVE this group was built from.
    pub fn curve_id(&self) -> u16 {
        self.curve_id
    }

    /// Number of bits in the field, which fixes the coordinate size.
    pub fn bits(&self) -> usize {
        unsafe { EC_GROUP_get_degree(self.group) as usize }
    }

    /// Number of octets in one coordinate, rounded up.
    pub fn coordinate_size(&self) -> usize {
        (self.bits() + 7) / 8
    }

    /// The group order.
    pub fn order(&self) -> TpmResult<BigNum> {
        let ptr = unsafe { EC_GROUP_get0_order(self.group) };
        if ptr.is_null() {
            return Err(failure());
        }
        let mut out = BigNum::new()?;
        if unsafe { aws_lc_sys::BN_copy(out.as_mut_ptr(), ptr) }.is_null() {
            return Err(failure());
        }
        Ok(out)
    }

    /// The curve parameters `(p, a, b)`.
    pub fn parameters(&self) -> TpmResult<(BigNum, BigNum, BigNum)> {
        let ctx = BnCtx::new()?;
        let mut p = BigNum::new()?;
        let mut a = BigNum::new()?;
        let mut b = BigNum::new()?;
        let ok = unsafe {
            EC_GROUP_get_curve_GFp(
                self.group,
                p.as_mut_ptr(),
                a.as_mut_ptr(),
                b.as_mut_ptr(),
                ctx.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(failure());
        }
        Ok((p, a, b))
    }

    /// The generator point.
    pub fn generator(&self) -> TpmResult<Point> {
        let g = unsafe { EC_GROUP_get0_generator(self.group) };
        if g.is_null() {
            return Err(failure());
        }
        let point = Point::new(self)?;
        if unsafe { aws_lc_sys::EC_POINT_copy(point.point, g) } != 1 {
            return Err(failure());
        }
        Ok(point)
    }

    /// The generator coordinates as octets.
    pub fn generator_coordinates(&self) -> TpmResult<(Vec<u8>, Vec<u8>)> {
        self.generator()?.coordinates(self)
    }
}

impl Drop for Curve {
    fn drop(&mut self) {
        unsafe { EC_GROUP_free(self.group) };
    }
}

impl std::fmt::Debug for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Curve({:#06x}, {} bits)", self.curve_id, self.bits())
    }
}

/// A point on a curve.
pub struct Point {
    point: *mut EC_POINT,
}

unsafe impl Send for Point {}

impl Point {
    /// A new point, initially at infinity.
    pub fn new(curve: &Curve) -> TpmResult<Point> {
        let point = unsafe { EC_POINT_new(curve.group) };
        if point.is_null() {
            return Err(failure());
        }
        Ok(Point { point })
    }

    /// Build from affine coordinates, checking that the point is on the curve.
    pub fn from_coordinates(curve: &Curve, x: &[u8], y: &[u8]) -> TpmResult<Point> {
        let ctx = BnCtx::new()?;
        let bx = BigNum::from_bytes(x)?;
        let by = BigNum::from_bytes(y)?;
        let point = Point::new(curve)?;
        let ok = unsafe {
            EC_POINT_set_affine_coordinates_GFp(
                curve.group,
                point.point,
                bx.as_ptr(),
                by.as_ptr(),
                ctx.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(TpmRc(rc::ECC_POINT));
        }
        if !point.is_on_curve(curve)? {
            return Err(TpmRc(rc::ECC_POINT));
        }
        Ok(point)
    }

    /// True when the point satisfies the curve equation.
    pub fn is_on_curve(&self, curve: &Curve) -> TpmResult<bool> {
        let ctx = BnCtx::new()?;
        let r = unsafe { EC_POINT_is_on_curve(curve.group, self.point, ctx.as_ptr()) };
        if r < 0 {
            return Err(failure());
        }
        Ok(r == 1)
    }

    /// True when the point is the identity.
    pub fn is_at_infinity(&self, curve: &Curve) -> bool {
        unsafe { EC_POINT_is_at_infinity(curve.group, self.point) == 1 }
    }

    /// The affine coordinates, each padded to the coordinate size.
    pub fn coordinates(&self, curve: &Curve) -> TpmResult<(Vec<u8>, Vec<u8>)> {
        if self.is_at_infinity(curve) {
            return Err(TpmRc(rc::NO_RESULT));
        }
        let ctx = BnCtx::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let ok = unsafe {
            EC_POINT_get_affine_coordinates(
                curve.group,
                self.point,
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                ctx.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(failure());
        }
        let size = curve.coordinate_size();
        Ok((x.to_bytes_padded(size)?, y.to_bytes_padded(size)?))
    }

    /// `scalar * self`.
    pub fn multiply(&self, curve: &Curve, scalar: &BigNum) -> TpmResult<Point> {
        let ctx = BnCtx::new()?;
        let out = Point::new(curve)?;
        let ok = unsafe {
            EC_POINT_mul(
                curve.group,
                out.point,
                ptr::null(),
                self.point,
                scalar.as_ptr(),
                ctx.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    /// `self + other`.
    pub fn add(&self, curve: &Curve, other: &Point) -> TpmResult<Point> {
        let ctx = BnCtx::new()?;
        let out = Point::new(curve)?;
        let ok = unsafe {
            EC_POINT_add(curve.group, out.point, self.point, other.point, ctx.as_ptr())
        };
        if ok != 1 {
            return Err(failure());
        }
        Ok(out)
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        unsafe { EC_POINT_free(self.point) };
    }
}

impl std::fmt::Debug for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The coordinates need the curve to read, which is not held here, so
        // only the identity of the point is shown.
        write!(f, "Point({:p})", self.point)
    }
}

/// `scalar * G` on `curve`.
pub fn multiply_generator(curve: &Curve, scalar: &BigNum) -> TpmResult<Point> {
    let ctx = BnCtx::new()?;
    let out = Point::new(curve)?;
    let ok = unsafe {
        EC_POINT_mul(
            curve.group,
            out.point,
            scalar.as_ptr(),
            ptr::null(),
            ptr::null(),
            ctx.as_ptr(),
        )
    };
    if ok != 1 {
        return Err(failure());
    }
    Ok(out)
}

/// An ECC key pair.
pub struct EccKey {
    pub curve: Curve,
    pub private: BigNum,
    pub public_x: Vec<u8>,
    pub public_y: Vec<u8>,
}

/// Draw a private scalar in `[1, order-1]` from `rng`.
///
/// FIPS 186-5 appendix A.4.2 calls this testing candidates: an octet string of
/// the order's length is drawn and rejected when it is zero or not below the
/// order. Rejection keeps the distribution uniform, and with a deterministic
/// generator it stays reproducible.
pub fn private_key_from_rng(curve: &Curve, rng: &mut dyn Rng) -> TpmResult<BigNum> {
    let order = curve.order()?;
    let size = curve.coordinate_size();
    let extra_bits = size * 8 - order.bits();
    for _ in 0..1000 {
        let mut bytes = rng.bytes(size)?;
        // Clear the bits above the order width so the rejection rate stays low
        // for curves such as P-521 whose order is not a whole octet count.
        if extra_bits > 0 {
            bytes[0] &= 0xffu8 >> extra_bits;
        }
        let candidate = BigNum::from_bytes(&bytes)?;
        if candidate.is_zero() || candidate.cmp(&order) >= 0 {
            continue;
        }
        return Ok(candidate);
    }
    Err(TpmRc(rc::NO_RESULT))
}

/// Generate a key pair, taking every octet from `rng`.
pub fn generate(curve_id: u16, rng: &mut dyn Rng) -> TpmResult<EccKey> {
    let curve = Curve::new(curve_id)?;
    let private = private_key_from_rng(&curve, rng)?;
    let point = multiply_generator(&curve, &private)?;
    let (public_x, public_y) = point.coordinates(&curve)?;
    let key = EccKey {
        curve,
        private,
        public_x,
        public_y,
    };
    // FIPS 140-3 Table 40 asks for a pair-wise consistency test on every
    // generated key pair. Doing it here rather than at the call sites means an
    // ephemeral pair gets one too, and a new caller cannot leave it out.
    crate::tpm::fips::pairwise_generated_ecc(&key)?;
    Ok(key)
}

/// The ECDH shared point `d * Q`, as required by TPM2_ECDH_ZGen.
pub fn ecdh(curve: &Curve, private: &BigNum, peer_x: &[u8], peer_y: &[u8]) -> TpmResult<(Vec<u8>, Vec<u8>)> {
    let peer = Point::from_coordinates(curve, peer_x, peer_y)?;
    let shared = peer.multiply(curve, private)?;
    if shared.is_at_infinity(curve) {
        return Err(TpmRc(rc::NO_RESULT));
    }
    shared.coordinates(curve)
}

/// Truncate a digest to the order width, as ECDSA requires.
///
/// FIPS 186-5 section 6.4.1 takes the leftmost `min(N, outlen)` bits of the
/// digest, where N is the bit length of the order.
pub fn digest_to_scalar(curve: &Curve, digest: &[u8]) -> TpmResult<BigNum> {
    let order = curve.order()?;
    let order_bits = order.bits();
    // Keep the leftmost min(N, outlen) bits. When the order is not a whole
    // number of octets, as on P-521, the extra low bits of the last octet
    // taken are shifted away.
    let keep_bits = order_bits.min(digest.len() * 8);
    let take = (keep_bits + 7) / 8;
    let mut value = BigNum::from_bytes(&digest[..take])?;
    let extra = take * 8 - keep_bits;
    if extra > 0 {
        value = value.shift_right(extra)?;
    }
    Ok(value)
}

/// An ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccSignature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

/// Sign `digest` with ECDSA, drawing the per message secret from `rng`.
pub fn ecdsa_sign(
    curve: &Curve,
    private: &BigNum,
    digest: &[u8],
    rng: &mut dyn Rng,
) -> TpmResult<EccSignature> {
    let ctx = BnCtx::new()?;
    let order = curve.order()?;
    let e = digest_to_scalar(curve, digest)?;
    let size = curve.coordinate_size();

    for _ in 0..1000 {
        let k = private_key_from_rng(curve, rng)?;
        let point = multiply_generator(curve, &k)?;
        if point.is_at_infinity(curve) {
            continue;
        }
        let (x, _) = point.coordinates(curve)?;
        let r = BigNum::from_bytes(&x)?.modulo(&order, &ctx)?;
        if r.is_zero() {
            continue;
        }
        // s = k^-1 (e + r * d) mod n
        let k_inv = k.mod_inverse(&order, &ctx)?;
        let rd = r.mul(private, &ctx)?.modulo(&order, &ctx)?;
        let sum = e.add(&rd)?.modulo(&order, &ctx)?;
        let s = k_inv.mul(&sum, &ctx)?.modulo(&order, &ctx)?;
        if s.is_zero() {
            continue;
        }
        return Ok(EccSignature {
            r: r.to_bytes_padded(size)?,
            s: s.to_bytes_padded(size)?,
        });
    }
    Err(TpmRc(rc::NO_RESULT))
}

/// Verify an ECDSA signature.
pub fn ecdsa_verify(
    curve: &Curve,
    public_x: &[u8],
    public_y: &[u8],
    digest: &[u8],
    sig: &EccSignature,
) -> TpmResult<()> {
    let ctx = BnCtx::new()?;
    let order = curve.order()?;
    let r = BigNum::from_bytes(&sig.r)?;
    let s = BigNum::from_bytes(&sig.s)?;
    if r.is_zero() || s.is_zero() || r.cmp(&order) >= 0 || s.cmp(&order) >= 0 {
        return Err(TpmRc(rc::SIGNATURE));
    }
    let e = digest_to_scalar(curve, digest)?;
    let s_inv = s.mod_inverse(&order, &ctx)?;
    let u1 = e.mul(&s_inv, &ctx)?.modulo(&order, &ctx)?;
    let u2 = r.mul(&s_inv, &ctx)?.modulo(&order, &ctx)?;

    let public = Point::from_coordinates(curve, public_x, public_y)?;
    let p1 = multiply_generator(curve, &u1)?;
    let p2 = public.multiply(curve, &u2)?;
    let sum = p1.add(curve, &p2)?;
    if sum.is_at_infinity(curve) {
        return Err(TpmRc(rc::SIGNATURE));
    }
    let (x, _) = sum.coordinates(curve)?;
    let v = BigNum::from_bytes(&x)?.modulo(&order, &ctx)?;
    if v.cmp(&r) != 0 {
        return Err(TpmRc(rc::SIGNATURE));
    }
    Ok(())
}

/// Sign with EC Schnorr, Part 1 clause C.5.
///
/// The commitment is `k * G`, `r` is `H(x_coordinate || digest)` reduced modulo
/// the order, and `s = k + r * d mod n`.
pub fn ecschnorr_sign(
    curve: &Curve,
    private: &BigNum,
    hash_alg: u16,
    digest: &[u8],
    rng: &mut dyn Rng,
) -> TpmResult<EccSignature> {
    let ctx = BnCtx::new()?;
    let order = curve.order()?;
    let size = curve.coordinate_size();
    let _ = digest_size(hash_alg)?;

    for _ in 0..1000 {
        let k = private_key_from_rng(curve, rng)?;
        let point = multiply_generator(curve, &k)?;
        if point.is_at_infinity(curve) {
            continue;
        }
        let (x, _) = point.coordinates(curve)?;
        let e = super::hash::digest_parts(hash_alg, &[&x, digest])?;
        let r = BigNum::from_bytes(&e)?.modulo(&order, &ctx)?;
        if r.is_zero() {
            continue;
        }
        let rd = r.mul(private, &ctx)?.modulo(&order, &ctx)?;
        let s = k.add(&rd)?.modulo(&order, &ctx)?;
        if s.is_zero() {
            continue;
        }
        return Ok(EccSignature {
            r: r.to_bytes_padded(size)?,
            s: s.to_bytes_padded(size)?,
        });
    }
    Err(TpmRc(rc::NO_RESULT))
}

/// Verify an EC Schnorr signature.
pub fn ecschnorr_verify(
    curve: &Curve,
    public_x: &[u8],
    public_y: &[u8],
    hash_alg: u16,
    digest: &[u8],
    sig: &EccSignature,
) -> TpmResult<()> {
    let ctx = BnCtx::new()?;
    let order = curve.order()?;
    let r = BigNum::from_bytes(&sig.r)?;
    let s = BigNum::from_bytes(&sig.s)?;
    if r.is_zero() || s.is_zero() || r.cmp(&order) >= 0 || s.cmp(&order) >= 0 {
        return Err(TpmRc(rc::SIGNATURE));
    }
    // Recover the commitment: s * G - r * Q.
    let public = Point::from_coordinates(curve, public_x, public_y)?;
    let neg_r = order.sub(&r)?;
    let p1 = multiply_generator(curve, &s)?;
    let p2 = public.multiply(curve, &neg_r)?;
    let sum = p1.add(curve, &p2)?;
    if sum.is_at_infinity(curve) {
        return Err(TpmRc(rc::SIGNATURE));
    }
    let (x, _) = sum.coordinates(curve)?;
    let e = super::hash::digest_parts(hash_alg, &[&x, digest])?;
    let check = BigNum::from_bytes(&e)?.modulo(&order, &ctx)?;
    if check.cmp(&r) != 0 {
        return Err(TpmRc(rc::SIGNATURE));
    }
    Ok(())
}

/// The ECDAA signature of Part 1 clause C.4.
///
/// The commitment point is chosen by TPM2_Commit rather than here, so this
/// takes the commitment scalar `k` and the digest and returns `(r, s)` where
/// `s = k + r * d mod n`. `r` is supplied by the caller as the hash of the
/// commitment and the message.
pub fn ecdaa_sign(
    curve: &Curve,
    private: &BigNum,
    commit_scalar: &BigNum,
    r_value: &[u8],
) -> TpmResult<EccSignature> {
    let ctx = BnCtx::new()?;
    let order = curve.order()?;
    let size = curve.coordinate_size();
    let r = BigNum::from_bytes(r_value)?.modulo(&order, &ctx)?;
    if r.is_zero() {
        return Err(TpmRc(rc::VALUE));
    }
    let rd = r.mul(private, &ctx)?.modulo(&order, &ctx)?;
    let s = commit_scalar.add(&rd)?.modulo(&order, &ctx)?;
    if s.is_zero() {
        return Err(TpmRc(rc::NO_RESULT));
    }
    Ok(EccSignature {
        r: r.to_bytes_padded(size)?,
        s: s.to_bytes_padded(size)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;
    use crate::tpm::crypto::rand::{Drbg, SeededRng};

    fn rng() -> Drbg {
        Drbg::new(&[0x3cu8; 48], b"ecc").unwrap()
    }

    const CURVES: &[u16] = &[
        curve::NIST_P224,
        curve::NIST_P256,
        curve::NIST_P384,
        curve::NIST_P521,
    ];

    #[test]
    fn supported_curves_load_with_the_expected_sizes() {
        let sizes = [
            (curve::NIST_P224, 28),
            (curve::NIST_P256, 32),
            (curve::NIST_P384, 48),
            (curve::NIST_P521, 66),
        ];
        for (id, size) in sizes {
            let c = Curve::new(id).unwrap();
            assert_eq!(c.coordinate_size(), size, "curve {id:#06x}");
            assert_eq!(c.curve_id(), id);
            assert!(is_supported(id));
        }
        for id in [curve::NIST_P192, curve::BN_P256, curve::SM2_P256, curve::CURVE_25519] {
            assert!(!is_supported(id));
            assert_eq!(Curve::new(id).unwrap_err(), TpmRc(rc::CURVE));
        }
    }

    #[test]
    fn p256_parameters_match_the_standard() {
        let c = Curve::new(curve::NIST_P256).unwrap();
        let (p, a, b) = c.parameters().unwrap();
        assert_eq!(
            crate::util::hex::encode(&p.to_bytes().unwrap()),
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        );
        assert_eq!(
            crate::util::hex::encode(&a.to_bytes().unwrap()),
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
        );
        assert_eq!(
            crate::util::hex::encode(&b.to_bytes().unwrap()),
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
        );
        assert_eq!(
            crate::util::hex::encode(&c.order().unwrap().to_bytes().unwrap()),
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
        );
        let (gx, gy) = c.generator_coordinates().unwrap();
        assert_eq!(
            crate::util::hex::encode(&gx),
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        );
        assert_eq!(
            crate::util::hex::encode(&gy),
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
    }

    #[test]
    fn generated_keys_are_on_the_curve() {
        let mut r = rng();
        for id in CURVES {
            let key = generate(*id, &mut r).unwrap();
            let size = key.curve.coordinate_size();
            assert_eq!(key.public_x.len(), size);
            assert_eq!(key.public_y.len(), size);
            let p = Point::from_coordinates(&key.curve, &key.public_x, &key.public_y).unwrap();
            assert!(p.is_on_curve(&key.curve).unwrap());
            assert!(!p.is_at_infinity(&key.curve));
            // The private scalar is in range.
            let order = key.curve.order().unwrap();
            assert!(!key.private.is_zero());
            assert!(key.private.cmp(&order) < 0);
        }
    }

    #[test]
    fn generation_is_deterministic_for_a_seed() {
        let mut a = SeededRng::new(alg::SHA256, &[3u8; 32], "ECC", b"ctx");
        let mut b = SeededRng::new(alg::SHA256, &[3u8; 32], "ECC", b"ctx");
        let ka = generate(curve::NIST_P256, &mut a).unwrap();
        let kb = generate(curve::NIST_P256, &mut b).unwrap();
        assert_eq!(ka.public_x, kb.public_x);
        assert_eq!(ka.public_y, kb.public_y);
    }

    #[test]
    fn a_point_off_the_curve_is_rejected() {
        let c = Curve::new(curve::NIST_P256).unwrap();
        let (gx, mut gy) = c.generator_coordinates().unwrap();
        gy[31] ^= 0x01;
        assert_eq!(
            Point::from_coordinates(&c, &gx, &gy).unwrap_err(),
            TpmRc(rc::ECC_POINT)
        );
    }

    #[test]
    fn scalar_multiplication_agrees_with_repeated_addition() {
        let c = Curve::new(curve::NIST_P256).unwrap();
        let g = c.generator().unwrap();
        let two = BigNum::from_u64(2).unwrap();
        let three = BigNum::from_u64(3).unwrap();
        let g2 = multiply_generator(&c, &two).unwrap();
        let g3 = multiply_generator(&c, &three).unwrap();
        let sum = g2.add(&c, &g).unwrap();
        assert_eq!(sum.coordinates(&c).unwrap(), g3.coordinates(&c).unwrap());
    }

    #[test]
    fn ecdh_agrees_in_both_directions() {
        let mut r = rng();
        for id in CURVES {
            let a = generate(*id, &mut r).unwrap();
            let b = generate(*id, &mut r).unwrap();
            let za = ecdh(&a.curve, &a.private, &b.public_x, &b.public_y).unwrap();
            let zb = ecdh(&b.curve, &b.private, &a.public_x, &a.public_y).unwrap();
            assert_eq!(za, zb, "curve {id:#06x}");
            assert_eq!(za.0.len(), a.curve.coordinate_size());
        }
    }

    #[test]
    fn ecdh_rejects_a_bad_peer_point() {
        let mut r = rng();
        let a = generate(curve::NIST_P256, &mut r).unwrap();
        let mut y = a.public_y.clone();
        y[0] ^= 0xff;
        assert_eq!(
            ecdh(&a.curve, &a.private, &a.public_x, &y).unwrap_err(),
            TpmRc(rc::ECC_POINT)
        );
    }

    #[test]
    fn ecdsa_round_trip_on_every_curve() {
        let mut r = rng();
        for id in CURVES {
            let key = generate(*id, &mut r).unwrap();
            let d = super::super::hash::digest(alg::SHA256, b"message").unwrap();
            let sig = ecdsa_sign(&key.curve, &key.private, &d, &mut r).unwrap();
            assert_eq!(sig.r.len(), key.curve.coordinate_size());
            ecdsa_verify(&key.curve, &key.public_x, &key.public_y, &d, &sig).unwrap();
        }
    }

    #[test]
    fn ecdsa_rejects_a_changed_message_or_signature() {
        let mut r = rng();
        let key = generate(curve::NIST_P256, &mut r).unwrap();
        let d = super::super::hash::digest(alg::SHA256, b"message").unwrap();
        let other = super::super::hash::digest(alg::SHA256, b"other").unwrap();
        let sig = ecdsa_sign(&key.curve, &key.private, &d, &mut r).unwrap();

        assert!(ecdsa_verify(&key.curve, &key.public_x, &key.public_y, &other, &sig).is_err());

        let mut bad = sig.clone();
        bad.s[31] ^= 0x01;
        assert!(ecdsa_verify(&key.curve, &key.public_x, &key.public_y, &d, &bad).is_err());

        // A zero component is refused outright.
        let zero = EccSignature {
            r: vec![0u8; 32],
            s: sig.s.clone(),
        };
        assert_eq!(
            ecdsa_verify(&key.curve, &key.public_x, &key.public_y, &d, &zero).unwrap_err(),
            TpmRc(rc::SIGNATURE)
        );
    }

    #[test]
    fn ecdsa_verifies_a_signature_from_another_key_as_invalid() {
        let mut r = rng();
        let a = generate(curve::NIST_P256, &mut r).unwrap();
        let b = generate(curve::NIST_P256, &mut r).unwrap();
        let d = super::super::hash::digest(alg::SHA256, b"m").unwrap();
        let sig = ecdsa_sign(&a.curve, &a.private, &d, &mut r).unwrap();
        assert!(ecdsa_verify(&b.curve, &b.public_x, &b.public_y, &d, &sig).is_err());
    }

    #[test]
    fn digest_truncation_follows_the_order_width() {
        // P-256 has a 256 bit order, so a SHA-384 digest is truncated.
        let c = Curve::new(curve::NIST_P256).unwrap();
        let d = vec![0xffu8; 48];
        let e = digest_to_scalar(&c, &d).unwrap();
        assert_eq!(e.bits(), 256);
        assert_eq!(e.to_bytes().unwrap(), vec![0xffu8; 32]);

        // P-521 has a 521 bit order, so a 64 octet digest keeps all its bits.
        let c = Curve::new(curve::NIST_P521).unwrap();
        let e = digest_to_scalar(&c, &vec![0xffu8; 64]).unwrap();
        assert_eq!(e.bits(), 512);
    }

    #[test]
    fn ecschnorr_round_trip() {
        let mut r = rng();
        for id in [curve::NIST_P256, curve::NIST_P384] {
            let key = generate(id, &mut r).unwrap();
            let d = super::super::hash::digest(alg::SHA256, b"schnorr message").unwrap();
            let sig = ecschnorr_sign(&key.curve, &key.private, alg::SHA256, &d, &mut r).unwrap();
            ecschnorr_verify(
                &key.curve,
                &key.public_x,
                &key.public_y,
                alg::SHA256,
                &d,
                &sig,
            )
            .unwrap();
        }
    }

    #[test]
    fn ecschnorr_rejects_a_changed_message() {
        let mut r = rng();
        let key = generate(curve::NIST_P256, &mut r).unwrap();
        let d = super::super::hash::digest(alg::SHA256, b"a").unwrap();
        let other = super::super::hash::digest(alg::SHA256, b"b").unwrap();
        let sig = ecschnorr_sign(&key.curve, &key.private, alg::SHA256, &d, &mut r).unwrap();
        assert!(ecschnorr_verify(
            &key.curve,
            &key.public_x,
            &key.public_y,
            alg::SHA256,
            &other,
            &sig
        )
        .is_err());
    }

    #[test]
    fn ecdaa_produces_s_from_the_commitment() {
        let mut r = rng();
        let key = generate(curve::NIST_P256, &mut r).unwrap();
        let ctx = BnCtx::new().unwrap();
        let order = key.curve.order().unwrap();
        let k = private_key_from_rng(&key.curve, &mut r).unwrap();
        let r_value = vec![0x11u8; 32];
        let sig = ecdaa_sign(&key.curve, &key.private, &k, &r_value).unwrap();

        // s must satisfy s = k + r * d mod n.
        let r_bn = BigNum::from_bytes(&sig.r).unwrap();
        let rd = r_bn.mul(&key.private, &ctx).unwrap().modulo(&order, &ctx).unwrap();
        let expected = k.add(&rd).unwrap().modulo(&order, &ctx).unwrap();
        assert_eq!(sig.s, expected.to_bytes_padded(32).unwrap());
    }

    #[test]
    fn ecdaa_rejects_a_zero_r() {
        let mut r = rng();
        let key = generate(curve::NIST_P256, &mut r).unwrap();
        let k = private_key_from_rng(&key.curve, &mut r).unwrap();
        assert_eq!(
            ecdaa_sign(&key.curve, &key.private, &k, &[0u8; 32]).unwrap_err(),
            TpmRc(rc::VALUE)
        );
    }
}
