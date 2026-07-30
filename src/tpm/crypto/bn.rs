//! A safe wrapper over the aws-lc-sys big number interface.
//!
//! RSA key generation from a seed, the raw RSA primitives and the ECC point
//! arithmetic all need arbitrary precision integers with explicit control over
//! the octet layout. The higher level aws-lc-rs interface does not expose that,
//! so the BIGNUM functions are wrapped here with ownership and error handling
//! rather than being called from several places.

use std::os::raw::c_int;
use std::ptr;

use aws_lc_sys::{
    BN_add, BN_add_word, BN_bin2bn, BN_bn2bin_padded, BN_cmp, BN_copy, BN_CTX_free, BN_CTX_new,
    BN_div, BN_free, BN_gcd, BN_is_odd, BN_is_one, BN_is_zero, BN_lshift, BN_mod_exp,
    BN_mod_inverse, BN_mul, BN_new, BN_nnmod, BN_num_bits, BN_num_bytes, BN_primality_test,
    BN_rshift, BN_set_bit, BN_set_word, BN_sub, BN_sub_word, BIGNUM, BN_CTX,
};

use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};

fn failure() -> TpmRc {
    TpmRc(rc::FAILURE)
}

/// An owned big number context, needed by the arithmetic routines.
pub struct BnCtx {
    ptr: *mut BN_CTX,
}

impl BnCtx {
    pub fn new() -> TpmResult<BnCtx> {
        let ptr = unsafe { BN_CTX_new() };
        if ptr.is_null() {
            return Err(failure());
        }
        Ok(BnCtx { ptr })
    }

    /// The raw context pointer, which stays valid while `self` is alive.
    pub(crate) fn as_ptr(&self) -> *mut BN_CTX {
        self.ptr
    }
}

impl Drop for BnCtx {
    fn drop(&mut self) {
        unsafe { BN_CTX_free(self.ptr) };
    }
}

/// An owned big number.
pub struct BigNum {
    ptr: *mut BIGNUM,
}

// The pointer is uniquely owned and the library routines take it explicitly, so
// the value can move between threads.
unsafe impl Send for BigNum {}

impl BigNum {
    /// A new value set to zero.
    pub fn new() -> TpmResult<BigNum> {
        let ptr = unsafe { BN_new() };
        if ptr.is_null() {
            return Err(failure());
        }
        Ok(BigNum { ptr })
    }

    /// Build from a big endian octet string.
    pub fn from_bytes(bytes: &[u8]) -> TpmResult<BigNum> {
        let ptr = unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut()) };
        if ptr.is_null() {
            return Err(failure());
        }
        Ok(BigNum { ptr })
    }

    /// Build from a small unsigned value.
    pub fn from_u64(v: u64) -> TpmResult<BigNum> {
        let n = BigNum::new()?;
        if unsafe { BN_set_word(n.ptr, v) } != 1 {
            return Err(failure());
        }
        Ok(n)
    }

    pub(crate) fn as_ptr(&self) -> *const BIGNUM {
        self.ptr
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut BIGNUM {
        self.ptr
    }

    /// Build from a raw pointer that this value takes ownership of.
    ///
    /// # Safety
    /// `ptr` must be a live BIGNUM that nothing else frees.
    pub(crate) unsafe fn from_raw(ptr: *mut BIGNUM) -> TpmResult<BigNum> {
        if ptr.is_null() {
            return Err(failure());
        }
        Ok(BigNum { ptr })
    }

    /// Number of significant bits.
    pub fn bits(&self) -> usize {
        unsafe { BN_num_bits(self.ptr) as usize }
    }

    /// Number of octets needed to hold the value.
    pub fn bytes_len(&self) -> usize {
        unsafe { BN_num_bytes(self.ptr) as usize }
    }

    /// Big endian octets with no leading zeros.
    pub fn to_bytes(&self) -> TpmResult<Vec<u8>> {
        self.to_bytes_padded(self.bytes_len())
    }

    /// Big endian octets in exactly `len` octets, zero padded on the left.
    ///
    /// Fails with TPM_RC_SIZE when the value does not fit, which is what the
    /// TPM reports for an out of range key parameter.
    pub fn to_bytes_padded(&self, len: usize) -> TpmResult<Vec<u8>> {
        if self.bytes_len() > len {
            return Err(TpmRc(rc::SIZE));
        }
        let mut out = vec![0u8; len];
        if len == 0 {
            return Ok(out);
        }
        if unsafe { BN_bn2bin_padded(out.as_mut_ptr(), len, self.ptr) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn is_zero(&self) -> bool {
        unsafe { BN_is_zero(self.ptr) == 1 }
    }

    pub fn is_one(&self) -> bool {
        unsafe { BN_is_one(self.ptr) == 1 }
    }

    pub fn is_odd(&self) -> bool {
        unsafe { BN_is_odd(self.ptr) == 1 }
    }

    /// Compare with another value: negative, zero or positive.
    pub fn cmp(&self, other: &BigNum) -> i32 {
        unsafe { BN_cmp(self.ptr, other.ptr) as i32 }
    }

    /// A copy of this value.
    ///
    /// BN_copy returns the destination pointer, so a null result is the only
    /// failure signal.
    pub fn duplicate(&self) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_copy(out.ptr, self.ptr) }.is_null() {
            return Err(failure());
        }
        Ok(out)
    }

    /// Set bit `n`, counting from the least significant bit.
    pub fn set_bit(&mut self, n: usize) -> TpmResult<()> {
        if unsafe { BN_set_bit(self.ptr, n as c_int) } != 1 {
            return Err(failure());
        }
        Ok(())
    }

    pub fn add(&self, other: &BigNum) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_add(out.ptr, self.ptr, other.ptr) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn sub(&self, other: &BigNum) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_sub(out.ptr, self.ptr, other.ptr) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn add_word(&self, w: u64) -> TpmResult<BigNum> {
        let out = self.duplicate()?;
        if unsafe { BN_add_word(out.ptr, w) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn sub_word(&self, w: u64) -> TpmResult<BigNum> {
        let out = self.duplicate()?;
        if unsafe { BN_sub_word(out.ptr, w) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn mul(&self, other: &BigNum, ctx: &BnCtx) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_mul(out.ptr, self.ptr, other.ptr, ctx.as_ptr()) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    /// Quotient and remainder of `self / divisor`.
    pub fn div_rem(&self, divisor: &BigNum, ctx: &BnCtx) -> TpmResult<(BigNum, BigNum)> {
        if divisor.is_zero() {
            return Err(TpmRc(rc::VALUE));
        }
        let q = BigNum::new()?;
        let r = BigNum::new()?;
        if unsafe { BN_div(q.ptr, r.ptr, self.ptr, divisor.ptr, ctx.as_ptr()) } != 1 {
            return Err(failure());
        }
        Ok((q, r))
    }

    /// `self mod m`, always non-negative.
    pub fn modulo(&self, m: &BigNum, ctx: &BnCtx) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_nnmod(out.ptr, self.ptr, m.ptr, ctx.as_ptr()) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    /// `self ^ exponent mod m`.
    pub fn mod_exp(&self, exponent: &BigNum, m: &BigNum, ctx: &BnCtx) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_mod_exp(out.ptr, self.ptr, exponent.ptr, m.ptr, ctx.as_ptr()) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    /// The inverse of `self` modulo `m`, or TPM_RC_NO_RESULT when there is none.
    pub fn mod_inverse(&self, m: &BigNum, ctx: &BnCtx) -> TpmResult<BigNum> {
        let ptr = unsafe { BN_mod_inverse(ptr::null_mut(), self.ptr, m.ptr, ctx.as_ptr()) };
        if ptr.is_null() {
            return Err(TpmRc(rc::NO_RESULT));
        }
        unsafe { BigNum::from_raw(ptr) }
    }

    pub fn gcd(&self, other: &BigNum, ctx: &BnCtx) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_gcd(out.ptr, self.ptr, other.ptr, ctx.as_ptr()) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn shift_left(&self, n: usize) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_lshift(out.ptr, self.ptr, n as c_int) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    pub fn shift_right(&self, n: usize) -> TpmResult<BigNum> {
        let out = BigNum::new()?;
        if unsafe { BN_rshift(out.ptr, self.ptr, n as c_int) } != 1 {
            return Err(failure());
        }
        Ok(out)
    }

    /// Miller-Rabin primality test with `checks` rounds and trial division.
    pub fn is_probably_prime(&self, checks: u32, ctx: &BnCtx) -> TpmResult<bool> {
        let mut result: c_int = 0;
        let ok = unsafe {
            BN_primality_test(
                &mut result,
                self.ptr,
                checks as c_int,
                ctx.as_ptr(),
                1,
                ptr::null_mut(),
            )
        };
        if ok != 1 {
            return Err(failure());
        }
        Ok(result == 1)
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        unsafe { BN_free(self.ptr) };
    }
}

impl std::fmt::Debug for BigNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_bytes() {
            Ok(b) => write!(f, "BigNum({})", crate::util::hex::encode(&b)),
            Err(_) => write!(f, "BigNum(?)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_round_trip_is_big_endian() {
        let n = BigNum::from_bytes(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(n.to_bytes().unwrap(), vec![0x01, 0x02, 0x03]);
        assert_eq!(n.bits(), 17);
        assert_eq!(n.bytes_len(), 3);
        assert_eq!(
            n.to_bytes_padded(5).unwrap(),
            vec![0x00, 0x00, 0x01, 0x02, 0x03]
        );
        // Leading zeros in the input are not significant.
        let n = BigNum::from_bytes(&[0x00, 0x00, 0xff]).unwrap();
        assert_eq!(n.to_bytes().unwrap(), vec![0xff]);
    }

    #[test]
    fn padding_shorter_than_the_value_is_a_size_error() {
        let n = BigNum::from_bytes(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(n.to_bytes_padded(2).unwrap_err(), TpmRc(rc::SIZE));
    }

    #[test]
    fn zero_and_one_are_recognised() {
        let z = BigNum::from_u64(0).unwrap();
        assert!(z.is_zero());
        assert!(!z.is_odd());
        assert_eq!(z.to_bytes().unwrap(), Vec::<u8>::new());
        let o = BigNum::from_u64(1).unwrap();
        assert!(o.is_one());
        assert!(o.is_odd());
    }

    #[test]
    fn arithmetic() {
        let ctx = BnCtx::new().unwrap();
        let a = BigNum::from_u64(1000).unwrap();
        let b = BigNum::from_u64(7).unwrap();
        assert_eq!(a.add(&b).unwrap().to_bytes().unwrap(), vec![0x03, 0xef]);
        assert_eq!(a.sub(&b).unwrap().to_bytes().unwrap(), vec![0x03, 0xe1]);
        let m = a.mul(&b, &ctx).unwrap();
        assert_eq!(m.to_bytes().unwrap(), 7000u32.to_be_bytes()[2..].to_vec());
        let (q, r) = a.div_rem(&b, &ctx).unwrap();
        assert_eq!(q.to_bytes().unwrap(), vec![142]);
        assert_eq!(r.to_bytes().unwrap(), vec![6]);
        assert_eq!(a.add_word(1).unwrap().to_bytes().unwrap(), vec![0x03, 0xe9]);
        assert_eq!(a.sub_word(1).unwrap().to_bytes().unwrap(), vec![0x03, 0xe7]);
    }

    #[test]
    fn division_by_zero_is_a_value_error() {
        let ctx = BnCtx::new().unwrap();
        let a = BigNum::from_u64(10).unwrap();
        let z = BigNum::from_u64(0).unwrap();
        assert_eq!(a.div_rem(&z, &ctx).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn modular_arithmetic() {
        let ctx = BnCtx::new().unwrap();
        // 4^13 mod 497 = 445, a worked example from many texts.
        let base = BigNum::from_u64(4).unwrap();
        let exp = BigNum::from_u64(13).unwrap();
        let m = BigNum::from_u64(497).unwrap();
        // 445 is 0x01BD, so the result needs two octets.
        assert_eq!(
            base.mod_exp(&exp, &m, &ctx).unwrap().to_bytes().unwrap(),
            vec![0x01u8, 0xBD]
        );
        // 3 * 5 = 15 = 1 mod 7, so 3 inverse mod 7 is 5.
        let three = BigNum::from_u64(3).unwrap();
        let seven = BigNum::from_u64(7).unwrap();
        assert_eq!(
            three.mod_inverse(&seven, &ctx).unwrap().to_bytes().unwrap(),
            vec![5u8]
        );
        // An even number has no inverse modulo an even modulus.
        let four = BigNum::from_u64(4).unwrap();
        let eight = BigNum::from_u64(8).unwrap();
        assert_eq!(
            four.mod_inverse(&eight, &ctx).unwrap_err(),
            TpmRc(rc::NO_RESULT)
        );
    }

    #[test]
    fn gcd_and_shifts() {
        let ctx = BnCtx::new().unwrap();
        let a = BigNum::from_u64(48).unwrap();
        let b = BigNum::from_u64(18).unwrap();
        assert_eq!(a.gcd(&b, &ctx).unwrap().to_bytes().unwrap(), vec![6u8]);
        assert_eq!(a.shift_left(2).unwrap().to_bytes().unwrap(), vec![192u8]);
        assert_eq!(a.shift_right(4).unwrap().to_bytes().unwrap(), vec![3u8]);
    }

    #[test]
    fn set_bit_and_comparison() {
        let mut n = BigNum::from_u64(0).unwrap();
        n.set_bit(7).unwrap();
        assert_eq!(n.to_bytes().unwrap(), vec![0x80]);
        n.set_bit(0).unwrap();
        assert_eq!(n.to_bytes().unwrap(), vec![0x81]);
        let bigger = BigNum::from_u64(0x82).unwrap();
        assert!(n.cmp(&bigger) < 0);
        assert!(bigger.cmp(&n) > 0);
        assert_eq!(n.cmp(&n.duplicate().unwrap()), 0);
    }

    #[test]
    fn primality_of_known_values() {
        let ctx = BnCtx::new().unwrap();
        for p in [2u64, 3, 5, 7, 11, 13, 65537, 2147483647] {
            assert!(
                BigNum::from_u64(p).unwrap().is_probably_prime(64, &ctx).unwrap(),
                "{p} should be prime"
            );
        }
        for c in [1u64, 4, 9, 15, 65536, 1000000] {
            assert!(
                !BigNum::from_u64(c).unwrap().is_probably_prime(64, &ctx).unwrap(),
                "{c} should be composite"
            );
        }
    }

    #[test]
    fn large_values_survive_a_round_trip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let n = BigNum::from_bytes(&bytes).unwrap();
        // The leading zero octet is not significant.
        assert_eq!(n.to_bytes().unwrap(), bytes[1..].to_vec());
        assert_eq!(n.to_bytes_padded(256).unwrap(), bytes);
        // The top significant octet is 0x01, so only one of its bits counts.
        assert_eq!(n.bits(), 254 * 8 + 1);
        assert_eq!(n.bytes_len(), 255);
    }
}
