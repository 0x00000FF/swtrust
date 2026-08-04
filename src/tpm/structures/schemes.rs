//! Algorithm scheme structures from Part 2 clause 11.
//!
//! Every scheme is a tagged union: a TPM_ALG_ID selector followed by the
//! details that selector calls for. TPM_ALG_NULL always selects an empty
//! detail, so a null scheme marshals as just the two selector octets.

use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::base::{digest_size, Tpm2bEccParameter};

/// TPMS_SCHEME_HASH, Part 2 Table 173.
///
/// Used directly by most schemes and aliased as TPMS_SCHEME_HMAC,
/// TPMS_SIG_SCHEME_RSASSA and the other single field scheme structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchemeHash {
    pub hash_alg: u16,
}

impl SchemeHash {
    pub fn new(hash_alg: u16) -> SchemeHash {
        SchemeHash { hash_alg }
    }
}

impl Marshal for SchemeHash {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash_alg);
    }
}

impl Unmarshal for SchemeHash {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash_alg = r.u16()?;
        if digest_size(hash_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        Ok(SchemeHash { hash_alg })
    }
}

/// True when a signing scheme is anonymous.
///
/// Part 2 clause 11.2.1.4 gives TPMI_ALG_ANONYMOUS_SIGNING as the schemes that
/// hide the identity of the signer, which is ECDAA. Part 3 clause 19.2.1
/// requires TPM2_Commit to be given a key with one of them.
pub fn is_anonymous(scheme: u16) -> bool {
    matches!(scheme, crate::tpm::constants::alg::ECDAA)
}

/// TPMS_SCHEME_ECDAA, Part 2 Table 174.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchemeEcdaa {
    pub hash_alg: u16,
    pub count: u16,
}

impl Marshal for SchemeEcdaa {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash_alg);
        w.u16(self.count);
    }
}

impl Unmarshal for SchemeEcdaa {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash_alg = r.u16()?;
        if digest_size(hash_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        let count = r.u16()?;
        Ok(SchemeEcdaa { hash_alg, count })
    }
}

/// TPMS_SCHEME_XOR, Part 2 Table 177.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchemeXor {
    pub hash_alg: u16,
    pub kdf: u16,
}

impl Marshal for SchemeXor {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash_alg);
        w.u16(self.kdf);
    }
}

impl Unmarshal for SchemeXor {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash_alg = r.u16()?;
        if digest_size(hash_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        let kdf = r.u16()?;
        if !is_kdf(kdf) {
            return Err(TpmRc(rc::KDF));
        }
        Ok(SchemeXor { hash_alg, kdf })
    }
}

/// True when `id` names a key derivation function this TPM implements.
///
/// Part 2 Table 82 lists TPM_ALG_HKDF beside the others, and the note under an
/// ECC key's kdf field says "currently, TPM_ALG_HKDF is the only supported KDF
/// for DHKEM", so a KEM key cannot be described without it.
pub fn is_kdf(id: u16) -> bool {
    matches!(
        id,
        alg::MGF1 | alg::KDF1_SP800_56A | alg::KDF2 | alg::KDF1_SP800_108 | alg::HKDF
    )
}

/// The details that follow a scheme selector.
///
/// The variant is determined by the selector, so the same enum serves every
/// scheme structure in Part 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeDetail {
    /// TPM_ALG_NULL, or a scheme such as TPM_ALG_RSAES that has no detail.
    Empty,
    /// A single hash algorithm.
    Hash(SchemeHash),
    /// A hash algorithm and a count, used by ECDAA.
    Ecdaa(SchemeEcdaa),
    /// A hash algorithm and a KDF, used by the XOR obfuscation scheme.
    Xor(SchemeXor),
}

impl SchemeDetail {
    /// The hash algorithm the detail carries, if any.
    pub fn hash_alg(&self) -> Option<u16> {
        match self {
            SchemeDetail::Empty => None,
            SchemeDetail::Hash(h) => Some(h.hash_alg),
            SchemeDetail::Ecdaa(e) => Some(e.hash_alg),
            SchemeDetail::Xor(x) => Some(x.hash_alg),
        }
    }
}

/// Which detail shape a scheme selector calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailKind {
    Empty,
    Hash,
    Ecdaa,
    Xor,
}

/// Selectors a TPMI_ALG_RSA_SCHEME accepts, Part 2 Table 189.
pub fn is_rsa_scheme(scheme: u16) -> bool {
    matches!(
        scheme,
        alg::RSASSA | alg::RSAPSS | alg::RSAES | alg::OAEP | alg::NULL
    )
}

/// Selectors a TPMI_ALG_RSA_DECRYPT accepts, Part 2 Table 192.
pub fn is_rsa_decrypt_scheme(scheme: u16) -> bool {
    matches!(scheme, alg::RSAES | alg::OAEP | alg::NULL)
}

/// Selectors a TPMI_ALG_ECC_SCHEME accepts, Part 2 Table 200.
pub fn is_ecc_scheme(scheme: u16) -> bool {
    matches!(
        scheme,
        alg::ECDSA | alg::ECDAA | alg::SM2 | alg::ECSCHNORR | alg::ECDH | alg::ECMQV | alg::NULL
    )
}

/// Selectors a TPMI_ALG_SIG_SCHEME accepts, Part 2 Table 83.
pub fn is_signature_scheme(scheme: u16) -> bool {
    matches!(
        scheme,
        alg::RSASSA
            | alg::RSAPSS
            | alg::ECDSA
            | alg::ECDAA
            | alg::SM2
            | alg::ECSCHNORR
            | alg::HMAC
            | alg::NULL
    )
}

/// The detail shape for any asymmetric or signature scheme selector.
///
/// Returns `None` when the selector names no scheme at all. Which selectors a
/// particular structure accepts is narrower and is enforced by the
/// `unmarshal_*` functions below.
pub fn asym_detail_kind(scheme: u16) -> Option<DetailKind> {
    Some(match scheme {
        alg::NULL => DetailKind::Empty,
        // RSAES carries no parameters, Part 2 Table 184.
        alg::RSAES => DetailKind::Empty,
        alg::RSASSA | alg::RSAPSS | alg::OAEP => DetailKind::Hash,
        alg::ECDSA | alg::ECSCHNORR | alg::SM2 => DetailKind::Hash,
        alg::ECDH | alg::ECMQV => DetailKind::Hash,
        alg::ECDAA => DetailKind::Ecdaa,
        alg::HMAC => DetailKind::Hash,
        _ => return None,
    })
}

/// Read the detail that follows `kind`.
fn read_detail(r: &mut Reader<'_>, kind: DetailKind) -> TpmResult<SchemeDetail> {
    Ok(match kind {
        DetailKind::Empty => SchemeDetail::Empty,
        DetailKind::Hash => SchemeDetail::Hash(SchemeHash::unmarshal(r)?),
        DetailKind::Ecdaa => SchemeDetail::Ecdaa(SchemeEcdaa::unmarshal(r)?),
        DetailKind::Xor => SchemeDetail::Xor(SchemeXor::unmarshal(r)?),
    })
}

fn write_detail(w: &mut Writer, detail: &SchemeDetail) {
    match detail {
        SchemeDetail::Empty => {}
        SchemeDetail::Hash(h) => h.marshal(w),
        SchemeDetail::Ecdaa(e) => e.marshal(w),
        SchemeDetail::Xor(x) => x.marshal(w),
    }
}

/// A scheme selector with its detail.
///
/// This one type stands in for TPMT_SIG_SCHEME, TPMT_RSA_SCHEME,
/// TPMT_RSA_DECRYPT, TPMT_ECC_SCHEME, TPMT_ASYM_SCHEME and
/// TPMT_KEYEDHASH_SCHEME. The permitted selectors differ per use and are
/// checked by the command that reads the structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scheme {
    pub scheme: u16,
    pub detail: SchemeDetail,
}

impl Default for Scheme {
    fn default() -> Self {
        Scheme::null()
    }
}

impl Scheme {
    /// TPM_ALG_NULL with no detail.
    pub fn null() -> Scheme {
        Scheme {
            scheme: alg::NULL,
            detail: SchemeDetail::Empty,
        }
    }

    /// A scheme with a single hash parameter.
    /// A scheme that carries a hash and the commit counter ECDAA needs.
    pub fn ecdaa(hash_alg: u16, count: u16) -> Scheme {
        Scheme {
            scheme: crate::tpm::constants::alg::ECDAA,
            detail: SchemeDetail::Ecdaa(SchemeEcdaa { hash_alg, count }),
        }
    }

    pub fn hash(scheme: u16, hash_alg: u16) -> Scheme {
        Scheme {
            scheme,
            detail: SchemeDetail::Hash(SchemeHash { hash_alg }),
        }
    }

    /// True when the selector is TPM_ALG_NULL.
    pub fn is_null(&self) -> bool {
        self.scheme == alg::NULL
    }

    /// The hash algorithm the scheme uses, if it has one.
    pub fn hash_alg(&self) -> Option<u16> {
        self.detail.hash_alg()
    }

    /// Unmarshal a scheme whose selector must satisfy `accepts`.
    ///
    /// `code` is the response code the interface type calls for when the
    /// selector is not one it allows.
    fn unmarshal_checked(
        r: &mut Reader<'_>,
        accepts: fn(u16) -> bool,
        code: u32,
    ) -> TpmResult<Scheme> {
        let scheme = r.u16()?;
        if !accepts(scheme) {
            return Err(TpmRc(code));
        }
        let kind = asym_detail_kind(scheme).ok_or(TpmRc(code))?;
        Ok(Scheme {
            scheme,
            detail: read_detail(r, kind)?,
        })
    }

    /// Unmarshal a TPMT_RSA_SCHEME, Part 2 Table 191.
    ///
    /// Table 189 makes the selector a TPMI_ALG_RSA_SCHEME, whose error is
    /// TPM_RC_VALUE.
    pub fn unmarshal_rsa_scheme(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        Scheme::unmarshal_checked(r, is_rsa_scheme, rc::VALUE)
    }

    /// Unmarshal a TPMT_RSA_DECRYPT, Part 2 Table 193.
    pub fn unmarshal_rsa_decrypt(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        Scheme::unmarshal_checked(r, is_rsa_decrypt_scheme, rc::VALUE)
    }

    /// Unmarshal a TPMT_ECC_SCHEME, Part 2 Table 203.
    pub fn unmarshal_ecc_scheme(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        Scheme::unmarshal_checked(r, is_ecc_scheme, rc::SCHEME)
    }

    /// Unmarshal a TPMT_SIG_SCHEME, Part 2 Table 183.
    pub fn unmarshal_sig_scheme(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        Scheme::unmarshal_checked(r, is_signature_scheme, rc::SCHEME)
    }

    /// Unmarshal a TPMT_ASYM_SCHEME, which accepts every asymmetric selector.
    pub fn unmarshal_asym(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        Scheme::unmarshal_checked(r, |s| asym_detail_kind(s).is_some(), rc::SCHEME)
    }

    /// Unmarshal a TPMT_KEYEDHASH_SCHEME, Part 2 Table 179.
    pub fn unmarshal_keyedhash(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        let scheme = r.u16()?;
        let kind = match scheme {
            alg::NULL => DetailKind::Empty,
            alg::HMAC => DetailKind::Hash,
            alg::XOR => DetailKind::Xor,
            _ => return Err(TpmRc(rc::SCHEME)),
        };
        Ok(Scheme {
            scheme,
            detail: read_detail(r, kind)?,
        })
    }

    /// Unmarshal a TPMT_KDF_SCHEME, Part 2 Table 188.
    pub fn unmarshal_kdf(r: &mut Reader<'_>) -> TpmResult<Scheme> {
        let scheme = r.u16()?;
        let kind = if scheme == alg::NULL {
            DetailKind::Empty
        } else if is_kdf(scheme) {
            DetailKind::Hash
        } else {
            return Err(TpmRc(rc::KDF));
        };
        Ok(Scheme {
            scheme,
            detail: read_detail(r, kind)?,
        })
    }
}

impl Marshal for Scheme {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.scheme);
        write_detail(w, &self.detail);
    }
}

/// TPMT_SYM_DEF and TPMT_SYM_DEF_OBJECT, Part 2 Tables 162 and 163.
///
/// `algorithm` selects both `key_bits` and `mode`: TPM_ALG_NULL has neither,
/// TPM_ALG_XOR has a hash algorithm in place of a key size and no mode, and a
/// block cipher has both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymDef {
    pub algorithm: u16,
    /// A key size in bits, or a TPMI_ALG_HASH when `algorithm` is TPM_ALG_XOR.
    pub key_bits: u16,
    pub mode: u16,
}

impl Default for SymDef {
    fn default() -> Self {
        SymDef::null()
    }
}

impl SymDef {
    /// TPM_ALG_NULL with no key size and no mode.
    pub fn null() -> SymDef {
        SymDef {
            algorithm: alg::NULL,
            key_bits: 0,
            mode: 0,
        }
    }

    /// A block cipher definition.
    pub fn new(algorithm: u16, key_bits: u16, mode: u16) -> SymDef {
        SymDef {
            algorithm,
            key_bits,
            mode,
        }
    }

    /// True when the selector is TPM_ALG_NULL.
    pub fn is_null(&self) -> bool {
        self.algorithm == alg::NULL
    }

    /// True when `id` names a symmetric block cipher this TPM implements.
    ///
    /// Part 2 Table 80 also lists TDES, SM4 and Camellia. Only the algorithms
    /// this TPM actually offers are accepted, so a template naming another one
    /// is refused when it is unmarshalled rather than later.
    pub fn is_block_cipher(id: u16) -> bool {
        id == alg::AES
    }

    /// True when `id` names a block cipher mode, Part 2 Table 81.
    pub fn is_mode(id: u16) -> bool {
        matches!(id, alg::CTR | alg::OFB | alg::CBC | alg::CFB | alg::ECB)
    }

    /// True when `key_bits` is a size Part 2 Table 158 allows for `algorithm`.
    pub fn is_key_size(algorithm: u16, key_bits: u16) -> bool {
        match algorithm {
            alg::AES => crate::tpm::config::IMPLEMENTED_AES_KEY_BITS.contains(&key_bits),
            _ => false,
        }
    }

    /// Unmarshal a TPMT_SYM_DEF, which may select TPM_ALG_XOR.
    pub fn unmarshal_sym_def(r: &mut Reader<'_>) -> TpmResult<SymDef> {
        let algorithm = r.u16()?;
        if algorithm == alg::NULL {
            return Ok(SymDef::null());
        }
        if algorithm == alg::XOR {
            let key_bits = r.u16()?;
            if digest_size(key_bits).is_none() {
                return Err(TpmRc(rc::HASH));
            }
            return Ok(SymDef {
                algorithm,
                key_bits,
                mode: alg::NULL,
            });
        }
        if !SymDef::is_block_cipher(algorithm) {
            return Err(TpmRc(rc::SYMMETRIC));
        }
        let key_bits = r.u16()?;
        // Table 158 makes the key size an interface type whose error is
        // TPM_RC_VALUE.
        if !SymDef::is_key_size(algorithm, key_bits) {
            return Err(TpmRc(rc::VALUE));
        }
        let mode = r.u16()?;
        if !SymDef::is_mode(mode) {
            return Err(TpmRc(rc::MODE));
        }
        Ok(SymDef {
            algorithm,
            key_bits,
            mode,
        })
    }

    /// Unmarshal a TPMT_SYM_DEF_OBJECT, which may not select TPM_ALG_XOR.
    pub fn unmarshal_sym_def_object(r: &mut Reader<'_>) -> TpmResult<SymDef> {
        let def = SymDef::unmarshal_sym_def(r)?;
        if def.algorithm == alg::XOR {
            return Err(TpmRc(rc::SYMMETRIC));
        }
        Ok(def)
    }
}

impl Marshal for SymDef {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.algorithm);
        if self.algorithm == alg::NULL {
            return;
        }
        w.u16(self.key_bits);
        if self.algorithm != alg::XOR {
            w.u16(self.mode);
        }
    }
}

/// TPMS_ECC_POINT, Part 2 Table 198.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

impl EccPoint {
    /// The point at infinity, encoded as two empty parameters.
    pub fn empty() -> EccPoint {
        EccPoint::default()
    }

    /// True when both coordinates are empty.
    pub fn is_empty(&self) -> bool {
        self.x.is_empty() && self.y.is_empty()
    }
}

impl Marshal for EccPoint {
    fn marshal(&self, w: &mut Writer) {
        self.x.marshal(w);
        self.y.marshal(w);
    }
}

impl Unmarshal for EccPoint {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(EccPoint {
            x: Tpm2bEccParameter::unmarshal(r)?,
            y: Tpm2bEccParameter::unmarshal(r)?,
        })
    }
}

/// TPM2B_ECC_POINT, Part 2 Table 199.
///
/// The size field covers the marshalled TPMS_ECC_POINT, not a raw buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tpm2bEccPoint {
    pub point: EccPoint,
}

impl Marshal for Tpm2bEccPoint {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.point.marshal(w));
    }
}

impl Unmarshal for Tpm2bEccPoint {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let point = EccPoint::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bEccPoint { point })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_asym(bytes: &[u8]) -> TpmResult<Scheme> {
        let mut r = Reader::new(bytes);
        let s = Scheme::unmarshal_asym(&mut r)?;
        assert!(r.is_empty(), "trailing octets");
        Ok(s)
    }

    #[test]
    fn null_scheme_is_two_octets() {
        let s = Scheme::null();
        assert_eq!(s.to_bytes(), vec![0x00, 0x10]);
        assert_eq!(parse_asym(&[0x00, 0x10]).unwrap(), s);
    }

    #[test]
    fn hash_scheme_round_trip() {
        let s = Scheme::hash(alg::RSASSA, alg::SHA256);
        assert_eq!(s.to_bytes(), vec![0x00, 0x14, 0x00, 0x0b]);
        assert_eq!(parse_asym(&s.to_bytes()).unwrap(), s);
        assert_eq!(s.hash_alg(), Some(alg::SHA256));
    }

    #[test]
    fn rsaes_has_no_detail() {
        let s = Scheme {
            scheme: alg::RSAES,
            detail: SchemeDetail::Empty,
        };
        assert_eq!(s.to_bytes(), vec![0x00, 0x15]);
        assert_eq!(parse_asym(&[0x00, 0x15]).unwrap(), s);
        assert_eq!(s.hash_alg(), None);
    }

    #[test]
    fn ecdaa_carries_a_count() {
        let s = Scheme {
            scheme: alg::ECDAA,
            detail: SchemeDetail::Ecdaa(SchemeEcdaa {
                hash_alg: alg::SHA256,
                count: 7,
            }),
        };
        assert_eq!(s.to_bytes(), vec![0x00, 0x1a, 0x00, 0x0b, 0x00, 0x07]);
        assert_eq!(parse_asym(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn unknown_scheme_selector_is_rejected() {
        assert_eq!(parse_asym(&[0x00, 0x01]).unwrap_err(), TpmRc(rc::SCHEME));
    }

    #[test]
    fn scheme_hash_must_name_a_hash() {
        // TPM_ALG_RSASSA followed by TPM_ALG_RSA is not a hash.
        assert_eq!(
            parse_asym(&[0x00, 0x14, 0x00, 0x01]).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }

    #[test]
    fn keyedhash_scheme_selectors() {
        let mut r = Reader::new(&[0x00, 0x05, 0x00, 0x0b]);
        let s = Scheme::unmarshal_keyedhash(&mut r).unwrap();
        assert_eq!(s.scheme, alg::HMAC);
        assert_eq!(s.hash_alg(), Some(alg::SHA256));

        let raw = [0x00u8, 0x0a, 0x00, 0x0b, 0x00, 0x07];
        let mut r = Reader::new(&raw);
        let s = Scheme::unmarshal_keyedhash(&mut r).unwrap();
        assert_eq!(s.scheme, alg::XOR);
        assert_eq!(s.detail, SchemeDetail::Xor(SchemeXor { hash_alg: alg::SHA256, kdf: alg::MGF1 }));
        assert_eq!(s.to_bytes(), raw);

        let mut r = Reader::new(&[0x00, 0x10]);
        assert!(Scheme::unmarshal_keyedhash(&mut r).unwrap().is_null());

        // A signature scheme is not a keyedhash scheme.
        let mut r = Reader::new(&[0x00, 0x14, 0x00, 0x0b]);
        assert_eq!(
            Scheme::unmarshal_keyedhash(&mut r).unwrap_err(),
            TpmRc(rc::SCHEME)
        );
    }

    #[test]
    fn kdf_scheme_selectors() {
        let mut r = Reader::new(&[0x00, 0x20, 0x00, 0x0b]);
        let s = Scheme::unmarshal_kdf(&mut r).unwrap();
        assert_eq!(s.scheme, alg::KDF1_SP800_56A);
        assert_eq!(s.hash_alg(), Some(alg::SHA256));

        let mut r = Reader::new(&[0x00, 0x10]);
        assert!(Scheme::unmarshal_kdf(&mut r).unwrap().is_null());

        let mut r = Reader::new(&[0x00, 0x14, 0x00, 0x0b]);
        assert_eq!(Scheme::unmarshal_kdf(&mut r).unwrap_err(), TpmRc(rc::KDF));
    }

    #[test]
    fn sym_def_null_is_two_octets() {
        let d = SymDef::null();
        assert_eq!(d.to_bytes(), vec![0x00, 0x10]);
        let mut r = Reader::new(&[0x00, 0x10]);
        assert_eq!(SymDef::unmarshal_sym_def(&mut r).unwrap(), d);
    }

    #[test]
    fn sym_def_block_cipher_has_bits_and_mode() {
        let d = SymDef::new(alg::AES, 128, alg::CFB);
        let bytes = d.to_bytes();
        assert_eq!(bytes, vec![0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
        let mut r = Reader::new(&bytes);
        assert_eq!(SymDef::unmarshal_sym_def(&mut r).unwrap(), d);
    }

    #[test]
    fn sym_def_xor_has_a_hash_and_no_mode() {
        let d = SymDef {
            algorithm: alg::XOR,
            key_bits: alg::SHA256,
            mode: alg::NULL,
        };
        assert_eq!(d.to_bytes(), vec![0x00, 0x0a, 0x00, 0x0b]);
        let mut r = Reader::new(&[0x00, 0x0a, 0x00, 0x0b]);
        assert_eq!(SymDef::unmarshal_sym_def(&mut r).unwrap(), d);
        // A sym def object may not select XOR.
        let mut r = Reader::new(&[0x00, 0x0a, 0x00, 0x0b]);
        assert_eq!(
            SymDef::unmarshal_sym_def_object(&mut r).unwrap_err(),
            TpmRc(rc::SYMMETRIC)
        );
    }

    #[test]
    fn sym_def_rejects_bad_algorithm_and_mode() {
        let mut r = Reader::new(&[0x00, 0x01, 0x00, 0x80, 0x00, 0x43]);
        assert_eq!(
            SymDef::unmarshal_sym_def(&mut r).unwrap_err(),
            TpmRc(rc::SYMMETRIC)
        );
        let mut r = Reader::new(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x01]);
        assert_eq!(
            SymDef::unmarshal_sym_def(&mut r).unwrap_err(),
            TpmRc(rc::MODE)
        );
    }

    #[test]
    fn ecc_point_round_trip() {
        let p = EccPoint {
            x: Tpm2bEccParameter::from_slice(&[1, 2, 3]).unwrap(),
            y: Tpm2bEccParameter::from_slice(&[4, 5]).unwrap(),
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes, vec![0x00, 0x03, 1, 2, 3, 0x00, 0x02, 4, 5]);
        assert_eq!(EccPoint::from_bytes(&bytes).unwrap(), p);

        let wrapped = Tpm2bEccPoint { point: p };
        let bytes = wrapped.to_bytes();
        assert_eq!(&bytes[0..2], &9u16.to_be_bytes());
        assert_eq!(Tpm2bEccPoint::from_bytes(&bytes).unwrap(), wrapped);
    }

    #[test]
    fn tpm2b_ecc_point_size_must_match_the_body() {
        // The size says eight octets but the body is nine.
        let raw = [0x00u8, 0x08, 0x00, 0x03, 1, 2, 3, 0x00, 0x02, 4, 5];
        assert!(Tpm2bEccPoint::from_bytes(&raw).is_err());
    }
}
