//! Public and sensitive areas from Part 2 clause 12.

use crate::tpm::config;
use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::ObjectAttributes;
use crate::tpm::structures::base::{
    digest_size, Tpm2bDigest, Tpm2bEccParameter, Tpm2bLabel, Tpm2bPrivateKeyRsa,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
};
use crate::tpm::structures::schemes::{EccPoint, Scheme, SymDef};

/// True when `id` is a TPMI_ALG_PUBLIC, Part 2 Table 225.
pub fn is_public_type(id: u16) -> bool {
    matches!(
        id,
        alg::KEYEDHASH | alg::SYMCIPHER | alg::RSA | alg::ECC
    )
}

/// TPMS_DERIVE, Part 2 Table 167.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Derive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

impl Marshal for Derive {
    fn marshal(&self, w: &mut Writer) {
        self.label.marshal(w);
        self.context.marshal(w);
    }
}

impl Unmarshal for Derive {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(Derive {
            label: Tpm2bLabel::unmarshal(r)?,
            context: Tpm2bLabel::unmarshal(r)?,
        })
    }
}

/// TPMU_PUBLIC_PARMS, Part 2 Table 233.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicParms {
    /// TPMS_KEYEDHASH_PARMS, Part 2 Table 227.
    KeyedHash { scheme: Scheme },
    /// TPMS_SYMCIPHER_PARMS, Part 2 Table 165.
    SymCipher { sym: SymDef },
    /// TPMS_RSA_PARMS, Part 2 Table 228.
    Rsa {
        symmetric: SymDef,
        scheme: Scheme,
        key_bits: u16,
        exponent: u32,
    },
    /// TPMS_ECC_PARMS, Part 2 Table 229.
    Ecc {
        symmetric: SymDef,
        scheme: Scheme,
        curve_id: u16,
        kdf: Scheme,
    },
}

impl PublicParms {
    /// The TPMI_ALG_PUBLIC that selects this variant.
    pub fn selector(&self) -> u16 {
        match self {
            PublicParms::KeyedHash { .. } => alg::KEYEDHASH,
            PublicParms::SymCipher { .. } => alg::SYMCIPHER,
            PublicParms::Rsa { .. } => alg::RSA,
            PublicParms::Ecc { .. } => alg::ECC,
        }
    }

    /// The signing or key exchange scheme, when the type has one.
    pub fn scheme(&self) -> Option<&Scheme> {
        match self {
            PublicParms::KeyedHash { scheme } => Some(scheme),
            PublicParms::SymCipher { .. } => None,
            PublicParms::Rsa { scheme, .. } => Some(scheme),
            PublicParms::Ecc { scheme, .. } => Some(scheme),
        }
    }

    /// The symmetric definition used to protect children, when the type has one.
    pub fn symmetric(&self) -> Option<&SymDef> {
        match self {
            PublicParms::KeyedHash { .. } => None,
            PublicParms::SymCipher { sym } => Some(sym),
            PublicParms::Rsa { symmetric, .. } => Some(symmetric),
            PublicParms::Ecc { symmetric, .. } => Some(symmetric),
        }
    }

    /// Unmarshal the variant selected by `selector`.
    pub fn unmarshal_with(r: &mut Reader<'_>, selector: u16) -> TpmResult<PublicParms> {
        Ok(match selector {
            alg::KEYEDHASH => PublicParms::KeyedHash {
                scheme: Scheme::unmarshal_keyedhash(r)?,
            },
            alg::SYMCIPHER => PublicParms::SymCipher {
                sym: SymDef::unmarshal_sym_def_object(r)?,
            },
            alg::RSA => {
                let symmetric = SymDef::unmarshal_sym_def_object(r)?;
                let scheme = Scheme::unmarshal_rsa_scheme(r)?;
                let key_bits = r.u16()?;
                // Table 195 makes keyBits a TPMI_RSA_KEY_BITS, whose error is
                // TPM_RC_VALUE.
                if !config::IMPLEMENTED_RSA_KEY_BITS.contains(&key_bits) {
                    return Err(TpmRc(rc::VALUE));
                }
                let exponent = r.u32()?;
                PublicParms::Rsa {
                    symmetric,
                    scheme,
                    key_bits,
                    exponent,
                }
            }
            alg::ECC => {
                let symmetric = SymDef::unmarshal_sym_def_object(r)?;
                let scheme = Scheme::unmarshal_ecc_scheme(r)?;
                let curve_id = r.u16()?;
                // Table 201 makes curveID a TPMI_ECC_CURVE, whose error is
                // TPM_RC_CURVE.
                if !config::IMPLEMENTED_CURVES.contains(&curve_id) {
                    return Err(TpmRc(rc::CURVE));
                }
                let kdf = Scheme::unmarshal_kdf(r)?;
                PublicParms::Ecc {
                    symmetric,
                    scheme,
                    curve_id,
                    kdf,
                }
            }
            _ => return Err(TpmRc(rc::TYPE)),
        })
    }
}

impl Marshal for PublicParms {
    fn marshal(&self, w: &mut Writer) {
        match self {
            PublicParms::KeyedHash { scheme } => scheme.marshal(w),
            PublicParms::SymCipher { sym } => sym.marshal(w),
            PublicParms::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            } => {
                symmetric.marshal(w);
                scheme.marshal(w);
                w.u16(*key_bits);
                w.u32(*exponent);
            }
            PublicParms::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            } => {
                symmetric.marshal(w);
                scheme.marshal(w);
                w.u16(*curve_id);
                kdf.marshal(w);
            }
        }
    }
}

/// TPMT_PUBLIC_PARMS, Part 2 Table 234.
///
/// A TPMI_ALG_PUBLIC followed by the parameters it selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicParmsTagged {
    pub parms: PublicParms,
}

impl Marshal for PublicParmsTagged {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.parms.selector());
        self.parms.marshal(w);
    }
}

impl Unmarshal for PublicParmsTagged {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let selector = r.u16()?;
        Ok(PublicParmsTagged {
            parms: PublicParms::unmarshal_with(r, selector)?,
        })
    }
}

/// TPMU_PUBLIC_ID, Part 2 Table 226.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicId {
    /// The digest that identifies a keyed hash object.
    KeyedHash(Tpm2bDigest),
    /// The digest that identifies a symmetric cipher object.
    Sym(Tpm2bDigest),
    /// An RSA public modulus.
    Rsa(Tpm2bPublicKeyRsa),
    /// An ECC public point.
    Ecc(EccPoint),
    /// Derivation values, used only by TPM2_CreateLoaded with a derivation
    /// parent.
    Derive(Derive),
}

impl PublicId {
    /// Unmarshal the variant selected by `selector`.
    pub fn unmarshal_with(r: &mut Reader<'_>, selector: u16) -> TpmResult<PublicId> {
        Ok(match selector {
            alg::KEYEDHASH => PublicId::KeyedHash(Tpm2bDigest::unmarshal(r)?),
            alg::SYMCIPHER => PublicId::Sym(Tpm2bDigest::unmarshal(r)?),
            alg::RSA => PublicId::Rsa(Tpm2bPublicKeyRsa::unmarshal(r)?),
            alg::ECC => PublicId::Ecc(EccPoint::unmarshal(r)?),
            _ => return Err(TpmRc(rc::TYPE)),
        })
    }

    /// An empty identifier for `selector`, used when a template leaves `unique`
    /// out.
    pub fn empty_for(selector: u16) -> TpmResult<PublicId> {
        Ok(match selector {
            alg::KEYEDHASH => PublicId::KeyedHash(Tpm2bDigest::empty()),
            alg::SYMCIPHER => PublicId::Sym(Tpm2bDigest::empty()),
            alg::RSA => PublicId::Rsa(Tpm2bPublicKeyRsa::empty()),
            alg::ECC => PublicId::Ecc(EccPoint::empty()),
            _ => return Err(TpmRc(rc::TYPE)),
        })
    }

    /// True when the identifier carries no data.
    pub fn is_empty(&self) -> bool {
        match self {
            PublicId::KeyedHash(d) | PublicId::Sym(d) => d.is_empty(),
            PublicId::Rsa(m) => m.is_empty(),
            PublicId::Ecc(p) => p.is_empty(),
            PublicId::Derive(_) => false,
        }
    }
}

impl Marshal for PublicId {
    fn marshal(&self, w: &mut Writer) {
        match self {
            PublicId::KeyedHash(d) | PublicId::Sym(d) => d.marshal(w),
            PublicId::Rsa(m) => m.marshal(w),
            PublicId::Ecc(p) => p.marshal(w),
            PublicId::Derive(d) => d.marshal(w),
        }
    }
}

/// TPMT_PUBLIC, Part 2 Table 235.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmtPublic {
    pub object_type: u16,
    pub name_alg: u16,
    pub object_attributes: ObjectAttributes,
    pub auth_policy: Tpm2bDigest,
    pub parameters: PublicParms,
    pub unique: PublicId,
}

impl TpmtPublic {
    /// Unmarshal a public area.
    ///
    /// `allow_derive` is set only when reading the template of
    /// TPM2_CreateLoaded with a derivation parent, where `unique` holds a
    /// TPMS_DERIVE instead of an object identifier.
    pub fn unmarshal_with(r: &mut Reader<'_>, allow_derive: bool) -> TpmResult<TpmtPublic> {
        let object_type = r.u16()?;
        if !is_public_type(object_type) {
            return Err(TpmRc(rc::TYPE));
        }
        let name_alg = r.u16()?;
        if name_alg != alg::NULL && digest_size(name_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        let object_attributes = ObjectAttributes::unmarshal(r)?;
        let auth_policy = Tpm2bDigest::unmarshal(r)?;
        let parameters = PublicParms::unmarshal_with(r, object_type)?;
        let unique = if allow_derive {
            PublicId::Derive(Derive::unmarshal(r)?)
        } else {
            PublicId::unmarshal_with(r, object_type)?
        };
        Ok(TpmtPublic {
            object_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        })
    }

    /// The scheme of the object, if its type has one.
    pub fn scheme(&self) -> Option<&Scheme> {
        self.parameters.scheme()
    }

    /// True when the object is an asymmetric key.
    pub fn is_asymmetric(&self) -> bool {
        matches!(self.object_type, alg::RSA | alg::ECC)
    }

    /// True when the object may be a parent of other objects.
    ///
    /// Part 1 clause 25.2 calls a restricted decryption key a Storage Key.
    pub fn is_parent(&self) -> bool {
        self.object_attributes
            .has(ObjectAttributes::RESTRICTED | ObjectAttributes::DECRYPT)
    }
}

impl Marshal for TpmtPublic {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.object_type);
        w.u16(self.name_alg);
        self.object_attributes.marshal(w);
        self.auth_policy.marshal(w);
        self.parameters.marshal(w);
        self.unique.marshal(w);
    }
}

impl Unmarshal for TpmtPublic {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        TpmtPublic::unmarshal_with(r, false)
    }
}

/// TPM2B_PUBLIC, Part 2 Table 236.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2bPublic {
    pub public_area: TpmtPublic,
}

impl Marshal for Tpm2bPublic {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.public_area.marshal(w));
    }
}

impl Unmarshal for Tpm2bPublic {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let public_area = TpmtPublic::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bPublic { public_area })
    }
}

/// TPMU_SENSITIVE_COMPOSITE, Part 2 Table 239.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitiveComposite {
    /// One RSA prime.
    Rsa(Tpm2bPrivateKeyRsa),
    /// An ECC private scalar.
    Ecc(Tpm2bEccParameter),
    /// The data of a keyed hash object.
    Bits(Tpm2bSensitiveData),
    /// A symmetric key.
    Sym(Tpm2bSymKey),
}

impl SensitiveComposite {
    /// The TPMI_ALG_PUBLIC that selects this variant.
    pub fn selector(&self) -> u16 {
        match self {
            SensitiveComposite::Rsa(_) => alg::RSA,
            SensitiveComposite::Ecc(_) => alg::ECC,
            SensitiveComposite::Bits(_) => alg::KEYEDHASH,
            SensitiveComposite::Sym(_) => alg::SYMCIPHER,
        }
    }

    /// The octets of the private value.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            SensitiveComposite::Rsa(v) => v.as_slice(),
            SensitiveComposite::Ecc(v) => v.as_slice(),
            SensitiveComposite::Bits(v) => v.as_slice(),
            SensitiveComposite::Sym(v) => v.as_slice(),
        }
    }

    /// Unmarshal the variant selected by `selector`.
    pub fn unmarshal_with(r: &mut Reader<'_>, selector: u16) -> TpmResult<SensitiveComposite> {
        Ok(match selector {
            alg::RSA => SensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::unmarshal(r)?),
            alg::ECC => SensitiveComposite::Ecc(Tpm2bEccParameter::unmarshal(r)?),
            alg::KEYEDHASH => SensitiveComposite::Bits(Tpm2bSensitiveData::unmarshal(r)?),
            alg::SYMCIPHER => SensitiveComposite::Sym(Tpm2bSymKey::unmarshal(r)?),
            _ => return Err(TpmRc(rc::TYPE)),
        })
    }
}

impl Marshal for SensitiveComposite {
    fn marshal(&self, w: &mut Writer) {
        match self {
            SensitiveComposite::Rsa(v) => v.marshal(w),
            SensitiveComposite::Ecc(v) => v.marshal(w),
            SensitiveComposite::Bits(v) => v.marshal(w),
            SensitiveComposite::Sym(v) => v.marshal(w),
        }
    }
}

/// TPMT_SENSITIVE, Part 2 Table 240.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmtSensitive {
    pub sensitive_type: u16,
    pub auth_value: Tpm2bDigest,
    pub seed_value: Tpm2bDigest,
    pub sensitive: SensitiveComposite,
}

impl Marshal for TpmtSensitive {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.sensitive_type);
        self.auth_value.marshal(w);
        self.seed_value.marshal(w);
        self.sensitive.marshal(w);
    }
}

impl Unmarshal for TpmtSensitive {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let sensitive_type = r.u16()?;
        if !is_public_type(sensitive_type) {
            return Err(TpmRc(rc::TYPE));
        }
        let auth_value = Tpm2bDigest::unmarshal(r)?;
        let seed_value = Tpm2bDigest::unmarshal(r)?;
        let sensitive = SensitiveComposite::unmarshal_with(r, sensitive_type)?;
        Ok(TpmtSensitive {
            sensitive_type,
            auth_value,
            seed_value,
            sensitive,
        })
    }
}

/// TPM2B_SENSITIVE, Part 2 Table 241.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2bSensitive {
    pub sensitive_area: TpmtSensitive,
}

impl Marshal for Tpm2bSensitive {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.sensitive_area.marshal(w));
    }
}

impl Unmarshal for Tpm2bSensitive {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let sensitive_area = TpmtSensitive::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bSensitive { sensitive_area })
    }
}

/// TPMS_SENSITIVE_CREATE, Part 2 Table 171.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SensitiveCreate {
    pub user_auth: Tpm2bDigest,
    pub data: Tpm2bSensitiveData,
}

impl Marshal for SensitiveCreate {
    fn marshal(&self, w: &mut Writer) {
        self.user_auth.marshal(w);
        self.data.marshal(w);
    }
}

impl Unmarshal for SensitiveCreate {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(SensitiveCreate {
            user_auth: Tpm2bDigest::unmarshal(r)?,
            data: Tpm2bSensitiveData::unmarshal(r)?,
        })
    }
}

/// TPM2B_SENSITIVE_CREATE, Part 2 Table 172.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tpm2bSensitiveCreate {
    pub sensitive: SensitiveCreate,
}

impl Marshal for Tpm2bSensitiveCreate {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.sensitive.marshal(w));
    }
}

impl Unmarshal for Tpm2bSensitiveCreate {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let sensitive = SensitiveCreate::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bSensitiveCreate { sensitive })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::structures::schemes::SchemeDetail;

    fn rsa_storage_public() -> TpmtPublic {
        TpmtPublic {
            object_type: alg::RSA,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::FIXED_TPM
                    | ObjectAttributes::FIXED_PARENT
                    | ObjectAttributes::SENSITIVE_DATA_ORIGIN
                    | ObjectAttributes::USER_WITH_AUTH
                    | ObjectAttributes::RESTRICTED
                    | ObjectAttributes::DECRYPT,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Rsa {
                symmetric: SymDef::new(alg::AES, 128, alg::CFB),
                scheme: Scheme::null(),
                key_bits: 2048,
                exponent: 0,
            },
            unique: PublicId::Rsa(Tpm2bPublicKeyRsa::from_slice(&[0xab; 256]).unwrap()),
        }
    }

    #[test]
    fn rsa_public_area_round_trip() {
        let p = rsa_storage_public();
        let bytes = p.to_bytes();
        // type, nameAlg, attributes, authPolicy size, symmetric, scheme,
        // keyBits, exponent, unique size, modulus
        assert_eq!(&bytes[0..2], &alg::RSA.to_be_bytes());
        assert_eq!(&bytes[2..4], &alg::SHA256.to_be_bytes());
        assert_eq!(TpmtPublic::from_bytes(&bytes).unwrap(), p);
        assert!(p.is_parent());
        assert!(p.is_asymmetric());
    }

    #[test]
    fn tpm2b_public_wraps_the_size() {
        let p = Tpm2bPublic {
            public_area: rsa_storage_public(),
        };
        let bytes = p.to_bytes();
        let inner_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(inner_len, bytes.len() - 2);
        assert_eq!(Tpm2bPublic::from_bytes(&bytes).unwrap(), p);
    }

    #[test]
    fn tpm2b_public_rejects_a_size_mismatch() {
        let p = Tpm2bPublic {
            public_area: rsa_storage_public(),
        };
        let mut bytes = p.to_bytes();
        let n = u16::from_be_bytes([bytes[0], bytes[1]]) - 1;
        bytes[0..2].copy_from_slice(&n.to_be_bytes());
        assert!(Tpm2bPublic::from_bytes(&bytes).is_err());
    }

    #[test]
    fn ecc_public_area_round_trip() {
        let p = TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::USER_WITH_AUTH,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                curve_id: crate::tpm::constants::curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(EccPoint {
                x: Tpm2bEccParameter::from_slice(&[1u8; 32]).unwrap(),
                y: Tpm2bEccParameter::from_slice(&[2u8; 32]).unwrap(),
            }),
        };
        let bytes = p.to_bytes();
        assert_eq!(TpmtPublic::from_bytes(&bytes).unwrap(), p);
    }

    #[test]
    fn keyedhash_public_area_round_trip() {
        let p = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::USER_WITH_AUTH),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme {
                    scheme: alg::HMAC,
                    detail: SchemeDetail::Hash(super::super::schemes::SchemeHash {
                        hash_alg: alg::SHA256,
                    }),
                },
            },
            unique: PublicId::KeyedHash(Tpm2bDigest::from_slice(&[9u8; 32]).unwrap()),
        };
        assert_eq!(TpmtPublic::from_bytes(&p.to_bytes()).unwrap(), p);
    }

    #[test]
    fn public_area_rejects_a_bad_type_or_name_algorithm() {
        let p = rsa_storage_public();
        let mut bytes = p.to_bytes();
        bytes[0..2].copy_from_slice(&alg::AES.to_be_bytes());
        assert_eq!(TpmtPublic::from_bytes(&bytes).unwrap_err(), TpmRc(rc::TYPE));

        let mut bytes = p.to_bytes();
        bytes[2..4].copy_from_slice(&alg::AES.to_be_bytes());
        assert_eq!(TpmtPublic::from_bytes(&bytes).unwrap_err(), TpmRc(rc::HASH));
    }

    #[test]
    fn public_area_allows_a_null_name_algorithm() {
        // Part 2 Table 235 marks nameAlg with a plus, so TPM_ALG_NULL is legal.
        let mut p = rsa_storage_public();
        p.name_alg = alg::NULL;
        assert_eq!(TpmtPublic::from_bytes(&p.to_bytes()).unwrap(), p);
    }

    #[test]
    fn sensitive_area_round_trip() {
        let s = TpmtSensitive {
            sensitive_type: alg::RSA,
            auth_value: Tpm2bDigest::from_slice(&[1, 2, 3]).unwrap(),
            seed_value: Tpm2bDigest::empty(),
            sensitive: SensitiveComposite::Rsa(
                Tpm2bPrivateKeyRsa::from_slice(&[0x77; 128]).unwrap(),
            ),
        };
        let bytes = s.to_bytes();
        assert_eq!(TpmtSensitive::from_bytes(&bytes).unwrap(), s);

        let wrapped = Tpm2bSensitive {
            sensitive_area: s,
        };
        assert_eq!(
            Tpm2bSensitive::from_bytes(&wrapped.to_bytes()).unwrap(),
            wrapped
        );
    }

    #[test]
    fn sensitive_composite_follows_the_type() {
        let raw = TpmtSensitive {
            sensitive_type: alg::SYMCIPHER,
            auth_value: Tpm2bDigest::empty(),
            seed_value: Tpm2bDigest::from_slice(&[5u8; 32]).unwrap(),
            sensitive: SensitiveComposite::Sym(Tpm2bSymKey::from_slice(&[3u8; 16]).unwrap()),
        };
        let bytes = raw.to_bytes();
        let back = TpmtSensitive::from_bytes(&bytes).unwrap();
        assert_eq!(back.sensitive.selector(), alg::SYMCIPHER);
        assert_eq!(back.sensitive.as_slice(), &[3u8; 16]);
    }

    #[test]
    fn derivation_template_reads_a_derive_value() {
        let p = TpmtPublic {
            object_type: alg::KEYEDHASH,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(ObjectAttributes::USER_WITH_AUTH),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::KeyedHash {
                scheme: Scheme::null(),
            },
            unique: PublicId::Derive(Derive {
                label: Tpm2bLabel::from_slice(b"label").unwrap(),
                context: Tpm2bLabel::from_slice(b"ctx").unwrap(),
            }),
        };
        let bytes = p.to_bytes();
        let mut r = Reader::new(&bytes);
        let back = TpmtPublic::unmarshal_with(&mut r, true).unwrap();
        assert_eq!(back, p);
        assert!(r.is_empty());
    }

    #[test]
    fn sensitive_create_round_trip() {
        let s = Tpm2bSensitiveCreate {
            sensitive: SensitiveCreate {
                user_auth: Tpm2bDigest::from_slice(b"pw").unwrap(),
                data: Tpm2bSensitiveData::from_slice(b"secret").unwrap(),
            },
        };
        let bytes = s.to_bytes();
        assert_eq!(&bytes[0..2], &12u16.to_be_bytes());
        assert_eq!(Tpm2bSensitiveCreate::from_bytes(&bytes).unwrap(), s);
    }
}
