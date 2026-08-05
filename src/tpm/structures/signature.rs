//! Signature structures from Part 2 clause 11.3.

use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::base::{digest_size, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmtHa};

/// TPMS_SIGNATURE_RSA, Part 2 Table 212.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRsa {
    pub hash: u16,
    pub sig: Tpm2bPublicKeyRsa,
}

impl Marshal for SignatureRsa {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash);
        self.sig.marshal(w);
    }
}

impl Unmarshal for SignatureRsa {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash = r.u16()?;
        if digest_size(hash).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        Ok(SignatureRsa {
            hash,
            sig: Tpm2bPublicKeyRsa::unmarshal(r)?,
        })
    }
}

/// TPMS_SIGNATURE_ECC, Part 2 Table 214.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEcc {
    pub hash: u16,
    pub signature_r: Tpm2bEccParameter,
    pub signature_s: Tpm2bEccParameter,
}

impl Marshal for SignatureEcc {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash);
        self.signature_r.marshal(w);
        self.signature_s.marshal(w);
    }
}

impl Unmarshal for SignatureEcc {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash = r.u16()?;
        if digest_size(hash).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        Ok(SignatureEcc {
            hash,
            signature_r: Tpm2bEccParameter::unmarshal(r)?,
            signature_s: Tpm2bEccParameter::unmarshal(r)?,
        })
    }
}

/// TPMU_SIGNATURE, Part 2 Table 218.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureValue {
    /// An RSA signature, for TPM_ALG_RSASSA and TPM_ALG_RSAPSS.
    Rsa(SignatureRsa),
    /// An ECC signature, for TPM_ALG_ECDSA, TPM_ALG_ECDAA, TPM_ALG_SM2 and
    /// TPM_ALG_ECSCHNORR.
    Ecc(SignatureEcc),
    /// An HMAC, for TPM_ALG_HMAC.
    Hmac(TpmtHa),
    /// TPM_ALG_NULL selects no signature at all.
    Null,
}

/// TPMT_SIGNATURE, Part 2 Table 219.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmtSignature {
    pub sig_alg: u16,
    pub signature: SignatureValue,
}

impl TpmtSignature {
    /// A signature with TPM_ALG_NULL, which marshals as two octets.
    pub fn null() -> TpmtSignature {
        TpmtSignature {
            sig_alg: alg::NULL,
            signature: SignatureValue::Null,
        }
    }

    /// True when the signature algorithm is TPM_ALG_NULL.
    pub fn is_null(&self) -> bool {
        self.sig_alg == alg::NULL
    }

    /// The hash algorithm the signature was made with, if it has one.
    pub fn hash_alg(&self) -> Option<u16> {
        match &self.signature {
            SignatureValue::Rsa(s) => Some(s.hash),
            SignatureValue::Ecc(s) => Some(s.hash),
            SignatureValue::Hmac(h) => Some(h.hash_alg),
            SignatureValue::Null => None,
        }
    }
}

impl Marshal for TpmtSignature {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.sig_alg);
        match &self.signature {
            SignatureValue::Rsa(s) => s.marshal(w),
            SignatureValue::Ecc(s) => s.marshal(w),
            SignatureValue::Hmac(h) => h.marshal(w),
            SignatureValue::Null => {}
        }
    }
}

impl Unmarshal for TpmtSignature {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let sig_alg = r.u16()?;
        let signature = match sig_alg {
            alg::RSASSA | alg::RSAPSS => SignatureValue::Rsa(SignatureRsa::unmarshal(r)?),
            alg::ECDSA | alg::ECDAA | alg::SM2 | alg::ECSCHNORR => {
                SignatureValue::Ecc(SignatureEcc::unmarshal(r)?)
            }
            alg::HMAC => SignatureValue::Hmac(TpmtHa::unmarshal(r)?),
            alg::NULL => SignatureValue::Null,
            // Table 219 makes sigAlg a TPMI_ALG_SIG_SCHEME, and Table 83 gives
            // that interface type TPM_RC_SCHEME. TPM_RC_SIGNATURE is for a
            // signature value that fails to verify.
            _ => return Err(TpmRc(rc::SCHEME)),
        };
        Ok(TpmtSignature {
            sig_alg,
            signature,
        })
    }
}

/// The general form of a ticket, Part 2 Table 109.
///
/// TPMT_TK_CREATION, TPMT_TK_AUTH and TPMT_TK_HASHCHECK all share this shape:
/// a structure tag, the hierarchy whose proof value keyed the HMAC, and the
/// HMAC itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub tag: u16,
    pub hierarchy: u32,
    pub digest: crate::tpm::structures::base::Tpm2bDigest,
}

impl Ticket {
    /// A null ticket: the given tag, the null hierarchy and an empty HMAC.
    pub fn null(tag: u16) -> Ticket {
        Ticket {
            tag,
            hierarchy: crate::tpm::constants::rh::NULL,
            digest: crate::tpm::structures::base::Tpm2bDigest::empty(),
        }
    }

    /// Unmarshal a ticket, requiring one of `allowed` as the tag.
    pub fn unmarshal_tagged(r: &mut Reader<'_>, allowed: &[u16]) -> TpmResult<Ticket> {
        let tag = r.u16()?;
        if !allowed.contains(&tag) {
            return Err(TpmRc(rc::TAG));
        }
        // Part 2 Table 105 gives a TPMT_TK_AUTH a TPMI_RH_HIERARCHY+ hierarchy,
        // and Table 71 ends that type with "#TPM_RC_VALUE — response code
        // returned if the handle is out of range", so a handle that names no
        // hierarchy does not unmarshal.
        let hierarchy = r.u32()?;
        if !crate::tpm::core::hierarchy::Hierarchies::is_hierarchy(hierarchy) {
            return Err(TpmRc(rc::VALUE));
        }
        Ok(Ticket {
            tag,
            hierarchy,
            digest: crate::tpm::structures::base::Tpm2bDigest::unmarshal(r)?,
        })
    }
}

impl Marshal for Ticket {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.tag);
        w.u32(self.hierarchy);
        self.digest.marshal(w);
    }
}

/// TPMT_TK_VERIFIED, Part 2 Table 113.
///
/// Version 185 added the metadata union of Table 111: a digest verification
/// ticket carries the hash algorithm that produced the digest, while the other
/// two tags carry nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTicket {
    pub tag: u16,
    pub hierarchy: u32,
    /// Present only when `tag` is TPM_ST_DIGEST_VERIFIED.
    pub digest_alg: Option<u16>,
    pub hmac: crate::tpm::structures::base::Tpm2bDigest,
}

impl VerifiedTicket {
    /// A null verification ticket.
    pub fn null() -> VerifiedTicket {
        VerifiedTicket {
            tag: crate::tpm::constants::st::VERIFIED,
            hierarchy: crate::tpm::constants::rh::NULL,
            digest_alg: None,
            hmac: crate::tpm::structures::base::Tpm2bDigest::empty(),
        }
    }
}

impl Marshal for VerifiedTicket {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.tag);
        w.u32(self.hierarchy);
        if let Some(a) = self.digest_alg {
            w.u16(a);
        }
        self.hmac.marshal(w);
    }
}

impl Unmarshal for VerifiedTicket {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        use crate::tpm::constants::st;
        let tag = r.u16()?;
        let hierarchy = r.u32()?;
        let digest_alg = match tag {
            st::VERIFIED | st::MESSAGE_VERIFIED => None,
            st::DIGEST_VERIFIED => {
                let a = r.u16()?;
                if digest_size(a).is_none() {
                    return Err(TpmRc(rc::HASH));
                }
                Some(a)
            }
            _ => return Err(TpmRc(rc::TAG)),
        };
        Ok(VerifiedTicket {
            tag,
            hierarchy,
            digest_alg,
            hmac: crate::tpm::structures::base::Tpm2bDigest::unmarshal(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{rh, st};
    use crate::tpm::structures::base::Tpm2bDigest;

    #[test]
    fn null_signature_is_two_octets() {
        let s = TpmtSignature::null();
        assert_eq!(s.to_bytes(), vec![0x00, 0x10]);
        assert_eq!(TpmtSignature::from_bytes(&[0x00, 0x10]).unwrap(), s);
        assert!(s.is_null());
        assert_eq!(s.hash_alg(), None);
    }

    #[test]
    fn rsa_signature_round_trip() {
        let s = TpmtSignature {
            sig_alg: alg::RSASSA,
            signature: SignatureValue::Rsa(SignatureRsa {
                hash: alg::SHA256,
                sig: Tpm2bPublicKeyRsa::from_slice(&[0x5a; 256]).unwrap(),
            }),
        };
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), 2 + 2 + 2 + 256);
        assert_eq!(TpmtSignature::from_bytes(&bytes).unwrap(), s);
        assert_eq!(s.hash_alg(), Some(alg::SHA256));
    }

    #[test]
    fn ecc_signature_round_trip() {
        let s = TpmtSignature {
            sig_alg: alg::ECDSA,
            signature: SignatureValue::Ecc(SignatureEcc {
                hash: alg::SHA256,
                signature_r: Tpm2bEccParameter::from_slice(&[1u8; 32]).unwrap(),
                signature_s: Tpm2bEccParameter::from_slice(&[2u8; 32]).unwrap(),
            }),
        };
        assert_eq!(TpmtSignature::from_bytes(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn hmac_signature_round_trip() {
        let s = TpmtSignature {
            sig_alg: alg::HMAC,
            signature: SignatureValue::Hmac(TpmtHa::new(alg::SHA256, vec![9u8; 32]).unwrap()),
        };
        assert_eq!(TpmtSignature::from_bytes(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn unknown_signature_algorithm_is_rejected() {
        // Table 219 makes sigAlg an interface type, so a bad selector is
        // TPM_RC_SCHEME rather than TPM_RC_SIGNATURE.
        assert_eq!(
            TpmtSignature::from_bytes(&[0x00, 0x06]).unwrap_err(),
            TpmRc(rc::SCHEME)
        );
        assert_eq!(
            TpmtSignature::from_bytes(&[0x00, 0x17]).unwrap_err(),
            TpmRc(rc::SCHEME)
        );
    }

    #[test]
    fn ticket_round_trip() {
        let t = Ticket {
            tag: st::CREATION,
            hierarchy: rh::OWNER,
            digest: Tpm2bDigest::from_slice(&[3u8; 32]).unwrap(),
        };
        let bytes = t.to_bytes();
        assert_eq!(&bytes[0..2], &st::CREATION.to_be_bytes());
        let mut r = Reader::new(&bytes);
        assert_eq!(Ticket::unmarshal_tagged(&mut r, &[st::CREATION]).unwrap(), t);

        let mut r = Reader::new(&bytes);
        assert_eq!(
            Ticket::unmarshal_tagged(&mut r, &[st::HASHCHECK]).unwrap_err(),
            TpmRc(rc::TAG)
        );
    }

    #[test]
    fn null_ticket_shape() {
        let t = Ticket::null(st::HASHCHECK);
        assert_eq!(
            t.to_bytes(),
            vec![0x80, 0x24, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00]
        );
    }

    #[test]
    fn verified_ticket_metadata_depends_on_the_tag() {
        let plain = VerifiedTicket {
            tag: st::VERIFIED,
            hierarchy: rh::OWNER,
            digest_alg: None,
            hmac: Tpm2bDigest::from_slice(&[4u8; 32]).unwrap(),
        };
        let bytes = plain.to_bytes();
        assert_eq!(bytes.len(), 2 + 4 + 2 + 32);
        assert_eq!(VerifiedTicket::from_bytes(&bytes).unwrap(), plain);

        let with_alg = VerifiedTicket {
            tag: st::DIGEST_VERIFIED,
            hierarchy: rh::OWNER,
            digest_alg: Some(alg::SHA384),
            hmac: Tpm2bDigest::from_slice(&[4u8; 32]).unwrap(),
        };
        let bytes = with_alg.to_bytes();
        assert_eq!(bytes.len(), 2 + 4 + 2 + 2 + 32);
        assert_eq!(VerifiedTicket::from_bytes(&bytes).unwrap(), with_alg);

        let message = VerifiedTicket {
            tag: st::MESSAGE_VERIFIED,
            hierarchy: rh::NULL,
            digest_alg: None,
            hmac: Tpm2bDigest::empty(),
        };
        assert_eq!(
            VerifiedTicket::from_bytes(&message.to_bytes()).unwrap(),
            message
        );
    }

    #[test]
    fn verified_ticket_rejects_a_bad_tag_or_hash() {
        let mut raw = st::CREATION.to_be_bytes().to_vec();
        raw.extend_from_slice(&rh::NULL.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(VerifiedTicket::from_bytes(&raw).unwrap_err(), TpmRc(rc::TAG));

        let mut raw = st::DIGEST_VERIFIED.to_be_bytes().to_vec();
        raw.extend_from_slice(&rh::NULL.to_be_bytes());
        raw.extend_from_slice(&alg::RSA.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            VerifiedTicket::from_bytes(&raw).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }
}
