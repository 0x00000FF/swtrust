//! Context and credential structures from Part 2 clauses 12.4 and 14.

use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::base::{Tpm2bContextData, Tpm2bContextSensitive, Tpm2bDigest};

/// TPMS_CONTEXT_DATA, Part 2 Table 258.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

impl Marshal for ContextData {
    fn marshal(&self, w: &mut Writer) {
        self.integrity.marshal(w);
        self.encrypted.marshal(w);
    }
}

impl Unmarshal for ContextData {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(ContextData {
            integrity: Tpm2bDigest::unmarshal(r)?,
            encrypted: Tpm2bContextSensitive::unmarshal(r)?,
        })
    }
}

/// TPMS_CONTEXT, Part 2 Table 260.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    pub sequence: u64,
    pub saved_handle: u32,
    pub hierarchy: u32,
    pub context_blob: Tpm2bContextData,
}

/// Values TPMI_DH_SAVED uses for a saved transient object, Part 2 Table 58.
pub mod saved {
    /// An ordinary transient object.
    pub const TRANSIENT_OBJECT: u32 = 0x8000_0000;
    /// A sequence object.
    pub const SEQUENCE_OBJECT: u32 = 0x8000_0001;
    /// A transient object whose stClear attribute is set.
    pub const TRANSIENT_STCLEAR: u32 = 0x8000_0002;
}

impl Marshal for Context {
    fn marshal(&self, w: &mut Writer) {
        w.u64(self.sequence);
        w.u32(self.saved_handle);
        w.u32(self.hierarchy);
        self.context_blob.marshal(w);
    }
}

impl Unmarshal for Context {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(Context {
            sequence: r.u64()?,
            saved_handle: r.u32()?,
            hierarchy: r.u32()?,
            context_blob: Tpm2bContextData::unmarshal(r)?,
        })
    }
}

/// TPMS_ID_OBJECT, Part 2 Table 244.
///
/// The credential blob produced by TPM2_MakeCredential. The encrypted portion
/// runs to the end of the containing TPM2B, so it is not itself sized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Vec<u8>,
}

impl Marshal for IdObject {
    fn marshal(&self, w: &mut Writer) {
        self.integrity_hmac.marshal(w);
        w.bytes(&self.enc_identity);
    }
}

impl Unmarshal for IdObject {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let integrity_hmac = Tpm2bDigest::unmarshal(r)?;
        Ok(IdObject {
            integrity_hmac,
            enc_identity: r.take_rest().to_vec(),
        })
    }
}

/// TPM2B_ID_OBJECT, Part 2 Table 245.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tpm2bIdObjectStruct {
    pub credential: IdObject,
}

impl Marshal for Tpm2bIdObjectStruct {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.credential.marshal(w));
    }
}

impl Unmarshal for Tpm2bIdObjectStruct {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let credential = IdObject::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bIdObjectStruct { credential })
    }
}

/// The plaintext layout of a TPM2B_PRIVATE, Part 2 Table 242.
///
/// A private area is an integrity HMAC over an encrypted TPMT_SENSITIVE. The
/// sensitive area is itself wrapped in a TPM2B when it is encrypted, so the
/// structure is written as `integrityOuter || encSensitive`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivateArea {
    pub integrity_outer: Tpm2bDigest,
    pub enc_sensitive: Vec<u8>,
}

impl Marshal for PrivateArea {
    fn marshal(&self, w: &mut Writer) {
        self.integrity_outer.marshal(w);
        w.bytes(&self.enc_sensitive);
    }
}

impl Unmarshal for PrivateArea {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let integrity_outer = Tpm2bDigest::unmarshal(r)?;
        Ok(PrivateArea {
            integrity_outer,
            enc_sensitive: r.take_rest().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::rh;

    #[test]
    fn context_round_trip() {
        let c = Context {
            sequence: 0x0102_0304_0506_0708,
            saved_handle: saved::TRANSIENT_OBJECT,
            hierarchy: rh::OWNER,
            context_blob: Tpm2bContextData::from_slice(&[1, 2, 3, 4]).unwrap(),
        };
        let bytes = c.to_bytes();
        assert_eq!(&bytes[0..8], &c.sequence.to_be_bytes());
        assert_eq!(&bytes[8..12], &saved::TRANSIENT_OBJECT.to_be_bytes());
        assert_eq!(Context::from_bytes(&bytes).unwrap(), c);
    }

    #[test]
    fn context_data_round_trip() {
        let d = ContextData {
            integrity: Tpm2bDigest::from_slice(&[9u8; 32]).unwrap(),
            encrypted: Tpm2bContextSensitive::from_slice(&[7u8; 64]).unwrap(),
        };
        assert_eq!(ContextData::from_bytes(&d.to_bytes()).unwrap(), d);
    }

    #[test]
    fn id_object_takes_the_rest_of_the_buffer() {
        let o = IdObject {
            integrity_hmac: Tpm2bDigest::from_slice(&[1u8; 32]).unwrap(),
            enc_identity: vec![2u8; 40],
        };
        let bytes = o.to_bytes();
        assert_eq!(bytes.len(), 2 + 32 + 40);
        assert_eq!(IdObject::from_bytes(&bytes).unwrap(), o);

        let wrapped = Tpm2bIdObjectStruct { credential: o };
        assert_eq!(
            Tpm2bIdObjectStruct::from_bytes(&wrapped.to_bytes()).unwrap(),
            wrapped
        );
    }

    #[test]
    fn private_area_takes_the_rest_of_the_buffer() {
        let p = PrivateArea {
            integrity_outer: Tpm2bDigest::from_slice(&[3u8; 32]).unwrap(),
            enc_sensitive: vec![4u8; 100],
        };
        let bytes = p.to_bytes();
        assert_eq!(PrivateArea::from_bytes(&bytes).unwrap(), p);
    }

    #[test]
    fn saved_handle_values_match_the_specification() {
        assert_eq!(saved::TRANSIENT_OBJECT, 0x8000_0000);
        assert_eq!(saved::SEQUENCE_OBJECT, 0x8000_0001);
        assert_eq!(saved::TRANSIENT_STCLEAR, 0x8000_0002);
    }
}
