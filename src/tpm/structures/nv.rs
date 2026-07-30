//! NV Index structures from Part 2 clause 13.

use crate::tpm::config;
use crate::tpm::constants::{ht, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::NvAttributes;
use crate::tpm::structures::base::{digest_size, Tpm2bDigest};

/// TPMA_NV_EXP, Part 2 Table 250.
///
/// The low 32 bits are a TPMA_NV. Bits 34:32 describe how an external NV Index
/// is protected and bits 63:35 are reserved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NvExpAttributes(pub u64);

impl NvExpAttributes {
    /// External NV Index contents are encrypted.
    pub const EXTERNAL_NV_ENCRYPTION: u64 = 1 << 32;
    /// External NV Index contents are integrity protected.
    pub const EXTERNAL_NV_INTEGRITY: u64 = 1 << 33;
    /// External NV Index contents are rollback protected.
    pub const EXTERNAL_NV_ANTIROLLBACK: u64 = 1 << 34;
    /// Bits 63:35 are reserved.
    pub const RESERVED: u64 = 0xFFFF_FFF8_0000_0000;

    /// The TPMA_NV held in the low 32 bits.
    pub fn base(self) -> NvAttributes {
        NvAttributes(self.0 as u32)
    }

    pub fn has(self, mask: u64) -> bool {
        self.0 & mask == mask
    }

    /// Check the reserved bits of both halves.
    pub fn check_reserved(self) -> TpmResult<()> {
        if self.0 & Self::RESERVED != 0 {
            return Err(TpmRc(rc::RESERVED_BITS));
        }
        self.base().check_reserved()
    }
}

impl Marshal for NvExpAttributes {
    fn marshal(&self, w: &mut Writer) {
        w.u64(self.0);
    }
}

impl Unmarshal for NvExpAttributes {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let v = NvExpAttributes(r.u64()?);
        v.check_reserved()?;
        Ok(v)
    }
}

/// TPMS_NV_PUBLIC, Part 2 Table 251.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPublic {
    pub nv_index: u32,
    pub name_alg: u16,
    pub attributes: NvAttributes,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

impl Marshal for NvPublic {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.nv_index);
        w.u16(self.name_alg);
        self.attributes.marshal(w);
        self.auth_policy.marshal(w);
        w.u16(self.data_size);
    }
}

impl Unmarshal for NvPublic {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let nv_index = r.u32()?;
        let name_alg = r.u16()?;
        if digest_size(name_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        let attributes = NvAttributes::unmarshal(r)?;
        let auth_policy = Tpm2bDigest::unmarshal(r)?;
        let data_size = r.u16()?;
        if data_size as usize > config::MAX_NV_INDEX_SIZE {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(NvPublic {
            nv_index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
        })
    }
}

/// TPM2B_NV_PUBLIC, Part 2 Table 252.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2bNvPublic {
    pub nv_public: NvPublic,
}

impl Marshal for Tpm2bNvPublic {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.nv_public.marshal(w));
    }
}

impl Unmarshal for Tpm2bNvPublic {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let nv_public = NvPublic::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bNvPublic { nv_public })
    }
}

/// TPMS_NV_PUBLIC_EXP_ATTR, Part 2 Table 253.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPublicExpAttr {
    pub nv_index: u32,
    pub name_alg: u16,
    pub attributes: NvExpAttributes,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

impl Marshal for NvPublicExpAttr {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.nv_index);
        w.u16(self.name_alg);
        self.attributes.marshal(w);
        self.auth_policy.marshal(w);
        w.u16(self.data_size);
    }
}

impl Unmarshal for NvPublicExpAttr {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let nv_index = r.u32()?;
        let name_alg = r.u16()?;
        if digest_size(name_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        let attributes = NvExpAttributes::unmarshal(r)?;
        let auth_policy = Tpm2bDigest::unmarshal(r)?;
        let data_size = r.u16()?;
        if data_size as usize > config::MAX_NV_INDEX_SIZE {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(NvPublicExpAttr {
            nv_index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
        })
    }
}

/// TPMU_NV_PUBLIC_2, Part 2 Table 254.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvPublic2 {
    /// An ordinary NV Index, selected by TPM_HT_NV_INDEX.
    Index(NvPublic),
    /// An external NV Index, selected by TPM_HT_EXTERNAL_NV.
    External(NvPublicExpAttr),
    /// A permanent NV Index, selected by TPM_HT_PERMANENT_NV.
    Permanent(NvPublic),
}

impl NvPublic2 {
    /// The TPM_HT that selects this variant.
    pub fn handle_type(&self) -> u8 {
        match self {
            NvPublic2::Index(_) => ht::NV_INDEX,
            NvPublic2::External(_) => ht::EXTERNAL_NV,
            NvPublic2::Permanent(_) => ht::PERMANENT_NV,
        }
    }
}

/// TPMT_NV_PUBLIC_2, Part 2 Table 255.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmtNvPublic2 {
    pub public_area: NvPublic2,
}

impl Marshal for TpmtNvPublic2 {
    fn marshal(&self, w: &mut Writer) {
        w.u8(self.public_area.handle_type());
        match &self.public_area {
            NvPublic2::Index(p) | NvPublic2::Permanent(p) => p.marshal(w),
            NvPublic2::External(p) => p.marshal(w),
        }
    }
}

impl Unmarshal for TpmtNvPublic2 {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let handle_type = r.u8()?;
        let public_area = match handle_type {
            ht::NV_INDEX => NvPublic2::Index(NvPublic::unmarshal(r)?),
            ht::EXTERNAL_NV => NvPublic2::External(NvPublicExpAttr::unmarshal(r)?),
            ht::PERMANENT_NV => NvPublic2::Permanent(NvPublic::unmarshal(r)?),
            _ => return Err(TpmRc(rc::SELECTOR)),
        };
        Ok(TpmtNvPublic2 { public_area })
    }
}

/// TPM2B_NV_PUBLIC_2, Part 2 Table 256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2bNvPublic2 {
    pub nv_public: TpmtNvPublic2,
}

impl Marshal for Tpm2bNvPublic2 {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.nv_public.marshal(w));
    }
}

impl Unmarshal for Tpm2bNvPublic2 {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let nv_public = TpmtNvPublic2::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bNvPublic2 { nv_public })
    }
}

/// TPMS_NV_PIN_COUNTER_PARAMETERS, Part 2 Table 248.
///
/// The data of a PIN pass or PIN fail Index is these two counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NvPinCounterParameters {
    pub pin_count: u32,
    pub pin_limit: u32,
}

impl Marshal for NvPinCounterParameters {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.pin_count);
        w.u32(self.pin_limit);
    }
}

impl Unmarshal for NvPinCounterParameters {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(NvPinCounterParameters {
            pin_count: r.u32()?,
            pin_limit: r.u32()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{alg, hc};
    use crate::tpm::structures::attributes::nt;

    fn public() -> NvPublic {
        NvPublic {
            nv_index: hc::NV_INDEX_FIRST + 1,
            name_alg: alg::SHA256,
            attributes: NvAttributes(NvAttributes::AUTHREAD | NvAttributes::AUTHWRITE)
                .with_index_type(nt::ORDINARY),
            auth_policy: Tpm2bDigest::empty(),
            data_size: 32,
        }
    }

    #[test]
    fn nv_public_round_trip() {
        let p = public();
        let bytes = p.to_bytes();
        assert_eq!(&bytes[0..4], &p.nv_index.to_be_bytes());
        assert_eq!(NvPublic::from_bytes(&bytes).unwrap(), p);

        let wrapped = Tpm2bNvPublic { nv_public: p };
        assert_eq!(
            Tpm2bNvPublic::from_bytes(&wrapped.to_bytes()).unwrap(),
            wrapped
        );
    }

    #[test]
    fn nv_public_rejects_a_bad_name_algorithm_or_size() {
        let p = public();
        let mut bytes = p.to_bytes();
        bytes[4..6].copy_from_slice(&alg::NULL.to_be_bytes());
        assert_eq!(NvPublic::from_bytes(&bytes).unwrap_err(), TpmRc(rc::HASH));

        let mut p = public();
        p.data_size = (config::MAX_NV_INDEX_SIZE + 1) as u16;
        assert_eq!(
            NvPublic::from_bytes(&p.to_bytes()).unwrap_err(),
            TpmRc(rc::SIZE)
        );
    }

    #[test]
    fn nv_exp_attributes_carry_a_tpma_nv_in_the_low_half() {
        let a = NvExpAttributes(
            NvExpAttributes::EXTERNAL_NV_ENCRYPTION
                | NvExpAttributes::EXTERNAL_NV_INTEGRITY
                | NvAttributes::AUTHREAD as u64,
        );
        assert!(a.has(NvExpAttributes::EXTERNAL_NV_ENCRYPTION));
        assert!(a.base().has(NvAttributes::AUTHREAD));
        assert_eq!(NvExpAttributes::from_bytes(&a.to_bytes()).unwrap(), a);
    }

    #[test]
    fn nv_exp_reserved_bits_are_rejected() {
        // Bit 35 is reserved in the high half.
        let a = NvExpAttributes(1 << 35);
        assert_eq!(
            NvExpAttributes::from_bytes(&a.to_bytes()).unwrap_err(),
            TpmRc(rc::RESERVED_BITS)
        );
        // A reserved bit of the embedded TPMA_NV is also rejected.
        let a = NvExpAttributes(NvAttributes::RESERVED as u64 & 0x0000_0300);
        assert_eq!(
            NvExpAttributes::from_bytes(&a.to_bytes()).unwrap_err(),
            TpmRc(rc::RESERVED_BITS)
        );
    }

    #[test]
    fn nv_public_2_selects_on_the_handle_type() {
        let index = TpmtNvPublic2 {
            public_area: NvPublic2::Index(public()),
        };
        let bytes = index.to_bytes();
        assert_eq!(bytes[0], ht::NV_INDEX);
        assert_eq!(TpmtNvPublic2::from_bytes(&bytes).unwrap(), index);

        let external = TpmtNvPublic2 {
            public_area: NvPublic2::External(NvPublicExpAttr {
                nv_index: hc::EXTERNAL_NV_FIRST,
                name_alg: alg::SHA256,
                attributes: NvExpAttributes(NvExpAttributes::EXTERNAL_NV_INTEGRITY),
                auth_policy: Tpm2bDigest::empty(),
                data_size: 8,
            }),
        };
        let bytes = external.to_bytes();
        assert_eq!(bytes[0], ht::EXTERNAL_NV);
        assert_eq!(TpmtNvPublic2::from_bytes(&bytes).unwrap(), external);

        let permanent = TpmtNvPublic2 {
            public_area: NvPublic2::Permanent(public()),
        };
        assert_eq!(
            TpmtNvPublic2::from_bytes(&permanent.to_bytes()).unwrap(),
            permanent
        );

        // An unknown handle type is a selector error.
        let mut bytes = index.to_bytes();
        bytes[0] = 0x7f;
        assert_eq!(
            TpmtNvPublic2::from_bytes(&bytes).unwrap_err(),
            TpmRc(rc::SELECTOR)
        );
    }

    #[test]
    fn tpm2b_nv_public_2_round_trip() {
        let v = Tpm2bNvPublic2 {
            nv_public: TpmtNvPublic2 {
                public_area: NvPublic2::Index(public()),
            },
        };
        assert_eq!(Tpm2bNvPublic2::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    #[test]
    fn pin_counter_parameters_round_trip() {
        let p = NvPinCounterParameters {
            pin_count: 3,
            pin_limit: 5,
        };
        assert_eq!(p.to_bytes(), vec![0, 0, 0, 3, 0, 0, 0, 5]);
        assert_eq!(NvPinCounterParameters::from_bytes(&p.to_bytes()).unwrap(), p);
    }
}
