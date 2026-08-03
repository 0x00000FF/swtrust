//! Counted lists and the tagged structures they hold, Part 2 clause 10.9.
//!
//! Every list is a UINT32 count followed by that many elements. The count is
//! bounded so a malformed input cannot ask the TPM to allocate without limit.

use crate::tpm::config;
use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{marshal_list, unmarshal_list, Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::{ActAttributes, CommandAttributes};
use crate::tpm::structures::base::{PcrSelect, PcrSelection, Tpm2bDigest, Tpm2bVendorProperty, TpmtHa};

/// TPMS_ALG_PROPERTY, Part 2 Table 116.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgProperty {
    pub alg: u16,
    /// TPMA_ALGORITHM. Every bit was deprecated in version 185.
    pub alg_properties: u32,
}

impl Marshal for AlgProperty {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.alg);
        w.u32(self.alg_properties);
    }
}

impl Unmarshal for AlgProperty {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(AlgProperty {
            alg: r.u16()?,
            alg_properties: r.u32()?,
        })
    }
}

/// TPMS_TAGGED_PROPERTY, Part 2 Table 117.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggedProperty {
    pub property: u32,
    pub value: u32,
}

impl TaggedProperty {
    pub fn new(property: u32, value: u32) -> TaggedProperty {
        TaggedProperty { property, value }
    }
}

impl Marshal for TaggedProperty {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.property);
        w.u32(self.value);
    }
}

impl Unmarshal for TaggedProperty {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(TaggedProperty {
            property: r.u32()?,
            value: r.u32()?,
        })
    }
}

/// TPMS_TAGGED_PCR_SELECT, Part 2 Table 118.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedPcrSelect {
    pub tag: u32,
    pub select: PcrSelect,
}

impl Marshal for TaggedPcrSelect {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.tag);
        self.select.marshal(w);
    }
}

impl Unmarshal for TaggedPcrSelect {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(TaggedPcrSelect {
            tag: r.u32()?,
            select: PcrSelect::unmarshal(r)?,
        })
    }
}

/// TPMS_TAGGED_POLICY, Part 2 Table 119.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedPolicy {
    pub handle: u32,
    pub policy_hash: TpmtHa,
}

impl Marshal for TaggedPolicy {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.handle);
        self.policy_hash.marshal(w);
    }
}

impl Unmarshal for TaggedPolicy {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(TaggedPolicy {
            handle: r.u32()?,
            policy_hash: TpmtHa::unmarshal(r)?,
        })
    }
}

/// TPMS_ACT_DATA, Part 2 Table 120.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActData {
    pub handle: u32,
    pub timeout: u32,
    pub attributes: ActAttributes,
}

impl Marshal for ActData {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.handle);
        w.u32(self.timeout);
        self.attributes.marshal(w);
    }
}

impl Unmarshal for ActData {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(ActData {
            handle: r.u32()?,
            timeout: r.u32()?,
            attributes: ActAttributes::unmarshal(r)?,
        })
    }
}

/// TPMS_SPDM_SESSION_INFO, Part 2 Table 121.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdmSessionInfo {
    pub session_id: u32,
    pub session_index: u8,
}

impl Marshal for SpdmSessionInfo {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.session_id);
        w.u8(self.session_index);
    }
}

impl Unmarshal for SpdmSessionInfo {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(SpdmSessionInfo {
            session_id: r.u32()?,
            session_index: r.u8()?,
        })
    }
}

/// TPMS_VENDOR_PROPERTY, carried by TPML_VENDOR_PROPERTY, Part 2 Table 137.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorProperty {
    pub property: u32,
    pub value: Tpm2bVendorProperty,
}

impl Marshal for VendorProperty {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.property);
        self.value.marshal(w);
    }
}

impl Unmarshal for VendorProperty {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(VendorProperty {
            property: r.u32()?,
            value: Tpm2bVendorProperty::unmarshal(r)?,
        })
    }
}

macro_rules! tpml {
    ($(#[$meta:meta])* $name:ident, $elem:ty, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $name {
            pub items: Vec<$elem>,
        }

        impl $name {
            /// Largest `count` the specification allows for this list.
            pub const MAX: usize = $max;

            pub fn new(items: Vec<$elem>) -> TpmResult<Self> {
                if items.len() > Self::MAX {
                    return Err(TpmRc(rc::SIZE));
                }
                Ok($name { items })
            }

            pub fn empty() -> Self {
                $name { items: Vec::new() }
            }

            pub fn len(&self) -> usize {
                self.items.len()
            }

            pub fn is_empty(&self) -> bool {
                self.items.is_empty()
            }
        }

        impl Marshal for $name {
            fn marshal(&self, w: &mut Writer) {
                marshal_list(w, &self.items);
            }
        }

        impl Unmarshal for $name {
            fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
                Ok($name {
                    items: unmarshal_list::<$elem>(r, Self::MAX)?,
                })
            }
        }
    };
}

/// Octets a capability response may carry beyond the capability selector.
///
/// Part 2 clause 10.10 defines `MAX_CAP_DATA = MAX_CAP_BUFFER - sizeof(TPM_CAP)
/// - sizeof(UINT32)`, and every capability list is bounded by how many of its
/// elements fit in that space.
pub const MAX_CAP_DATA: usize = config::MAX_CAP_BUFFER - 4 - 4;

/// The element count that fits in a capability response.
const fn cap_list_max(element_size: usize) -> usize {
    MAX_CAP_DATA / element_size
}

tpml! {
    /// TPML_CC, Part 2 Table 122.
    TpmlCc, u32, cap_list_max(4)
}
tpml! {
    /// TPML_CCA, Part 2 Table 123.
    TpmlCca, CommandAttributes, cap_list_max(4)
}
tpml! {
    /// TPML_ALG, Part 2 Table 124.
    TpmlAlg, u16, config::MAX_ALG_LIST_SIZE
}
tpml! {
    /// TPML_HANDLE, Part 2 Table 125.
    TpmlHandle, u32, cap_list_max(4)
}
tpml! {
    /// TPML_DIGEST_VALUES, Part 2 Table 127.
    TpmlDigestValues, TpmtHa, config::HASH_COUNT
}
tpml! {
    /// TPML_PCR_SELECTION, Part 2 Table 128.
    TpmlPcrSelection, PcrSelection, config::HASH_COUNT
}
tpml! {
    /// TPML_ALG_PROPERTY, Part 2 Table 129.
    TpmlAlgProperty, AlgProperty, cap_list_max(6)
}
tpml! {
    /// TPML_TAGGED_TPM_PROPERTY, Part 2 Table 130.
    TpmlTaggedTpmProperty, TaggedProperty, cap_list_max(8)
}
tpml! {
    /// TPML_TAGGED_PCR_PROPERTY, Part 2 Table 131.
    ///
    /// Each entry is a UINT32 tag and a TPMS_PCR_SELECT.
    TpmlTaggedPcrProperty, TaggedPcrSelect, cap_list_max(4 + 1 + config::PCR_SELECT_MAX as usize)
}
tpml! {
    /// TPML_ECC_CURVE, Part 2 Table 132.
    TpmlEccCurve, u16, cap_list_max(2)
}
tpml! {
    /// TPML_TAGGED_POLICY, Part 2 Table 133.
    ///
    /// Each entry is a handle and a TPMT_HA.
    TpmlTaggedPolicy, TaggedPolicy, cap_list_max(4 + 2 + crate::tpm::structures::base::MAX_DIGEST_SIZE)
}
tpml! {
    /// TPML_ACT_DATA, Part 2 Table 134.
    TpmlActData, ActData, cap_list_max(12)
}
tpml! {
    /// TPML_PUB_KEY, Part 2 Table 135.
    TpmlPubKey, crate::tpm::structures::keys::Tpm2bPublic, 16
}
tpml! {
    /// TPML_SPDM_SESSION_INFO, Part 2 Table 136.
    TpmlSpdmSessionInfo, SpdmSessionInfo, cap_list_max(5)
}
tpml! {
    /// TPML_VENDOR_PROPERTY, Part 2 Table 137.
    ///
    /// Each entry is a property identifier and a TPM2B_VENDOR_PROPERTY, whose
    /// smallest form is an empty buffer.
    TpmlVendorProperty, VendorProperty, cap_list_max(4 + 2)
}

/// TPML_DIGEST, Part 2 Table 126.
///
/// Unlike the other lists this one has a minimum count of two, because it is
/// only used by TPM2_PolicyOR where a single branch would be meaningless.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TpmlDigest {
    pub digests: Vec<Tpm2bDigest>,
}

impl TpmlDigest {
    pub const MIN: usize = 2;
    pub const MAX: usize = 8;

    pub fn new(digests: Vec<Tpm2bDigest>) -> TpmResult<TpmlDigest> {
        if !(Self::MIN..=Self::MAX).contains(&digests.len()) {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(TpmlDigest { digests })
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }
}

impl Marshal for TpmlDigest {
    fn marshal(&self, w: &mut Writer) {
        marshal_list(w, &self.digests);
    }
}

impl Unmarshal for TpmlDigest {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let count = r.u32()? as usize;
        if !(Self::MIN..=Self::MAX).contains(&count) {
            return Err(TpmRc(rc::SIZE));
        }
        let mut digests = Vec::with_capacity(count);
        for _ in 0..count {
            digests.push(Tpm2bDigest::unmarshal(r)?);
        }
        Ok(TpmlDigest { digests })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;

    #[test]
    fn a_list_is_a_count_then_elements() {
        let l = TpmlAlg::new(vec![alg::SHA384, alg::SHA256]).unwrap();
        assert_eq!(
            l.to_bytes(),
            vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x0b]
        );
        assert_eq!(TpmlAlg::from_bytes(&l.to_bytes()).unwrap(), l);
    }

    #[test]
    fn an_empty_list_is_just_a_zero_count() {
        let l = TpmlHandle::empty();
        assert_eq!(l.to_bytes(), vec![0, 0, 0, 0]);
        assert_eq!(TpmlHandle::from_bytes(&[0, 0, 0, 0]).unwrap(), l);
    }

    #[test]
    fn a_count_above_the_maximum_is_rejected_before_allocating() {
        let mut raw = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        raw.extend_from_slice(&[0u8; 4]);
        assert_eq!(TpmlHandle::from_bytes(&raw).unwrap_err(), TpmRc(rc::SIZE));
        assert!(TpmlAlg::new(vec![0u16; TpmlAlg::MAX + 1]).is_err());
    }

    #[test]
    fn a_truncated_element_is_insufficient() {
        // The count says two but only one handle follows.
        let mut raw = 2u32.to_be_bytes().to_vec();
        raw.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            TpmlHandle::from_bytes(&raw).unwrap_err(),
            TpmRc(rc::INSUFFICIENT)
        );
    }

    #[test]
    fn digest_list_requires_at_least_two_entries() {
        let one = vec![Tpm2bDigest::from_slice(&[1u8; 32]).unwrap()];
        assert_eq!(TpmlDigest::new(one.clone()).unwrap_err(), TpmRc(rc::SIZE));

        let mut raw = 1u32.to_be_bytes().to_vec();
        raw.extend_from_slice(&one[0].to_bytes());
        assert_eq!(TpmlDigest::from_bytes(&raw).unwrap_err(), TpmRc(rc::SIZE));

        let two = vec![
            Tpm2bDigest::from_slice(&[1u8; 32]).unwrap(),
            Tpm2bDigest::from_slice(&[2u8; 32]).unwrap(),
        ];
        let l = TpmlDigest::new(two).unwrap();
        assert_eq!(TpmlDigest::from_bytes(&l.to_bytes()).unwrap(), l);

        // More than eight branches is also refused.
        let nine = vec![Tpm2bDigest::from_slice(&[0u8; 32]).unwrap(); 9];
        assert!(TpmlDigest::new(nine).is_err());
    }

    #[test]
    fn pcr_selection_list_round_trip() {
        let mut s = PcrSelect::none();
        s.select(0);
        s.select(7);
        let l = TpmlPcrSelection::new(vec![
            PcrSelection::new(alg::SHA384, s.clone()),
            PcrSelection::new(alg::SHA256, s),
        ])
        .unwrap();
        assert_eq!(TpmlPcrSelection::from_bytes(&l.to_bytes()).unwrap(), l);
    }

    #[test]
    fn tagged_property_round_trip() {
        let p = TaggedProperty::new(crate::tpm::constants::pt::MANUFACTURER, 0x5357_5400);
        assert_eq!(
            p.to_bytes(),
            vec![0x00, 0x00, 0x01, 0x05, 0x53, 0x57, 0x54, 0x00]
        );
        assert_eq!(TaggedProperty::from_bytes(&p.to_bytes()).unwrap(), p);
    }

    #[test]
    fn tagged_pcr_select_round_trip() {
        let mut s = PcrSelect::none();
        s.select(16);
        let t = TaggedPcrSelect {
            tag: crate::tpm::constants::pt_pcr::EXTEND_L0,
            select: s,
        };
        assert_eq!(TaggedPcrSelect::from_bytes(&t.to_bytes()).unwrap(), t);
    }

    #[test]
    fn act_data_round_trip() {
        let a = ActData {
            handle: crate::tpm::constants::rh::ACT_0,
            timeout: 1234,
            attributes: ActAttributes(ActAttributes::SIGNALED),
        };
        assert_eq!(ActData::from_bytes(&a.to_bytes()).unwrap(), a);
    }

    #[test]
    fn digest_values_list_round_trip() {
        let l = TpmlDigestValues::new(vec![
            TpmtHa::new(alg::SHA384, vec![1u8; 48]).unwrap(),
            TpmtHa::new(alg::SHA256, vec![2u8; 32]).unwrap(),
        ])
        .unwrap();
        assert_eq!(TpmlDigestValues::from_bytes(&l.to_bytes()).unwrap(), l);
    }
}
