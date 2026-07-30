//! Capability data from Part 2 clause 10.10, and the command and response
//! authorization areas from clause 10.12.

use crate::tpm::constants::{cap, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::SessionAttributes;
use crate::tpm::structures::base::{Tpm2bAuth, Tpm2bNonce};
use crate::tpm::structures::lists::{
    TpmlAlgProperty, TpmlActData, TpmlCc, TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection,
    TpmlPubKey, TpmlSpdmSessionInfo, TpmlTaggedPcrProperty, TpmlTaggedPolicy,
    TpmlTaggedTpmProperty, TpmlVendorProperty,
};

/// TPMU_CAPABILITIES, Part 2 Table 138.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capabilities {
    Algorithms(TpmlAlgProperty),
    Handles(TpmlHandle),
    Command(TpmlCca),
    PpCommands(TpmlCc),
    AuditCommands(TpmlCc),
    AssignedPcr(TpmlPcrSelection),
    TpmProperties(TpmlTaggedTpmProperty),
    PcrProperties(TpmlTaggedPcrProperty),
    EccCurves(TpmlEccCurve),
    AuthPolicies(TpmlTaggedPolicy),
    Act(TpmlActData),
    PubKeys(TpmlPubKey),
    SpdmSessionInfo(TpmlSpdmSessionInfo),
    VendorProperty(TpmlVendorProperty),
}

impl Capabilities {
    /// The TPM_CAP that selects this variant.
    pub fn selector(&self) -> u32 {
        match self {
            Capabilities::Algorithms(_) => cap::ALGS,
            Capabilities::Handles(_) => cap::HANDLES,
            Capabilities::Command(_) => cap::COMMANDS,
            Capabilities::PpCommands(_) => cap::PP_COMMANDS,
            Capabilities::AuditCommands(_) => cap::AUDIT_COMMANDS,
            Capabilities::AssignedPcr(_) => cap::PCRS,
            Capabilities::TpmProperties(_) => cap::TPM_PROPERTIES,
            Capabilities::PcrProperties(_) => cap::PCR_PROPERTIES,
            Capabilities::EccCurves(_) => cap::ECC_CURVES,
            Capabilities::AuthPolicies(_) => cap::AUTH_POLICIES,
            Capabilities::Act(_) => cap::ACT,
            Capabilities::PubKeys(_) => cap::PUB_KEYS,
            Capabilities::SpdmSessionInfo(_) => cap::SPDM_SESSION_INFO,
            Capabilities::VendorProperty(_) => cap::VENDOR_PROPERTY,
        }
    }

    /// Unmarshal the variant selected by `selector`.
    pub fn unmarshal_with(r: &mut Reader<'_>, selector: u32) -> TpmResult<Capabilities> {
        Ok(match selector {
            cap::ALGS => Capabilities::Algorithms(TpmlAlgProperty::unmarshal(r)?),
            cap::HANDLES => Capabilities::Handles(TpmlHandle::unmarshal(r)?),
            cap::COMMANDS => Capabilities::Command(TpmlCca::unmarshal(r)?),
            cap::PP_COMMANDS => Capabilities::PpCommands(TpmlCc::unmarshal(r)?),
            cap::AUDIT_COMMANDS => Capabilities::AuditCommands(TpmlCc::unmarshal(r)?),
            cap::PCRS => Capabilities::AssignedPcr(TpmlPcrSelection::unmarshal(r)?),
            cap::TPM_PROPERTIES => {
                Capabilities::TpmProperties(TpmlTaggedTpmProperty::unmarshal(r)?)
            }
            cap::PCR_PROPERTIES => {
                Capabilities::PcrProperties(TpmlTaggedPcrProperty::unmarshal(r)?)
            }
            cap::ECC_CURVES => Capabilities::EccCurves(TpmlEccCurve::unmarshal(r)?),
            cap::AUTH_POLICIES => Capabilities::AuthPolicies(TpmlTaggedPolicy::unmarshal(r)?),
            cap::ACT => Capabilities::Act(TpmlActData::unmarshal(r)?),
            cap::PUB_KEYS => Capabilities::PubKeys(TpmlPubKey::unmarshal(r)?),
            cap::SPDM_SESSION_INFO => {
                Capabilities::SpdmSessionInfo(TpmlSpdmSessionInfo::unmarshal(r)?)
            }
            cap::VENDOR_PROPERTY => Capabilities::VendorProperty(TpmlVendorProperty::unmarshal(r)?),
            _ => return Err(TpmRc(rc::SELECTOR)),
        })
    }
}

impl Marshal for Capabilities {
    fn marshal(&self, w: &mut Writer) {
        match self {
            Capabilities::Algorithms(l) => l.marshal(w),
            Capabilities::Handles(l) => l.marshal(w),
            Capabilities::Command(l) => l.marshal(w),
            Capabilities::PpCommands(l) => l.marshal(w),
            Capabilities::AuditCommands(l) => l.marshal(w),
            Capabilities::AssignedPcr(l) => l.marshal(w),
            Capabilities::TpmProperties(l) => l.marshal(w),
            Capabilities::PcrProperties(l) => l.marshal(w),
            Capabilities::EccCurves(l) => l.marshal(w),
            Capabilities::AuthPolicies(l) => l.marshal(w),
            Capabilities::Act(l) => l.marshal(w),
            Capabilities::PubKeys(l) => l.marshal(w),
            Capabilities::SpdmSessionInfo(l) => l.marshal(w),
            Capabilities::VendorProperty(l) => l.marshal(w),
        }
    }
}

/// TPMS_CAPABILITY_DATA, Part 2 Table 139.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityData {
    pub data: Capabilities,
}

impl Marshal for CapabilityData {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.data.selector());
        self.data.marshal(w);
    }
}

impl Unmarshal for CapabilityData {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let selector = r.u32()?;
        Ok(CapabilityData {
            data: Capabilities::unmarshal_with(r, selector)?,
        })
    }
}

/// TPMS_AUTH_COMMAND, Part 2 Table 156.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthCommand {
    pub session_handle: u32,
    pub nonce: Tpm2bNonce,
    pub session_attributes: SessionAttributes,
    pub hmac: Tpm2bAuth,
}

impl Marshal for AuthCommand {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.session_handle);
        self.nonce.marshal(w);
        self.session_attributes.marshal(w);
        self.hmac.marshal(w);
    }
}

impl Unmarshal for AuthCommand {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(AuthCommand {
            session_handle: r.u32()?,
            nonce: Tpm2bNonce::unmarshal(r)?,
            session_attributes: SessionAttributes::unmarshal(r)?,
            hmac: Tpm2bAuth::unmarshal(r)?,
        })
    }
}

/// TPMS_AUTH_RESPONSE, Part 2 Table 157.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthResponse {
    pub nonce: Tpm2bNonce,
    pub session_attributes: SessionAttributes,
    pub hmac: Tpm2bAuth,
}

impl Marshal for AuthResponse {
    fn marshal(&self, w: &mut Writer) {
        self.nonce.marshal(w);
        self.session_attributes.marshal(w);
        self.hmac.marshal(w);
    }
}

impl Unmarshal for AuthResponse {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(AuthResponse {
            nonce: Tpm2bNonce::unmarshal(r)?,
            session_attributes: SessionAttributes::unmarshal(r)?,
            hmac: Tpm2bAuth::unmarshal(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::{alg, pt, rh};
    use crate::tpm::structures::lists::TaggedProperty;

    #[test]
    fn capability_data_is_a_selector_then_a_list() {
        let d = CapabilityData {
            data: Capabilities::TpmProperties(
                TpmlTaggedTpmProperty::new(vec![
                    TaggedProperty::new(pt::MANUFACTURER, 0x5357_5400),
                    TaggedProperty::new(pt::FIRMWARE_VERSION_1, 0x0001_0000),
                ])
                .unwrap(),
            ),
        };
        let bytes = d.to_bytes();
        assert_eq!(&bytes[0..4], &cap::TPM_PROPERTIES.to_be_bytes());
        assert_eq!(&bytes[4..8], &2u32.to_be_bytes());
        assert_eq!(CapabilityData::from_bytes(&bytes).unwrap(), d);
    }

    #[test]
    fn every_capability_selector_round_trips() {
        let cases = vec![
            Capabilities::Algorithms(TpmlAlgProperty::empty()),
            Capabilities::Handles(TpmlHandle::new(vec![rh::OWNER]).unwrap()),
            Capabilities::Command(TpmlCca::empty()),
            Capabilities::PpCommands(TpmlCc::empty()),
            Capabilities::AuditCommands(TpmlCc::empty()),
            Capabilities::AssignedPcr(TpmlPcrSelection::empty()),
            Capabilities::TpmProperties(TpmlTaggedTpmProperty::empty()),
            Capabilities::PcrProperties(TpmlTaggedPcrProperty::empty()),
            Capabilities::EccCurves(TpmlEccCurve::new(vec![alg::SHA256]).unwrap()),
            Capabilities::AuthPolicies(TpmlTaggedPolicy::empty()),
            Capabilities::Act(TpmlActData::empty()),
            Capabilities::PubKeys(TpmlPubKey::empty()),
            Capabilities::SpdmSessionInfo(TpmlSpdmSessionInfo::empty()),
            Capabilities::VendorProperty(TpmlVendorProperty::empty()),
        ];
        for c in cases {
            let d = CapabilityData { data: c.clone() };
            let bytes = d.to_bytes();
            assert_eq!(&bytes[0..4], &c.selector().to_be_bytes());
            assert_eq!(CapabilityData::from_bytes(&bytes).unwrap(), d);
        }
    }

    #[test]
    fn an_unknown_capability_is_a_selector_error() {
        let mut raw = 0x0000_0099u32.to_be_bytes().to_vec();
        raw.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            CapabilityData::from_bytes(&raw).unwrap_err(),
            TpmRc(rc::SELECTOR)
        );
    }

    #[test]
    fn command_authorization_round_trip() {
        let a = AuthCommand {
            session_handle: rh::RS_PW,
            nonce: Tpm2bNonce::empty(),
            session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
            hmac: Tpm2bAuth::from_slice(b"password").unwrap(),
        };
        let bytes = a.to_bytes();
        assert_eq!(&bytes[0..4], &rh::RS_PW.to_be_bytes());
        assert_eq!(&bytes[4..6], &[0x00, 0x00]);
        assert_eq!(bytes[6], 0x01);
        assert_eq!(AuthCommand::from_bytes(&bytes).unwrap(), a);
    }

    #[test]
    fn response_authorization_round_trip() {
        let a = AuthResponse {
            nonce: Tpm2bNonce::from_slice(&[5u8; 32]).unwrap(),
            session_attributes: SessionAttributes(SessionAttributes::CONTINUE_SESSION),
            hmac: Tpm2bAuth::from_slice(&[6u8; 32]).unwrap(),
        };
        assert_eq!(AuthResponse::from_bytes(&a.to_bytes()).unwrap(), a);
    }

    #[test]
    fn a_reserved_session_attribute_bit_is_rejected() {
        let mut bytes = AuthCommand::default().to_bytes();
        // sessionHandle(4) + nonce size(2) + attributes(1)
        bytes[6] = 0x08;
        assert_eq!(
            AuthCommand::from_bytes(&bytes).unwrap_err(),
            TpmRc(rc::RESERVED_BITS)
        );
    }
}
