//! Attestation structures from Part 2 clause 10.12.

use crate::tpm::constants::{rc, st, TPM_GENERATED_VALUE};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};
use crate::tpm::structures::attributes::LocalityAttributes;
use crate::tpm::structures::base::{
    Tpm2bData, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bName,
};
use crate::tpm::structures::lists::TpmlPcrSelection;

/// TPMS_CLOCK_INFO, Part 2 Table 142.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

impl Marshal for ClockInfo {
    fn marshal(&self, w: &mut Writer) {
        w.u64(self.clock);
        w.u32(self.reset_count);
        w.u32(self.restart_count);
        w.u8(u8::from(self.safe));
    }
}

impl Unmarshal for ClockInfo {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let clock = r.u64()?;
        let reset_count = r.u32()?;
        let restart_count = r.u32()?;
        Ok(ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe: unmarshal_yes_no(r)?,
        })
    }
}

/// Read a TPMI_YES_NO, Part 2 Table 48.
///
/// Only zero and one are legal; anything else is TPM_RC_VALUE.
pub fn unmarshal_yes_no(r: &mut Reader<'_>) -> TpmResult<bool> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(TpmRc(rc::VALUE)),
    }
}

/// TPMS_TIME_INFO, Part 2 Table 143.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeInfo {
    pub time: u64,
    pub clock_info: ClockInfo,
}

impl Marshal for TimeInfo {
    fn marshal(&self, w: &mut Writer) {
        w.u64(self.time);
        self.clock_info.marshal(w);
    }
}

impl Unmarshal for TimeInfo {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(TimeInfo {
            time: r.u64()?,
            clock_info: ClockInfo::unmarshal(r)?,
        })
    }
}

/// TPMU_ATTEST, Part 2 Table 153.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attested {
    /// TPMS_CERTIFY_INFO, Part 2 Table 145.
    Certify {
        name: Tpm2bName,
        qualified_name: Tpm2bName,
    },
    /// TPMS_CREATION_INFO, Part 2 Table 149.
    Creation {
        object_name: Tpm2bName,
        creation_hash: Tpm2bDigest,
    },
    /// TPMS_QUOTE_INFO, Part 2 Table 146.
    Quote {
        pcr_select: TpmlPcrSelection,
        pcr_digest: Tpm2bDigest,
    },
    /// TPMS_COMMAND_AUDIT_INFO, Part 2 Table 147.
    CommandAudit {
        audit_counter: u64,
        digest_alg: u16,
        audit_digest: Tpm2bDigest,
        command_digest: Tpm2bDigest,
    },
    /// TPMS_SESSION_AUDIT_INFO, Part 2 Table 148.
    SessionAudit {
        exclusive_session: bool,
        session_digest: Tpm2bDigest,
    },
    /// TPMS_TIME_ATTEST_INFO, Part 2 Table 144.
    Time {
        time: TimeInfo,
        firmware_version: u64,
    },
    /// TPMS_NV_CERTIFY_INFO, Part 2 Table 150.
    Nv {
        index_name: Tpm2bName,
        offset: u16,
        nv_contents: Tpm2bMaxNvBuffer,
    },
    /// TPMS_NV_DIGEST_CERTIFY_INFO, Part 2 Table 151.
    NvDigest {
        index_name: Tpm2bName,
        nv_digest: Tpm2bDigest,
    },
}

impl Attested {
    /// The TPMI_ST_ATTEST that selects this variant, Part 2 Table 152.
    pub fn selector(&self) -> u16 {
        match self {
            Attested::Certify { .. } => st::ATTEST_CERTIFY,
            Attested::Creation { .. } => st::ATTEST_CREATION,
            Attested::Quote { .. } => st::ATTEST_QUOTE,
            Attested::CommandAudit { .. } => st::ATTEST_COMMAND_AUDIT,
            Attested::SessionAudit { .. } => st::ATTEST_SESSION_AUDIT,
            Attested::Time { .. } => st::ATTEST_TIME,
            Attested::Nv { .. } => st::ATTEST_NV,
            Attested::NvDigest { .. } => st::ATTEST_NV_DIGEST,
        }
    }

    /// Unmarshal the variant selected by `selector`.
    pub fn unmarshal_with(r: &mut Reader<'_>, selector: u16) -> TpmResult<Attested> {
        Ok(match selector {
            st::ATTEST_CERTIFY => Attested::Certify {
                name: Tpm2bName::unmarshal(r)?,
                qualified_name: Tpm2bName::unmarshal(r)?,
            },
            st::ATTEST_CREATION => Attested::Creation {
                object_name: Tpm2bName::unmarshal(r)?,
                creation_hash: Tpm2bDigest::unmarshal(r)?,
            },
            st::ATTEST_QUOTE => Attested::Quote {
                pcr_select: TpmlPcrSelection::unmarshal(r)?,
                pcr_digest: Tpm2bDigest::unmarshal(r)?,
            },
            st::ATTEST_COMMAND_AUDIT => Attested::CommandAudit {
                audit_counter: r.u64()?,
                digest_alg: r.u16()?,
                audit_digest: Tpm2bDigest::unmarshal(r)?,
                command_digest: Tpm2bDigest::unmarshal(r)?,
            },
            st::ATTEST_SESSION_AUDIT => Attested::SessionAudit {
                exclusive_session: unmarshal_yes_no(r)?,
                session_digest: Tpm2bDigest::unmarshal(r)?,
            },
            st::ATTEST_TIME => Attested::Time {
                time: TimeInfo::unmarshal(r)?,
                firmware_version: r.u64()?,
            },
            st::ATTEST_NV => Attested::Nv {
                index_name: Tpm2bName::unmarshal(r)?,
                offset: r.u16()?,
                nv_contents: Tpm2bMaxNvBuffer::unmarshal(r)?,
            },
            st::ATTEST_NV_DIGEST => Attested::NvDigest {
                index_name: Tpm2bName::unmarshal(r)?,
                nv_digest: Tpm2bDigest::unmarshal(r)?,
            },
            _ => return Err(TpmRc(rc::SELECTOR)),
        })
    }
}

impl Marshal for Attested {
    fn marshal(&self, w: &mut Writer) {
        match self {
            Attested::Certify {
                name,
                qualified_name,
            } => {
                name.marshal(w);
                qualified_name.marshal(w);
            }
            Attested::Creation {
                object_name,
                creation_hash,
            } => {
                object_name.marshal(w);
                creation_hash.marshal(w);
            }
            Attested::Quote {
                pcr_select,
                pcr_digest,
            } => {
                pcr_select.marshal(w);
                pcr_digest.marshal(w);
            }
            Attested::CommandAudit {
                audit_counter,
                digest_alg,
                audit_digest,
                command_digest,
            } => {
                w.u64(*audit_counter);
                w.u16(*digest_alg);
                audit_digest.marshal(w);
                command_digest.marshal(w);
            }
            Attested::SessionAudit {
                exclusive_session,
                session_digest,
            } => {
                w.u8(u8::from(*exclusive_session));
                session_digest.marshal(w);
            }
            Attested::Time {
                time,
                firmware_version,
            } => {
                time.marshal(w);
                w.u64(*firmware_version);
            }
            Attested::Nv {
                index_name,
                offset,
                nv_contents,
            } => {
                index_name.marshal(w);
                w.u16(*offset);
                nv_contents.marshal(w);
            }
            Attested::NvDigest {
                index_name,
                nv_digest,
            } => {
                index_name.marshal(w);
                nv_digest.marshal(w);
            }
        }
    }
}

/// TPMS_ATTEST, Part 2 Table 154.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    pub magic: u32,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
    pub attested: Attested,
}

impl Attest {
    /// Build an attestation with the required magic value.
    pub fn new(
        qualified_signer: Tpm2bName,
        extra_data: Tpm2bData,
        clock_info: ClockInfo,
        firmware_version: u64,
        attested: Attested,
    ) -> Attest {
        Attest {
            magic: TPM_GENERATED_VALUE,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            attested,
        }
    }
}

impl Marshal for Attest {
    fn marshal(&self, w: &mut Writer) {
        w.u32(self.magic);
        w.u16(self.attested.selector());
        self.qualified_signer.marshal(w);
        self.extra_data.marshal(w);
        self.clock_info.marshal(w);
        w.u64(self.firmware_version);
        self.attested.marshal(w);
    }
}

impl Unmarshal for Attest {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let magic = r.u32()?;
        if magic != TPM_GENERATED_VALUE {
            return Err(TpmRc(rc::VALUE));
        }
        let selector = r.u16()?;
        let qualified_signer = Tpm2bName::unmarshal(r)?;
        let extra_data = Tpm2bData::unmarshal(r)?;
        let clock_info = ClockInfo::unmarshal(r)?;
        let firmware_version = r.u64()?;
        let attested = Attested::unmarshal_with(r, selector)?;
        Ok(Attest {
            magic,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            attested,
        })
    }
}

/// TPMS_CREATION_DATA, Part 2 Table 261.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: LocalityAttributes,
    pub parent_name_alg: u16,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

impl Marshal for CreationData {
    fn marshal(&self, w: &mut Writer) {
        self.pcr_select.marshal(w);
        self.pcr_digest.marshal(w);
        self.locality.marshal(w);
        w.u16(self.parent_name_alg);
        self.parent_name.marshal(w);
        self.parent_qualified_name.marshal(w);
        self.outside_info.marshal(w);
    }
}

impl Unmarshal for CreationData {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        Ok(CreationData {
            pcr_select: TpmlPcrSelection::unmarshal(r)?,
            pcr_digest: Tpm2bDigest::unmarshal(r)?,
            locality: LocalityAttributes::unmarshal(r)?,
            parent_name_alg: r.u16()?,
            parent_name: Tpm2bName::unmarshal(r)?,
            parent_qualified_name: Tpm2bName::unmarshal(r)?,
            outside_info: Tpm2bData::unmarshal(r)?,
        })
    }
}

/// TPM2B_CREATION_DATA, Part 2 Table 262.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2bCreationData {
    pub creation_data: CreationData,
}

impl Marshal for Tpm2bCreationData {
    fn marshal(&self, w: &mut Writer) {
        w.sized16_with(|w| self.creation_data.marshal(w));
    }
}

impl Unmarshal for Tpm2bCreationData {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u16()? as usize;
        let mut inner = r.sub(size)?;
        let creation_data = CreationData::unmarshal(&mut inner)?;
        if !inner.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(Tpm2bCreationData { creation_data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::constants::alg;
    use crate::tpm::structures::base::{PcrSelect, PcrSelection};

    fn name(byte: u8) -> Tpm2bName {
        let mut v = alg::SHA256.to_be_bytes().to_vec();
        v.extend_from_slice(&[byte; 32]);
        Tpm2bName::new(v).unwrap()
    }

    fn clock() -> ClockInfo {
        ClockInfo {
            clock: 1234,
            reset_count: 2,
            restart_count: 3,
            safe: true,
        }
    }

    #[test]
    fn clock_info_round_trip() {
        let c = clock();
        assert_eq!(
            c.to_bytes(),
            vec![0, 0, 0, 0, 0, 0, 0x04, 0xd2, 0, 0, 0, 2, 0, 0, 0, 3, 1]
        );
        assert_eq!(ClockInfo::from_bytes(&c.to_bytes()).unwrap(), c);
    }

    #[test]
    fn yes_no_rejects_other_values() {
        let mut bytes = clock().to_bytes();
        *bytes.last_mut().unwrap() = 2;
        assert_eq!(ClockInfo::from_bytes(&bytes).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn attest_carries_the_generated_magic() {
        let a = Attest::new(
            name(1),
            Tpm2bData::from_slice(b"qualifier").unwrap(),
            clock(),
            0x0001_0000_0000_0000,
            Attested::Certify {
                name: name(2),
                qualified_name: name(3),
            },
        );
        let bytes = a.to_bytes();
        assert_eq!(&bytes[0..4], &TPM_GENERATED_VALUE.to_be_bytes());
        assert_eq!(&bytes[4..6], &st::ATTEST_CERTIFY.to_be_bytes());
        assert_eq!(Attest::from_bytes(&bytes).unwrap(), a);
    }

    #[test]
    fn attest_rejects_a_wrong_magic() {
        let a = Attest::new(
            name(1),
            Tpm2bData::empty(),
            clock(),
            0,
            Attested::NvDigest {
                index_name: name(4),
                nv_digest: Tpm2bDigest::from_slice(&[7u8; 32]).unwrap(),
            },
        );
        let mut bytes = a.to_bytes();
        bytes[0] ^= 0xff;
        assert_eq!(Attest::from_bytes(&bytes).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn attest_rejects_an_unknown_type() {
        let a = Attest::new(name(1), Tpm2bData::empty(), clock(), 0, Attested::Time {
            time: TimeInfo::default(),
            firmware_version: 5,
        });
        let mut bytes = a.to_bytes();
        bytes[4..6].copy_from_slice(&0x8099u16.to_be_bytes());
        assert_eq!(Attest::from_bytes(&bytes).unwrap_err(), TpmRc(rc::SELECTOR));
    }

    #[test]
    fn every_attest_variant_round_trips() {
        let mut sel = PcrSelect::none();
        sel.select(0);
        let variants = vec![
            Attested::Certify {
                name: name(1),
                qualified_name: name(2),
            },
            Attested::Creation {
                object_name: name(3),
                creation_hash: Tpm2bDigest::from_slice(&[1u8; 32]).unwrap(),
            },
            Attested::Quote {
                pcr_select: TpmlPcrSelection::new(vec![PcrSelection::new(alg::SHA256, sel)])
                    .unwrap(),
                pcr_digest: Tpm2bDigest::from_slice(&[2u8; 32]).unwrap(),
            },
            Attested::CommandAudit {
                audit_counter: 9,
                digest_alg: alg::SHA256,
                audit_digest: Tpm2bDigest::from_slice(&[3u8; 32]).unwrap(),
                command_digest: Tpm2bDigest::from_slice(&[4u8; 32]).unwrap(),
            },
            Attested::SessionAudit {
                exclusive_session: true,
                session_digest: Tpm2bDigest::from_slice(&[5u8; 32]).unwrap(),
            },
            Attested::Time {
                time: TimeInfo {
                    time: 42,
                    clock_info: clock(),
                },
                firmware_version: 7,
            },
            Attested::Nv {
                index_name: name(5),
                offset: 16,
                nv_contents: Tpm2bMaxNvBuffer::from_slice(&[6u8; 8]).unwrap(),
            },
            Attested::NvDigest {
                index_name: name(6),
                nv_digest: Tpm2bDigest::from_slice(&[7u8; 32]).unwrap(),
            },
        ];
        for v in variants {
            let a = Attest::new(name(0), Tpm2bData::empty(), clock(), 1, v.clone());
            let bytes = a.to_bytes();
            let back = Attest::from_bytes(&bytes).unwrap();
            assert_eq!(back.attested, v);
            assert_eq!(back.attested.selector(), v.selector());
        }
    }

    #[test]
    fn creation_data_round_trip() {
        let mut sel = PcrSelect::none();
        sel.select(7);
        let c = CreationData {
            pcr_select: TpmlPcrSelection::new(vec![PcrSelection::new(alg::SHA256, sel)]).unwrap(),
            pcr_digest: Tpm2bDigest::from_slice(&[1u8; 32]).unwrap(),
            locality: LocalityAttributes(LocalityAttributes::ZERO),
            parent_name_alg: alg::SHA256,
            parent_name: name(1),
            parent_qualified_name: name(2),
            outside_info: Tpm2bData::from_slice(b"info").unwrap(),
        };
        assert_eq!(CreationData::from_bytes(&c.to_bytes()).unwrap(), c);
        let wrapped = Tpm2bCreationData { creation_data: c };
        assert_eq!(
            Tpm2bCreationData::from_bytes(&wrapped.to_bytes()).unwrap(),
            wrapped
        );
    }
}
