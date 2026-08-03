//! Conformance to the PC Client Platform TPM Profile 1.07.
//!
//! The Library specification says what a TPM may do. The platform profile says
//! what a PC Client TPM must do, must not do, and must report. Each test here
//! names the clause it comes from and checks the value that clause fixes, so
//! the profile is measured against the TPM rather than against a description of
//! it.
//!
//! Where the profile fixes something a caller can observe, it is read back
//! through TPM2_GetCapability, because that is what a verifier would do.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::config;
use swtrust::tpm::constants::{alg, cap, cc, curve, pt, rc, st};
use swtrust::tpm::device::Tpm;

struct Harness {
    tpm: Tpm,
    dir: std::path::PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "swtrust-ptp-{tag}-{}-{}",
            std::process::id(),
            swtrust::util::time::unix_millis_now()
        ));
        let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
        let tpm = Tpm::new(dir.join("state"), logger).unwrap();
        tpm.power_on();
        let h = Harness { tpm, dir };
        let r = h.send(cc::Startup, &[0x00, 0x00]);
        assert_eq!(code_of(&r), rc::SUCCESS, "startup failed");
        h
    }

    fn send(&self, command: u32, body: &[u8]) -> Vec<u8> {
        let mut v = st::NO_SESSIONS.to_be_bytes().to_vec();
        v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        v.extend_from_slice(&command.to_be_bytes());
        v.extend_from_slice(body);
        self.tpm.execute(0, &v)
    }

    /// Every TPM_PT this TPM reports, as property and value.
    fn properties(&self) -> Vec<(u32, u32)> {
        let mut body = cap::TPM_PROPERTIES.to_be_bytes().to_vec();
        body.extend_from_slice(&pt::PT_FIXED.to_be_bytes());
        body.extend_from_slice(&256u32.to_be_bytes());
        let r = self.send(cc::GetCapability, &body);
        assert_eq!(code_of(&r), rc::SUCCESS);

        // moreData, then the capability, then a counted list of pairs.
        let count = u32::from_be_bytes(r[15..19].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let at = 19 + i * 8;
            out.push((
                u32::from_be_bytes(r[at..at + 4].try_into().unwrap()),
                u32::from_be_bytes(r[at + 4..at + 8].try_into().unwrap()),
            ));
        }
        out
    }

    fn property(&self, which: u32) -> u32 {
        self.properties()
            .into_iter()
            .find(|(p, _)| *p == which)
            .unwrap_or_else(|| panic!("property {which:#010x} is not reported"))
            .1
    }

    /// Every algorithm this TPM reports as implemented.
    fn algorithms(&self) -> Vec<u16> {
        let mut body = cap::ALGS.to_be_bytes().to_vec();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&256u32.to_be_bytes());
        let r = self.send(cc::GetCapability, &body);
        assert_eq!(code_of(&r), rc::SUCCESS);
        let count = u32::from_be_bytes(r[15..19].try_into().unwrap()) as usize;
        (0..count)
            .map(|i| {
                let at = 19 + i * 6;
                u16::from_be_bytes(r[at..at + 2].try_into().unwrap())
            })
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn code_of(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]])
}

/// Clause 4.2, the platform-specific values the profile fixes exactly.
#[test]
fn the_platform_specific_properties_have_the_values_the_profile_fixes() {
    let h = Harness::new("props");
    for (name, which, want) in [
        ("TPM_PT_PS_FAMILY_INDICATOR", pt::PS_FAMILY_INDICATOR, 0x0000_0001),
        ("TPM_PT_PS_LEVEL", pt::PS_LEVEL, 0x0000_0000),
        // The revision of the profile, not of the Library specification. The
        // clause gives the format as 0xAABBCCDD with AA and BB zero, CC the
        // major revision and DD the minor, and requires this value for 1.07.
        ("TPM_PT_PS_REVISION", pt::PS_REVISION, 0x0000_0107),
        ("TPM_PT_PS_DAY_OF_YEAR", pt::PS_DAY_OF_YEAR, 0x0000_0000),
        ("TPM_PT_PS_YEAR", pt::PS_YEAR, 0x0000_0000),
        // Described in the clause as reserved and not used.
        ("TPM_PT_VENDOR_TPM_TYPE", pt::VENDOR_TPM_TYPE, 0x0000_0000),
    ] {
        assert_eq!(h.property(which), want, "{name}");
    }
}

/// Clause 4.2, the values the profile gives a floor rather than a value.
#[test]
fn the_reported_minimums_are_at_least_what_the_profile_asks_for() {
    let h = Harness::new("minimums");
    for (name, which, least) in [
        ("TPM_PT_HR_TRANSIENT_MIN", pt::HR_TRANSIENT_MIN, 3),
        ("TPM_PT_HR_PERSISTENT_MIN", pt::HR_PERSISTENT_MIN, 9),
        ("TPM_PT_HR_LOADED_MIN", pt::HR_LOADED_MIN, 3),
        ("TPM_PT_ACTIVE_SESSIONS_MAX", pt::ACTIVE_SESSIONS_MAX, 64),
        ("TPM_PT_PCR_COUNT", pt::PCR_COUNT, 24),
        ("TPM_PT_PCR_SELECT_MIN", pt::PCR_SELECT_MIN, 3),
        // The size of an X.509 endorsement key certificate for an ML-KEM-1024
        // key signed with an ML-DSA-87 key, together with its authorization.
        ("TPM_PT_NV_INDEX_MAX", pt::NV_INDEX_MAX, 8500),
        ("TPM_PT_NV_BUFFER_MAX", pt::NV_BUFFER_MAX, 512),
    ] {
        let got = h.property(which);
        assert!(got >= least, "{name} is {got}, the profile asks for {least}");
    }
}

/// Clause 4.2 gives both PCR group counts as zero, and clause 4.7 items 5 and 6
/// give every PCR an Empty Auth and an Empty Policy, which is the same thing
/// said twice: there is no group to give a policy or an authorization value to.
#[test]
fn no_pcr_group_has_a_policy_or_an_authorization_value_of_its_own() {
    assert_eq!(config::NUM_POLICY_PCR_GROUP, 0);
    assert_eq!(config::NUM_AUTHVALUE_PCR_GROUP, 0);
}

/// Clause 4.3 Table 3 item 5: an algorithm listed as Not Allowed (N) "SHALL NOT
/// be supported".
#[test]
fn no_algorithm_the_profile_forbids_is_supported() {
    let h = Harness::new("forbidden");
    let reported = h.algorithms();
    for (name, id) in [
        ("TPM_ALG_SHA1", alg::SHA1),
        ("TPM_ALG_TDES", alg::TDES),
    ] {
        assert!(
            !reported.contains(&id),
            "{name} is reported as implemented but the profile forbids it"
        );
    }

    // Reporting is not enough on its own: the algorithm must not work either.
    let mut body = 20u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0u8; 20]);
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.extend_from_slice(&0x4000_0007u32.to_be_bytes());
    let r = h.send(cc::Hash, &body);
    assert_ne!(code_of(&r), rc::SUCCESS, "TPM2_Hash accepted SHA-1");
}

/// Clause 4.3 Table 3: the algorithms marked Mandatory (M) that this TPM
/// implements must be reported as implemented.
#[test]
fn the_mandatory_algorithms_are_reported() {
    let h = Harness::new("mandatory");
    let reported = h.algorithms();
    for (name, id) in [
        ("TPM_ALG_RSA", alg::RSA),
        ("TPM_ALG_HMAC", alg::HMAC),
        ("TPM_ALG_AES", alg::AES),
        ("TPM_ALG_MGF1", alg::MGF1),
        ("TPM_ALG_KEYEDHASH", alg::KEYEDHASH),
        ("TPM_ALG_XOR", alg::XOR),
        ("TPM_ALG_SHA256", alg::SHA256),
        ("TPM_ALG_SHA384", alg::SHA384),
        ("TPM_ALG_SHA512", alg::SHA512),
        ("TPM_ALG_RSASSA", alg::RSASSA),
        ("TPM_ALG_RSAPSS", alg::RSAPSS),
        ("TPM_ALG_OAEP", alg::OAEP),
        ("TPM_ALG_ECDSA", alg::ECDSA),
        ("TPM_ALG_ECDH", alg::ECDH),
        ("TPM_ALG_ECC", alg::ECC),
        ("TPM_ALG_SYMCIPHER", alg::SYMCIPHER),
        ("TPM_ALG_NULL", alg::NULL),
    ] {
        assert!(reported.contains(&id), "{name} is mandatory and is missing");
    }
}

/// Clause 4.3 Table 3 for TPM_ALG_RSA: "Support for 3072-bit keys is required;
/// a TPM SHALL NOT support 1024-bit keys."
#[test]
fn rsa_supports_3072_and_not_1024() {
    assert!(config::IMPLEMENTED_RSA_KEY_BITS.contains(&3072));
    assert!(!config::IMPLEMENTED_RSA_KEY_BITS.contains(&1024));
    // And nothing below can build one, so the size is refused rather than
    // merely left out of what is advertised.
    let mut r = swtrust::tpm::crypto::rand::Drbg::new(&[9u8; 48], b"ptp").unwrap();
    assert!(swtrust::tpm::crypto::rsa::generate(&mut r, 1024, 0).is_err());
}

/// Clause 4.4 Table 4: the curves marked Mandatory (M).
#[test]
fn the_mandatory_curves_are_implemented() {
    for (name, id) in [
        ("TPM_ECC_NIST_P256", curve::NIST_P256),
        ("TPM_ECC_NIST_P384", curve::NIST_P384),
    ] {
        assert!(
            config::IMPLEMENTED_CURVES.contains(&id),
            "{name} is mandatory and is missing"
        );
    }
}

/// Clause 4.7 item 3 requires SHA-256 and SHA-384, and item 3.a.i requires the
/// required algorithms to be the ones enabled by default.
#[test]
fn the_banks_allocated_by_default_are_the_ones_the_profile_requires() {
    assert!(config::DEFAULT_PCR_BANKS.contains(&alg::SHA256));
    assert!(config::DEFAULT_PCR_BANKS.contains(&alg::SHA384));

    let h = Harness::new("banks");
    let mut body = cap::PCRS.to_be_bytes().to_vec();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&16u32.to_be_bytes());
    let r = h.send(cc::GetCapability, &body);
    assert_eq!(code_of(&r), rc::SUCCESS);

    // A TPML_PCR_SELECTION: a count, then for each bank the algorithm, the
    // size of the selection and the selection itself.
    let count = u32::from_be_bytes(r[15..19].try_into().unwrap()) as usize;
    let mut at = 19;
    let mut banks = Vec::new();
    for _ in 0..count {
        let alg_id = u16::from_be_bytes(r[at..at + 2].try_into().unwrap());
        let size = r[at + 2] as usize;
        banks.push(alg_id);
        at += 3 + size;
    }
    assert!(banks.contains(&alg::SHA256), "SHA-256 must be allocated");
    assert!(banks.contains(&alg::SHA384), "SHA-384 must be allocated");
    assert!(
        !banks.contains(&alg::SHA1),
        "SHA-1 is Not Allowed, so no bank may use it"
    );
}

/// Clause 4.7 item 8: "the D-RTM PCR SHALL be PCR 17 and the S-HCRTM PCR SHALL
/// be PCR 0."
#[test]
fn the_drtm_and_hcrtm_registers_are_the_ones_the_profile_names() {
    assert_eq!(config::DRTM_PCR, 17);
    assert_eq!(config::HCRTM_PCR, 0);
}
