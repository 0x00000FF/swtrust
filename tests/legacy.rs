//! What the TPM does when it is started without `--ptp`, which is the default.
//!
//! The PC Client Platform TPM Profile 1.07 clause 4.3 Table 3 marks
//! TPM_ALG_SHA1 as Not Allowed and item 5 of that clause says such an algorithm
//! "SHALL NOT be supported". Software that runs on real TPMs has not followed:
//! BitLocker seals its volume master key in an object whose nameAlg is
//! TPM_ALG_SHA1, and the key a TPM virtual smart card certifies itself with is
//! signed with RSASSA over SHA-1. Both were seen to fail against a TPM without
//! it, so the default keeps SHA-1 and `--ptp` takes it away.
//!
//! The strict side is measured in `ptp.rs`, which runs as its own binary and
//! selects the other profile.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::config;
use swtrust::tpm::constants::{alg, cap, cc, rc, st};
use swtrust::tpm::device::Tpm;

struct Harness {
    tpm: Tpm,
    dir: std::path::PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        swtrust::tpm::profile::set(swtrust::tpm::profile::Profile::Legacy);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "swtrust-legacy-{tag}-{}-{}",
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

    fn send(&self, code: u32, params: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&st::NO_SESSIONS.to_be_bytes());
        buf.extend_from_slice(&((10 + params.len()) as u32).to_be_bytes());
        buf.extend_from_slice(&code.to_be_bytes());
        buf.extend_from_slice(params);
        self.tpm.execute(0, &buf)
    }

    /// Every algorithm TPM2_GetCapability reports.
    fn algorithms(&self) -> Vec<u16> {
        let mut out = Vec::new();
        let mut next = 0u32;
        loop {
            let mut body = cap::ALGS.to_be_bytes().to_vec();
            body.extend_from_slice(&next.to_be_bytes());
            body.extend_from_slice(&64u32.to_be_bytes());
            let r = self.send(cc::GetCapability, &body);
            assert_eq!(code_of(&r), rc::SUCCESS);
            let more = r[10] != 0;
            let count = u32::from_be_bytes([r[15], r[16], r[17], r[18]]) as usize;
            for i in 0..count {
                let at = 19 + i * 6;
                out.push(u16::from_be_bytes([r[at], r[at + 1]]));
            }
            if !more {
                return out;
            }
            next = *out.last().unwrap() as u32 + 1;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn code_of(response: &[u8]) -> u32 {
    u32::from_be_bytes([response[6], response[7], response[8], response[9]])
}

#[test]
fn sha1_is_implemented_by_default() {
    let h = Harness::new("sha1");
    assert!(
        h.algorithms().contains(&alg::SHA1),
        "SHA-1 is not reported as implemented"
    );

    // Reporting is not enough on its own: the algorithm has to work. FIPS 180-4
    // gives SHA-1("abc").
    let mut body = 3u16.to_be_bytes().to_vec();
    body.extend_from_slice(b"abc");
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.extend_from_slice(&0x4000_0007u32.to_be_bytes());
    let r = h.send(cc::Hash, &body);
    assert_eq!(code_of(&r), rc::SUCCESS, "TPM2_Hash refused SHA-1");
    assert_eq!(
        &r[12..12 + 20],
        &[
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
        ]
    );
}

#[test]
fn a_sha1_bank_may_be_allocated_but_is_not_one_of_the_defaults() {
    // Clause 4.7 item 3 fixes the banks a TPM comes up with as SHA-256 and
    // SHA-384, and that holds whichever profile is in force. Item 3.b.ii lets
    // any supported hash back a bank, so SHA-1 is available to a platform that
    // asks for it.
    assert!(!config::DEFAULT_PCR_BANKS.contains(&alg::SHA1));
    assert!(config::implemented_pcr_banks().contains(&alg::SHA1));
}

#[test]
fn a_structure_may_name_sha1() {
    // A digest or a PCR selection carrying TPM_ALG_SHA1 has to unmarshal, which
    // is a separate table from the one that computes the digest. BitLocker
    // reads PCR 11 in the SHA-1 bank, and a TPM that refused the selection
    // answered TPM_RC_HASH before any digest was reached.
    let h = Harness::new("select");
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.push(3);
    body.extend_from_slice(&[0x00, 0x08, 0x00]);
    let r = h.send(cc::PCR_Read, &body);
    assert_eq!(
        code_of(&r),
        rc::SUCCESS,
        "a selection naming SHA-1 was refused: {:#x}",
        code_of(&r)
    );
}

#[test]
fn an_rsassa_signature_over_sha1_is_available() {
    // The DigestInfo prefix of RFC 8017 section 9.2 is a third table again. A
    // TPM virtual smart card certifies its key with RSASSA over SHA-1, and
    // without the prefix TPM2_CertifyCreation answered TPM_RC_HASH.
    let digest = vec![0xabu8; 20];
    let encoded =
        swtrust::tpm::crypto::rsa::pkcs1v15_sign_encode(alg::SHA1, &digest, 256).unwrap();
    assert_eq!(encoded.len(), 256);
    assert_eq!(
        &encoded[256 - 35..256 - 20],
        &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14
        ]
    );
}
