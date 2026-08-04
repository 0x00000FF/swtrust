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
use swtrust::tpm::constants::{alg, cap, cc, hc, rc, rh, st};
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

    /// Send a command whose one handle is authorized with an empty password.
    fn send_authorized(&self, code: u32, handle: u32, params: &[u8]) -> Vec<u8> {
        let mut auth = rh::RS_PW.to_be_bytes().to_vec();
        auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
        auth.push(0x01); // continueSession
        auth.extend_from_slice(&0u16.to_be_bytes()); // password

        let mut body = handle.to_be_bytes().to_vec();
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth);
        body.extend_from_slice(params);

        let mut buf = st::SESSIONS.to_be_bytes().to_vec();
        buf.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        buf.extend_from_slice(&code.to_be_bytes());
        buf.extend_from_slice(&body);
        self.tpm.execute(0, &buf)
    }

    /// The same for a command whose handle is a PCR.
    fn send_pcr(&self, code: u32, index: u32, params: &[u8]) -> Vec<u8> {
        self.send_authorized(code, hc::PCR_FIRST + index, params)
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

#[test]
fn a_sha1_bank_can_be_allocated_extended_and_read() {
    // The tables above say SHA-1 is available; this drives it through the
    // commands that use a PCR bank, because a bank that can be named and one
    // that works are not the same claim.
    let h = Harness::new("bank");

    // TPM2_PCR_Allocate names the banks the TPM comes up with after a reset.
    let mut body = 2u32.to_be_bytes().to_vec();
    for a in [alg::SHA1, alg::SHA256] {
        body.extend_from_slice(&a.to_be_bytes());
        body.push(3);
        body.extend_from_slice(&[0xff, 0xff, 0xff]);
    }
    let r = h.send_authorized(cc::PCR_Allocate, rh::PLATFORM, &body);
    assert_eq!(
        code_of(&r),
        rc::SUCCESS,
        "a SHA-1 bank was refused: {:#x}",
        code_of(&r)
    );

    // The allocation takes effect at the next reset, so the TPM is restarted.
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(cc::Startup, &[0x00, 0x00]);
    assert_eq!(code_of(&r), rc::SUCCESS);

    // Extend PCR 11 in the SHA-1 bank, which is what BitLocker reads.
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.extend_from_slice(&[0xab; 20]);
    let r = h.send_pcr(cc::PCR_Extend, 11, &body);
    assert_eq!(
        code_of(&r),
        rc::SUCCESS,
        "a SHA-1 extend was refused: {:#x}",
        code_of(&r)
    );

    // Read it back and check the register moved.
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.push(3);
    body.extend_from_slice(&[0x00, 0x08, 0x00]);
    let r = h.send(cc::PCR_Read, &body);
    assert_eq!(code_of(&r), rc::SUCCESS);
    // pcrUpdateCounter, the selection echoed back, then the digest list.
    let digest = &r[r.len() - 20..];
    assert_ne!(digest, [0u8; 20], "the SHA-1 register did not change");
}

#[test]
fn an_object_may_be_named_with_sha1_and_sign_with_it() {
    // The nameAlg of BitLocker's sealed object is TPM_ALG_SHA1 and the key a
    // virtual smart card certifies itself with signs RSASSA over SHA-1. Both
    // go through TPM2_CreatePrimary and TPM2_Sign here rather than through the
    // encoder alone.
    let h = Harness::new("sha1-key");

    let mut t = Vec::new();
    t.extend_from_slice(&0x0001u16.to_be_bytes()); // TPM_ALG_RSA
    t.extend_from_slice(&alg::SHA1.to_be_bytes()); // nameAlg
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    t.extend_from_slice(&0x0004_0072u32.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes()); // authPolicy
    t.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric TPM_ALG_NULL
    t.extend_from_slice(&0x0014u16.to_be_bytes()); // scheme TPM_ALG_RSASSA
    t.extend_from_slice(&alg::SHA1.to_be_bytes()); // over SHA-1
    t.extend_from_slice(&2048u16.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes()); // exponent
    t.extend_from_slice(&0u16.to_be_bytes()); // unique

    let mut body = 4u16.to_be_bytes().to_vec(); // inSensitive
    body.extend_from_slice(&0u16.to_be_bytes()); // userAuth
    body.extend_from_slice(&0u16.to_be_bytes()); // data
    body.extend_from_slice(&(t.len() as u16).to_be_bytes());
    body.extend_from_slice(&t);
    body.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo
    body.extend_from_slice(&0u32.to_be_bytes()); // creationPCR
    let r = h.send_authorized(cc::CreatePrimary, rh::OWNER, &body);
    assert_eq!(
        code_of(&r),
        rc::SUCCESS,
        "a key named with SHA-1 was refused: {:#x}",
        code_of(&r)
    );
    let handle = u32::from_be_bytes([r[10], r[11], r[12], r[13]]);
    assert_eq!(handle >> 24, 0x80, "a transient handle was expected");

    // Sign a SHA-1 digest with it, which is the path that needed the
    // DigestInfo prefix.
    let mut body = 20u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0xcd; 20]);
    body.extend_from_slice(&0x0010u16.to_be_bytes()); // inScheme TPM_ALG_NULL
    body.extend_from_slice(&0x8024u16.to_be_bytes()); // a null validation ticket
    body.extend_from_slice(&rh::NULL.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    let r = h.send_authorized(cc::Sign, handle, &body);
    assert_eq!(
        code_of(&r),
        rc::SUCCESS,
        "an RSASSA signature over SHA-1 was refused: {:#x}",
        code_of(&r)
    );
    // A response to a command with sessions carries parameterSize before the
    // parameters, so the TPMT_SIGNATURE starts four octets further in: the
    // algorithm, its hash, then the signature.
    assert_eq!(u16::from_be_bytes([r[14], r[15]]), 0x0014);
    assert_eq!(u16::from_be_bytes([r[16], r[17]]), alg::SHA1);
    assert_eq!(u16::from_be_bytes([r[18], r[19]]), 256);
}
