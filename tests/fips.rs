//! End to end tests for the FIPS self tests.
//!
//! The self tests matter through the command interface, so these drive them
//! the way a caller would: TPM2_SelfTest, TPM2_IncrementalSelfTest and
//! TPM2_GetTestResult over real command buffers, plus the pair-wise
//! consistency test that runs whenever a key is generated.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::constants::{alg, cc, rc, rh, st};
use swtrust::tpm::device::Tpm;
use swtrust::tpm::marshal::{Reader, Writer};

struct Harness {
    tpm: Tpm,
    dir: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn harness(tag: &str) -> Harness {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "swtrust-fips-{tag}-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
    let tpm = Tpm::new(dir.join("state"), logger).unwrap();
    tpm.power_on();
    Harness { tpm, dir }
}

struct Answer {
    code: u32,
    body: Vec<u8>,
}

fn command(tag: u16, code: u32, handles: &[u32], auth: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let mut body = Writer::new();
    for h in handles {
        body.u32(*h);
    }
    if let Some(a) = auth {
        body.u32(a.len() as u32);
        body.bytes(a);
    }
    body.bytes(params);
    let body = body.finish().unwrap();
    let mut w = Writer::new();
    w.u16(tag);
    w.u32((10 + body.len()) as u32);
    w.u32(code);
    w.bytes(&body);
    w.finish().unwrap()
}

fn send(h: &Harness, buf: &[u8]) -> Answer {
    let out = h.tpm.execute(0, buf);
    Answer {
        code: u32::from_be_bytes([out[6], out[7], out[8], out[9]]),
        body: out[10..].to_vec(),
    }
}

fn startup(h: &Harness) {
    let r = send(h, &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS, "startup failed");
}

#[test]
fn a_full_self_test_passes_and_reports_the_image_digest() {
    let h = harness("full");
    startup(&h);

    // TPM2_SelfTest(fullTest = YES) is the periodic self test both standards
    // ask for, so it runs everything whether or not it has run before.
    let r = send(&h, &command(st::NO_SESSIONS, cc::SelfTest, &[], None, &[0x01]));
    assert_eq!(r.code, rc::SUCCESS, "full self test -> {:08x}", r.code);

    // TPM2_GetTestResult reports success and carries the digest the
    // pre-operational integrity test produced.
    let r = send(&h, &command(st::NO_SESSIONS, cc::GetTestResult, &[], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap();
    assert_eq!(size, 32, "the integrity digest is a SHA-256 value");
    let digest = reader.take(32).unwrap().to_vec();
    assert_ne!(digest, vec![0u8; 32]);
    assert_eq!(reader.u32().unwrap(), rc::SUCCESS);

    // The digest is of the running image, so it does not change between runs
    // of the test.
    let r = send(&h, &command(st::NO_SESSIONS, cc::SelfTest, &[], None, &[0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = send(&h, &command(st::NO_SESSIONS, cc::GetTestResult, &[], None, &[]));
    let mut reader = Reader::new(&r.body);
    reader.u16().unwrap();
    assert_eq!(reader.take(32).unwrap(), &digest[..]);
}

#[test]
fn a_partial_self_test_is_accepted() {
    let h = harness("partial");
    startup(&h);
    // fullTest = NO tests only what has not been tested. Power on ran the
    // whole set, so there is nothing left to do and the answer is success.
    let r = send(&h, &command(st::NO_SESSIONS, cc::SelfTest, &[], None, &[0x00]));
    assert_eq!(r.code, rc::SUCCESS, "partial self test -> {:08x}", r.code);
}

#[test]
fn incremental_self_test_reports_what_it_does_not_cover() {
    let h = harness("incremental");
    startup(&h);

    // An algorithm a known answer test covers is reported as done, so the
    // returned list is empty.
    let mut p = Writer::new();
    p.u32(2);
    p.u16(alg::SHA256);
    p.u16(alg::RSA);
    let r = send(
        &h,
        &command(
            st::NO_SESSIONS,
            cc::IncrementalSelfTest,
            &[],
            None,
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "-> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    assert_eq!(reader.u32().unwrap(), 0, "nothing should be left to test");

    // An implemented algorithm that no known answer test covers is reported
    // as still to do rather than silently claimed.
    let mut p = Writer::new();
    p.u32(1);
    p.u16(alg::XOR);
    let r = send(
        &h,
        &command(
            st::NO_SESSIONS,
            cc::IncrementalSelfTest,
            &[],
            None,
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    assert_eq!(reader.u32().unwrap(), 1);
    assert_eq!(reader.u16().unwrap(), alg::XOR);

    // An algorithm this TPM does not implement is refused.
    let mut p = Writer::new();
    p.u32(1);
    p.u16(0x7fff);
    let r = send(
        &h,
        &command(
            st::NO_SESSIONS,
            cc::IncrementalSelfTest,
            &[],
            None,
            &p.finish().unwrap(),
        ),
    );
    assert_ne!(r.code, rc::SUCCESS, "an unimplemented algorithm is refused");
}

#[test]
fn a_failed_self_test_puts_the_tpm_in_failure_mode() {
    // Failure mode is what both standards require of a module whose self test
    // failed: no further cryptographic output, and an error indicator. There
    // is no way to corrupt an algorithm from outside, so the state is set the
    // way a failed test sets it and the consequences are checked.
    let h = harness("failed");
    startup(&h);
    h.tpm.with_state_mut(|s| {
        s.failure_mode = true;
        s.self_test_done = false;
        s.test_failure = Some("SHA-256".to_string());
    });

    // TPM2_GetRandom produces cryptographic output, so it is refused.
    let mut p = Writer::new();
    p.u16(16);
    let r = send(
        &h,
        &command(st::NO_SESSIONS, cc::GetRandom, &[], None, &p.finish().unwrap()),
    );
    assert_eq!(r.code, rc::FAILURE, "-> {:08x}", r.code);

    // TPM2_GetTestResult still answers, and says which test failed.
    let r = send(&h, &command(st::NO_SESSIONS, cc::GetTestResult, &[], None, &[]));
    assert_eq!(r.code, rc::SUCCESS, "GetTestResult -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap() as usize;
    assert_eq!(reader.take(size).unwrap(), b"SHA-256");
    assert_eq!(reader.u32().unwrap(), rc::FAILURE);
}

#[test]
fn a_generated_key_has_passed_its_pairwise_test() {
    // TPM2_CreatePrimary generates a key pair, so the pair-wise consistency
    // test of FIPS 140-3 Table 40 runs inside it. A key that came back is a
    // key that passed.
    let h = harness("pairwise");
    startup(&h);

    for (name, template) in [("ecc", ecc_signing_template()), ("rsa", rsa_signing_template())] {
        let mut p = Writer::new();
        p.u16(4);
        p.u16(0);
        p.u16(0);
        p.u16(template.len() as u16);
        p.bytes(&template);
        p.u16(0); // outsideInfo
        p.u32(0); // creationPCR
        let auth = [0x40u8, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00];
        let r = send(
            &h,
            &command(
                st::SESSIONS,
                cc::CreatePrimary,
                &[rh::OWNER],
                Some(&auth),
                &p.finish().unwrap(),
            ),
        );
        assert_eq!(r.code, rc::SUCCESS, "{name} primary -> {:08x}", r.code);
    }
}

#[test]
fn self_test_refuses_a_value_that_is_not_yes_or_no() {
    // Part 2 Table 48 makes fullTest a TPMI_YES_NO, which is exactly 0 or 1.
    let h = harness("yesno");
    startup(&h);
    for good in [0u8, 1] {
        let r = send(&h, &command(st::NO_SESSIONS, cc::SelfTest, &[], None, &[good]));
        assert_eq!(r.code, rc::SUCCESS, "fullTest {good} -> {:08x}", r.code);
    }
    for bad in [2u8, 0x7f, 0xff] {
        let r = send(&h, &command(st::NO_SESSIONS, cc::SelfTest, &[], None, &[bad]));
        assert_ne!(r.code, rc::SUCCESS, "fullTest {bad} was accepted");
    }
}

#[test]
fn an_ephemeral_key_is_pair_wise_tested_too() {
    // TPM2_EC_Ephemeral generates a key pair that never becomes an object, so
    // the test has to live in the generator rather than in object creation.
    // A key that came back is one that passed.
    let h = harness("ephemeral");
    startup(&h);
    let mut p = Writer::new();
    p.u16(0x0003); // NIST P-256
    let r = send(
        &h,
        &command(st::NO_SESSIONS, cc::EC_Ephemeral, &[], None, &p.finish().unwrap()),
    );
    assert_eq!(r.code, rc::SUCCESS, "-> {:08x}", r.code);
}

#[test]
fn commit_generates_a_point_that_passed_its_pairwise_test() {
    // TPM2_Commit builds an ephemeral pair, which used to be assembled from a
    // scalar and a multiplication rather than through ecc::generate, so it had
    // no pair-wise consistency test. The point it returns has to be a real one.
    let h = harness("commit");
    startup(&h);

    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010); // symmetric NULL
    t.u16(0x001C); // TPM_ALG_ECDAA, which TPM2_Commit needs
    t.u16(alg::SHA256);
    t.u16(0x0003); // NIST P-256
    t.u16(0x0010);
    t.u16(0);
    t.u16(0);
    let template = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let auth = [0x40u8, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00];
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::CreatePrimary,
            &[rh::OWNER],
            Some(&auth),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let handle = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    // P1 given as a point with two empty coordinates, then s2 and y2 absent.
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(0);
    p.u16(0);
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::Commit,
            &[handle],
            Some(&auth),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);

    // Read past K and L to E, which is the generated point.
    let mut rd = Reader::new(&r.body);
    rd.u32().unwrap(); // parameterSize
    for _ in 0..2 {
        let n = rd.u16().unwrap() as usize;
        rd.take(n).unwrap();
    }
    let e_size = rd.u16().unwrap() as usize;
    let e = rd.take(e_size).unwrap().to_vec();
    let mut er = Reader::new(&e);
    let xn = er.u16().unwrap() as usize;
    let x = er.take(xn).unwrap().to_vec();
    let yn = er.u16().unwrap() as usize;
    let y = er.take(yn).unwrap().to_vec();
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);

    // The point it produced has to be on the curve, which is what the
    // pair-wise consistency test inside the generator checks.
    let curve = swtrust::tpm::crypto::ecc::Curve::new(0x0003).unwrap();
    assert!(
        swtrust::tpm::crypto::ecc::Point::from_coordinates(&curve, &x, &y).is_ok(),
        "TPM2_Commit returned a point that is not on the curve"
    );
}

fn ecc_signing_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010); // symmetric NULL
    t.u16(0x0018); // ECDSA
    t.u16(alg::SHA256);
    t.u16(0x0003); // NIST P-256
    t.u16(0x0010); // kdf NULL
    t.u16(0);
    t.u16(0);
    t.finish().unwrap()
}

fn rsa_signing_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(alg::RSA);
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010); // symmetric NULL
    t.u16(0x0014); // RSASSA
    t.u16(alg::SHA256);
    t.u16(2048);
    t.u32(0);
    t.u16(0);
    t.finish().unwrap()
}
