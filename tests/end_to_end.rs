//! End to end tests that drive the TPM through its command interface.
//!
//! Every test builds real command buffers, hands them to the device, and reads
//! the response buffers back, so the header handling, dispatch, authorization
//! and marshalling are all exercised together.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::constants::{alg, cap, cc, hc, pt, rc, rh, st, su};
use swtrust::tpm::device::Tpm;
use swtrust::tpm::marshal::{Reader, Writer};

/// A TPM with its state in a fresh temporary directory.
struct Harness {
    tpm: Tpm,
    dir: std::path::PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "swtrust-e2e-{tag}-{}-{}",
            std::process::id(),
            swtrust::util::time::unix_millis_now()
        ));
        let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
        let tpm = Tpm::new(dir.join("state"), logger).unwrap();
        tpm.power_on();
        Harness { tpm, dir }
    }

    fn started(tag: &str) -> Harness {
        let h = Harness::new(tag);
        let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[
            0x00, 0x00,
        ]));
        assert_eq!(r.code, rc::SUCCESS, "startup failed");
        h
    }

    fn send(&self, buf: &[u8]) -> Answer {
        Answer::parse(&self.tpm.execute(0, buf))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// A parsed response.
struct Answer {
    tag: u16,
    code: u32,
    body: Vec<u8>,
}

impl Answer {
    fn parse(buf: &[u8]) -> Answer {
        assert!(buf.len() >= 10, "response is too short: {buf:02x?}");
        let tag = u16::from_be_bytes([buf[0], buf[1]]);
        let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        assert_eq!(size, buf.len(), "responseSize does not match the buffer");
        let code = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        Answer {
            tag,
            code,
            body: buf[10..].to_vec(),
        }
    }
}

/// Build a command buffer.
fn command(
    tag: u16,
    code: u32,
    handles: &[u32],
    auth: Option<&[u8]>,
    params: &[u8],
) -> Vec<u8> {
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

/// A password authorization area.
fn password(pw: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(rh::RS_PW);
    w.u16(0); // nonce
    w.u8(0x01); // continueSession
    w.u16(pw.len() as u16);
    w.bytes(pw);
    w.finish().unwrap()
}

#[test]
fn a_command_before_startup_is_refused() {
    let h = Harness::new("prestartup");
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0x00, 0x08]));
    assert_eq!(r.code, rc::INITIALIZE);
    assert_eq!(r.tag, st::NO_SESSIONS);
}

#[test]
fn startup_then_get_random_returns_the_requested_size() {
    let h = Harness::started("random");
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0x00, 0x20]));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap();
    assert_eq!(size, 32);
    assert_eq!(reader.take(32).unwrap().len(), 32);
    assert!(reader.is_empty());
}

#[test]
fn get_random_is_capped_at_the_largest_digest() {
    let h = Harness::started("randomcap");
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0xff, 0xff]));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    assert_eq!(reader.u16().unwrap(), 64);
}

#[test]
fn successive_random_values_differ() {
    let h = Harness::started("randomdiff");
    let cmd = command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0x00, 0x20]);
    let a = h.send(&cmd).body;
    let b = h.send(&cmd).body;
    assert_ne!(a, b);
}

#[test]
fn get_capability_reports_the_manufacturer_and_version() {
    let h = Harness::started("capability");
    let mut p = Writer::new();
    p.u32(cap::TPM_PROPERTIES);
    p.u32(pt::MANUFACTURER);
    // Enough properties to reach both firmware version words, which follow the
    // four vendor strings and the vendor TPM type.
    p.u32(16);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::GetCapability,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);

    let mut reader = Reader::new(&r.body);
    let _more = reader.u8().unwrap();
    assert_eq!(reader.u32().unwrap(), cap::TPM_PROPERTIES);
    let count = reader.u32().unwrap();
    assert!(count >= 3);

    let mut found = std::collections::BTreeMap::new();
    for _ in 0..count {
        let property = reader.u32().unwrap();
        let value = reader.u32().unwrap();
        found.insert(property, value);
    }
    // "SWT" with a null terminator.
    assert_eq!(found.get(&pt::MANUFACTURER), Some(&0x5357_5400));
    assert_eq!(&found[&pt::MANUFACTURER].to_be_bytes(), b"SWT\0");
    // Firmware version 1.0.0.0.
    assert_eq!(found.get(&pt::FIRMWARE_VERSION_1), Some(&0x0001_0000));
    assert_eq!(found.get(&pt::FIRMWARE_VERSION_2), Some(&0x0000_0000));
}

#[test]
fn get_capability_reports_the_implemented_commands() {
    let h = Harness::started("capcommands");
    let mut p = Writer::new();
    p.u32(cap::COMMANDS);
    p.u32(cc::FIRST);
    p.u32(255);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::GetCapability,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let _more = reader.u8().unwrap();
    assert_eq!(reader.u32().unwrap(), cap::COMMANDS);
    let count = reader.u32().unwrap();
    assert!(count > 100, "only {count} commands reported");
}

#[test]
fn pcr_read_and_extend_change_the_register() {
    let h = Harness::started("pcr");

    // Select PCR 0 in the SHA-256 bank.
    let mut p = Writer::new();
    p.u32(1); // count
    p.u16(alg::SHA256);
    p.u8(3);
    p.bytes(&[0x01, 0x00, 0x00]);
    let read = command(st::NO_SESSIONS, cc::PCR_Read, &[], None, &p.finish().unwrap());

    let r = h.send(&read);
    assert_eq!(r.code, rc::SUCCESS);
    let before = r.body.clone();
    // A freshly reset PCR 0 is all zeros.
    assert!(before.ends_with(&[0u8; 32]));

    // Extend PCR 0 with a digest of ones.
    let mut p = Writer::new();
    p.u32(1); // one digest
    p.u16(alg::SHA256);
    p.bytes(&[0x11u8; 32]);
    let extend = command(
        st::SESSIONS,
        cc::PCR_Extend,
        &[hc::PCR_FIRST],
        Some(&password(b"")),
        &p.finish().unwrap(),
    );
    let r = h.send(&extend);
    assert_eq!(r.code, rc::SUCCESS, "extend failed: {:08x}", r.code);

    let r = h.send(&read);
    assert_eq!(r.code, rc::SUCCESS);
    assert_ne!(r.body, before);
    // The new value is the hash of the old value and the extended digest.
    let expected = swtrust::tpm::crypto::hash::digest_parts(
        alg::SHA256,
        &[&[0u8; 32], &[0x11u8; 32]],
    )
    .unwrap();
    assert!(r.body.ends_with(&expected));
}

#[test]
fn pcr_extend_from_a_locality_that_may_not_is_refused() {
    let h = Harness::started("pcrlocality");
    let mut p = Writer::new();
    p.u32(1);
    p.u16(alg::SHA256);
    p.bytes(&[0x11u8; 32]);
    let extend = command(
        st::SESSIONS,
        cc::PCR_Extend,
        &[hc::PCR_FIRST + 17],
        Some(&password(b"")),
        &p.finish().unwrap(),
    );
    // Locality 0 may not extend PCR 17.
    let response = h.tpm.execute(0, &extend);
    assert_eq!(Answer::parse(&response).code, rc::LOCALITY);
    // Locality 2 may.
    let response = h.tpm.execute(2, &extend);
    assert_eq!(Answer::parse(&response).code, rc::SUCCESS);
}

#[test]
fn read_clock_reports_the_reset_count() {
    let h = Harness::started("clock");
    let r = h.send(&command(st::NO_SESSIONS, cc::ReadClock, &[], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let _time = reader.u64().unwrap();
    let _clock = reader.u64().unwrap();
    assert_eq!(reader.u32().unwrap(), 1, "resetCount after one startup");
    assert_eq!(reader.u32().unwrap(), 0, "restartCount");
    assert_eq!(reader.u8().unwrap(), 1, "safe");
}

#[test]
fn a_bad_tag_is_reported_as_tpm_rc_tag() {
    let h = Harness::started("badtag");
    let mut w = Writer::new();
    w.u16(0x00c1);
    w.u32(10);
    w.u32(cc::GetRandom);
    let r = h.send(&w.finish().unwrap());
    assert_eq!(r.code, rc::TAG);
    assert_eq!(r.tag, st::NO_SESSIONS);
}

#[test]
fn a_size_that_disagrees_with_the_buffer_is_refused() {
    let h = Harness::started("badsize");
    let mut w = Writer::new();
    w.u16(st::NO_SESSIONS);
    w.u32(99);
    w.u32(cc::GetRandom);
    w.u16(8);
    let r = h.send(&w.finish().unwrap());
    assert_eq!(r.code, rc::COMMAND_SIZE);
}

#[test]
fn an_unimplemented_command_code_is_refused() {
    let h = Harness::started("badcode");
    let r = h.send(&command(st::NO_SESSIONS, 0x0000_0123, &[], None, &[]));
    assert_eq!(r.code, rc::COMMAND_CODE);
}

#[test]
fn a_session_response_carries_a_session_area() {
    let h = Harness::started("sessionarea");
    let mut p = Writer::new();
    p.u32(1);
    p.u16(alg::SHA256);
    p.bytes(&[0x22u8; 32]);
    let r = h.send(&command(
        st::SESSIONS,
        cc::PCR_Extend,
        &[hc::PCR_FIRST],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(r.tag, st::SESSIONS);
    // parameterSize of zero followed by the response session area.
    let mut reader = Reader::new(&r.body);
    assert_eq!(reader.u32().unwrap(), 0);
    assert_eq!(reader.take_rest(), &[0x00, 0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn the_state_file_is_written_and_reloaded() {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "swtrust-e2e-persist-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let state_dir = dir.join("state");

    {
        let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
        let tpm = Tpm::new(&state_dir, logger).unwrap();
        tpm.power_on();
        let r = Answer::parse(&tpm.execute(
            0,
            &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]),
        ));
        assert_eq!(r.code, rc::SUCCESS);
        tpm.power_off();
    }

    // The state file exists and is hex text.
    let path = state_dir.join("tpm-state.hex");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("# swtrust TPM state v1"));
    assert!(text.lines().skip(1).all(|l| l.chars().all(|c| c.is_ascii_hexdigit())));

    {
        let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
        let tpm = Tpm::new(&state_dir, logger).unwrap();
        tpm.power_on();
        let r = Answer::parse(&tpm.execute(
            0,
            &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]),
        ));
        assert_eq!(r.code, rc::SUCCESS);
        // The reset count carried over and advanced again.
        let r = Answer::parse(&tpm.execute(
            0,
            &command(st::NO_SESSIONS, cc::ReadClock, &[], None, &[]),
        ));
        let mut reader = Reader::new(&r.body);
        let _time = reader.u64().unwrap();
        let _clock = reader.u64().unwrap();
        assert_eq!(reader.u32().unwrap(), 2, "resetCount across a power cycle");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_command_log_records_every_exchange() {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "swtrust-e2e-log-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let log_dir = dir.join("logs");
    {
        let logger = Arc::new(Logger::new(&log_dir, false).unwrap());
        let tpm = Tpm::new(dir.join("state"), logger.clone()).unwrap();
        tpm.power_on();
        let cmd = command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]);
        let rsp = tpm.execute(0, &cmd);
        logger.command(1, 0, &cmd);
        logger.response(1, &rsp);
    }
    let date = swtrust::util::time::now().date_string();
    let text = std::fs::read_to_string(log_dir.join(format!("{date}.log"))).unwrap();
    assert!(text.contains("cc=0x00000144(TPM2_Startup)"), "{text}");
    assert!(text.contains("rc=0x00000000"), "{text}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn shutdown_and_restart_keeps_the_state() {
    let h = Harness::started("shutdown");
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    // After a shutdown the TPM will not take commands until it starts again.
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0x00, 0x08]));
    assert_eq!(r.code, rc::INITIALIZE);
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0x00, 0x08]));
    assert_eq!(r.code, rc::SUCCESS);
}

#[test]
fn self_test_and_test_result() {
    let h = Harness::started("selftest");
    let r = h.send(&command(st::NO_SESSIONS, cc::SelfTest, &[], None, &[0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::GetTestResult, &[], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap();
    let _data = reader.take(size as usize).unwrap();
    assert_eq!(reader.u32().unwrap(), rc::SUCCESS);
}

#[test]
fn ecc_parameters_describe_p256() {
    let h = Harness::started("eccparms");
    let mut p = Writer::new();
    p.u16(swtrust::tpm::constants::curve::NIST_P256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ECC_Parameters,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    assert_eq!(reader.u16().unwrap(), swtrust::tpm::constants::curve::NIST_P256);
    assert_eq!(reader.u16().unwrap(), 256);
}

#[test]
fn an_unsupported_curve_is_refused() {
    let h = Harness::started("badcurve");
    let mut p = Writer::new();
    p.u16(swtrust::tpm::constants::curve::BN_P256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ECC_Parameters,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::CURVE & 0x03f);
}

#[test]
fn the_vendor_test_command_echoes_its_input() {
    let h = Harness::started("vendor");
    let mut p = Writer::new();
    p.u16(4);
    p.bytes(b"ping");
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::Vendor_TCG_Test,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(r.body, vec![0x00, 0x04, b'p', b'i', b'n', b'g']);
}
