//! End to end tests that drive the TPM through its command interface.
//!
//! Every test builds real command buffers, hands them to the device, and reads
//! the response buffers back, so the header handling, dispatch, authorization
//! and marshalling are all exercised together.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::constants::{alg, cap, cc, hc, pt, rc, rh, st};
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
fn a_trial_policy_session_accumulates_a_digest() {
    let h = Harness::started("policy");

    // TPM2_StartAuthSession with a trial session over SHA-256.
    let mut p = Writer::new();
    p.u16(32); // nonceCaller
    p.bytes(&[0xa5u8; 32]);
    p.u16(0); // no salt
    p.u8(0x03); // TPM_SE_TRIAL
    p.u16(alg::NULL); // symmetric
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "StartAuthSession -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let session = reader.u32().unwrap();
    assert_eq!(session >> 24, 0x03, "policy session handle range");
    let nonce_size = reader.u16().unwrap();
    assert_eq!(nonce_size, 32);

    // The digest starts as zeros.
    let get_digest = command(st::NO_SESSIONS, cc::PolicyGetDigest, &[session], None, &[]);
    let r = h.send(&get_digest);
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(r.body, {
        let mut v = vec![0x00, 0x20];
        v.extend_from_slice(&[0u8; 32]);
        v
    });

    // TPM2_PolicyCommandCode(TPM2_Unseal) extends it.
    let mut p = Writer::new();
    p.u32(cc::Unseal);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCommandCode,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);

    let r = h.send(&get_digest);
    assert_eq!(r.code, rc::SUCCESS);
    let expected = swtrust::tpm::crypto::hash::digest_parts(
        alg::SHA256,
        &[
            &[0u8; 32],
            &cc::PolicyCommandCode.to_be_bytes(),
            &cc::Unseal.to_be_bytes(),
        ],
    )
    .unwrap();
    assert!(r.body.ends_with(&expected), "policy digest did not match");

    // A second, different command code is refused.
    let mut p = Writer::new();
    p.u32(cc::Quote);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCommandCode,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::VALUE & 0x03f);

    // TPM2_PolicyRestart clears it again.
    let r = h.send(&command(st::NO_SESSIONS, cc::PolicyRestart, &[session], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&get_digest);
    assert!(r.body.ends_with(&[0u8; 32]));

    // TPM2_FlushContext removes the session.
    let mut p = Writer::new();
    p.u32(session);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::FlushContext,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    // The handle no longer references a session, which Part 1 clause 12.5
    // reports as TPM_RC_HANDLE against the first handle.
    let r = h.send(&get_digest);
    assert_eq!(r.code & 0x03f, rc::HANDLE & 0x03f);
}

#[test]
fn nv_define_write_and_read_round_trip() {
    let h = Harness::started("nv");
    let index = hc::NV_INDEX_FIRST + 1;

    // Define a 16 octet ordinary Index writable and readable with its own
    // authorization value.
    let mut public = Writer::new();
    public.u32(index);
    public.u16(alg::SHA256);
    public.u32(0x0000_0004 | 0x0004_0000); // AUTHWRITE | AUTHREAD
    public.u16(0); // no policy
    public.u16(16);
    let public = public.finish().unwrap();

    let mut p = Writer::new();
    p.u16(4);
    p.bytes(b"nvpw"); // the Index authorization value
    p.u16(public.len() as u16);
    p.bytes(&public);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_DefineSpace,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "NV_DefineSpace -> {:08x}", r.code);

    // Reading before a write reports that the Index is uninitialized.
    let mut p = Writer::new();
    p.u16(16);
    p.u16(0);
    let read = command(
        st::SESSIONS,
        cc::NV_Read,
        &[index, index],
        Some(&password(b"nvpw")),
        &p.finish().unwrap(),
    );
    let r = h.send(&read);
    assert_eq!(r.code, rc::NV_UNINITIALIZED);

    // Write, then read it back.
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0x5au8; 16]);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_Write,
        &[index, index],
        Some(&password(b"nvpw")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "NV_Write -> {:08x}", r.code);

    let r = h.send(&read);
    assert_eq!(r.code, rc::SUCCESS, "NV_Read -> {:08x}", r.code);
    // parameterSize, then the TPM2B, then the session area.
    let mut reader = Reader::new(&r.body);
    let param_size = reader.u32().unwrap();
    assert_eq!(param_size, 18);
    assert_eq!(reader.u16().unwrap(), 16);
    assert_eq!(reader.take(16).unwrap(), &[0x5au8; 16]);

    // The wrong authorization value is refused.
    let mut p = Writer::new();
    p.u16(16);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_Read,
        &[index, index],
        Some(&password(b"wrong")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::AUTH_FAIL & 0x03f);

    // TPM2_NV_ReadPublic reports the Index and its Name.
    let r = h.send(&command(st::NO_SESSIONS, cc::NV_ReadPublic, &[index], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);

    // Undefining it with owner authorization removes it.
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_UndefineSpace,
        &[rh::OWNER, index],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::NV_ReadPublic, &[index], None, &[]));
    assert_eq!(r.code & 0x03f, rc::HANDLE & 0x03f);
}

#[test]
fn an_nv_counter_only_advances() {
    let h = Harness::started("nvcounter");
    let index = hc::NV_INDEX_FIRST + 7;

    let mut public = Writer::new();
    public.u32(index);
    public.u16(alg::SHA256);
    // AUTHWRITE | AUTHREAD with TPM_NT_COUNTER in bits 7:4.
    public.u32(0x0000_0004 | 0x0004_0000 | 0x0000_0010);
    public.u16(0);
    public.u16(8);
    let public = public.finish().unwrap();

    let mut p = Writer::new();
    p.u16(0);
    p.u16(public.len() as u16);
    p.bytes(&public);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_DefineSpace,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "define counter -> {:08x}", r.code);

    let increment = command(
        st::SESSIONS,
        cc::NV_Increment,
        &[index, index],
        Some(&password(b"")),
        &[],
    );
    let mut p = Writer::new();
    p.u16(8);
    p.u16(0);
    let read = command(
        st::SESSIONS,
        cc::NV_Read,
        &[index, index],
        Some(&password(b"")),
        &p.finish().unwrap(),
    );

    assert_eq!(h.send(&increment).code, rc::SUCCESS);
    let r = h.send(&read);
    assert_eq!(r.code, rc::SUCCESS);
    assert!(r.body.windows(8).any(|w| w == 1u64.to_be_bytes()));

    assert_eq!(h.send(&increment).code, rc::SUCCESS);
    let r = h.send(&read);
    assert!(r.body.windows(8).any(|w| w == 2u64.to_be_bytes()));

    // An ordinary write to a counter is refused.
    let mut p = Writer::new();
    p.u16(8);
    p.bytes(&[0u8; 8]);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_Write,
        &[index, index],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::ATTRIBUTES & 0x03f);
}

#[test]
fn hierarchy_authorization_can_be_changed_and_is_enforced() {
    let h = Harness::started("hierarchyauth");

    // Set ownerAuth.
    let mut p = Writer::new();
    p.u16(6);
    p.bytes(b"secret");
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);

    // The empty password no longer works.
    let mut p = Writer::new();
    p.u16(0);
    p.bytes(b"");
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::AUTH_FAIL & 0x03f);

    // The new one does.
    let mut p = Writer::new();
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"secret")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
}

/// A restricted ECC storage key template on P-256 with AES-128-CFB.
fn storage_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0023); // TPM_ALG_ECC
    t.u16(alg::SHA256);
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth |
    // restricted | decrypt
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0001_0000 | 0x0002_0000);
    t.u16(0); // authPolicy
    t.u16(0x0006); // symmetric AES
    t.u16(128);
    t.u16(0x0043); // CFB
    t.u16(0x0010); // scheme TPM_ALG_NULL
    t.u16(0x0003); // curve NIST P-256
    t.u16(0x0010); // kdf TPM_ALG_NULL
    t.u16(0); // unique x
    t.u16(0); // unique y
    t.finish().unwrap()
}

/// A sealed data object template.
fn sealed_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0008); // TPM_ALG_KEYEDHASH
    t.u16(alg::SHA256);
    t.u32(0x0040); // userWithAuth
    t.u16(0); // authPolicy
    t.u16(0x0010); // scheme TPM_ALG_NULL
    t.u16(0); // unique
    t.finish().unwrap()
}

#[test]
fn a_primary_key_is_created_and_regenerates_identically() {
    let h = Harness::started("primary");

    let template = storage_template();
    let mut p = Writer::new();
    p.u16(4); // inSensitive
    p.u16(0); // userAuth
    p.u16(0); // data
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    let cmd = command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    );

    let r = h.send(&cmd);
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let handle = reader.u32().unwrap();
    assert_eq!(handle >> 24, 0x80, "transient handle range");
    let _param_size = reader.u32().unwrap();
    let public_size = reader.u16().unwrap();
    let public = reader.take(public_size as usize).unwrap().to_vec();
    assert!(public_size > 0);

    // Creating it again from the same seed and template gives the same key.
    let r2 = h.send(&cmd);
    assert_eq!(r2.code, rc::SUCCESS);
    let mut reader2 = Reader::new(&r2.body);
    let handle2 = reader2.u32().unwrap();
    let _ = reader2.u32().unwrap();
    let size2 = reader2.u16().unwrap();
    let public2 = reader2.take(size2 as usize).unwrap().to_vec();
    assert_eq!(public, public2, "the primary key was not regenerated");
    assert_ne!(handle, handle2, "each load takes its own handle");

    // TPM2_ReadPublic returns the same public area.
    let r = h.send(&command(st::NO_SESSIONS, cc::ReadPublic, &[handle], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap();
    assert_eq!(reader.take(size as usize).unwrap(), &public[..]);

    // Flushing frees the slot.
    let mut p = Writer::new();
    p.u32(handle);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::FlushContext,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::ReadPublic, &[handle], None, &[]));
    assert_eq!(r.code & 0x03f, rc::HANDLE & 0x03f);
}

#[test]
fn a_sealed_object_round_trips_through_create_load_and_unseal() {
    let h = Harness::started("seal");

    // A primary storage key to be the parent.
    let template = storage_template();
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let parent = Reader::new(&r.body).u32().unwrap();

    // Seal a secret under it.
    let secret = b"the sealed secret";
    let template = sealed_template();
    let mut sensitive = Writer::new();
    sensitive.u16(2);
    sensitive.bytes(b"pw");
    sensitive.u16(secret.len() as u16);
    sensitive.bytes(secret);
    let sensitive = sensitive.finish().unwrap();

    let mut p = Writer::new();
    p.u16(sensitive.len() as u16);
    p.bytes(&sensitive);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Create,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "Create -> {:08x}", r.code);

    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let private_size = reader.u16().unwrap();
    let private = reader.take(private_size as usize).unwrap().to_vec();
    let public_size = reader.u16().unwrap();
    let public = reader.take(public_size as usize).unwrap().to_vec();

    // Load it back.
    let mut p = Writer::new();
    p.u16(private.len() as u16);
    p.bytes(&private);
    p.u16(public.len() as u16);
    p.bytes(&public);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Load,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "Load -> {:08x}", r.code);
    let sealed = Reader::new(&r.body).u32().unwrap();

    // Unseal it with the right authorization value.
    let r = h.send(&command(
        st::SESSIONS,
        cc::Unseal,
        &[sealed],
        Some(&password(b"pw")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "Unseal -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let size = reader.u16().unwrap();
    assert_eq!(reader.take(size as usize).unwrap(), secret);

    // The wrong authorization value fails.
    let r = h.send(&command(
        st::SESSIONS,
        cc::Unseal,
        &[sealed],
        Some(&password(b"nope")),
        &[],
    ));
    assert_eq!(r.code & 0x03f, rc::AUTH_FAIL & 0x03f);
}

#[test]
fn a_private_area_does_not_load_under_the_wrong_parent() {
    let h = Harness::started("wrongparent");

    let template = storage_template();
    let make_primary = |hierarchy: u32| {
        let mut p = Writer::new();
        p.u16(4);
        p.u16(0);
        p.u16(0);
        p.u16(template.len() as u16);
        p.bytes(&template);
        p.u16(0);
        p.u32(0);
        let r = h.send(&command(
            st::SESSIONS,
            cc::CreatePrimary,
            &[hierarchy],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS);
        Reader::new(&r.body).u32().unwrap()
    };
    let owner_parent = make_primary(rh::OWNER);
    let platform_parent = make_primary(rh::PLATFORM);

    // Create a child under the owner parent.
    let child_template = sealed_template();
    let mut sensitive = Writer::new();
    sensitive.u16(0);
    sensitive.u16(4);
    sensitive.bytes(b"data");
    let sensitive = sensitive.finish().unwrap();
    let mut p = Writer::new();
    p.u16(sensitive.len() as u16);
    p.bytes(&sensitive);
    p.u16(child_template.len() as u16);
    p.bytes(&child_template);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Create,
        &[owner_parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let _ = reader.u32().unwrap();
    let private_size = reader.u16().unwrap();
    let private = reader.take(private_size as usize).unwrap().to_vec();
    let public_size = reader.u16().unwrap();
    let public = reader.take(public_size as usize).unwrap().to_vec();

    // Loading it under the other parent fails the integrity check.
    let mut p = Writer::new();
    p.u16(private.len() as u16);
    p.bytes(&private);
    p.u16(public.len() as u16);
    p.bytes(&public);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Load,
        &[platform_parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::INTEGRITY & 0x03f);
}

#[test]
fn a_primary_key_changes_when_the_hierarchy_seed_changes() {
    let h = Harness::started("changeeps");

    let template = storage_template();
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let cmd = command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::ENDORSEMENT],
        Some(&password(b"")),
        &p.finish().unwrap(),
    );

    let read_public = |body: &[u8]| {
        let mut reader = Reader::new(body);
        let _handle = reader.u32().unwrap();
        let _ = reader.u32().unwrap();
        let size = reader.u16().unwrap();
        reader.take(size as usize).unwrap().to_vec()
    };

    let before = read_public(&h.send(&cmd).body);

    // TPM2_ChangeEPS replaces the endorsement seed.
    let r = h.send(&command(
        st::SESSIONS,
        cc::ChangeEPS,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "ChangeEPS -> {:08x}", r.code);

    let after = read_public(&h.send(&cmd).body);
    assert_ne!(before, after, "the endorsement key survived a seed change");
}

/// An unrestricted ECDSA signing key template on P-256.
fn signing_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0023); // TPM_ALG_ECC
    t.u16(alg::SHA256);
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000);
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric TPM_ALG_NULL
    t.u16(0x0018); // scheme TPM_ALG_ECDSA
    t.u16(alg::SHA256);
    t.u16(0x0003); // curve NIST P-256
    t.u16(0x0010); // kdf TPM_ALG_NULL
    t.u16(0); // unique x
    t.u16(0); // unique y
    t.finish().unwrap()
}

#[test]
fn hash_produces_a_known_digest() {
    let h = Harness::started("hash");
    let mut p = Writer::new();
    p.u16(3);
    p.bytes(b"abc");
    p.u16(alg::SHA256);
    p.u32(rh::NULL);
    let r = h.send(&command(st::NO_SESSIONS, cc::Hash, &[], None, &p.finish().unwrap()));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap();
    assert_eq!(size, 32);
    // FIPS 180-4 known answer for "abc".
    assert_eq!(
        reader.take(32).unwrap(),
        &swtrust::util::hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        .unwrap()[..]
    );
}

#[test]
fn a_hash_sequence_matches_a_single_hash() {
    let h = Harness::started("hashseq");

    let mut p = Writer::new();
    p.u16(0); // auth
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::HashSequenceStart,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let sequence = Reader::new(&r.body).u32().unwrap();

    for chunk in [b"a".as_slice(), b"b".as_slice()] {
        let mut p = Writer::new();
        p.u16(chunk.len() as u16);
        p.bytes(chunk);
        let r = h.send(&command(
            st::SESSIONS,
            cc::SequenceUpdate,
            &[sequence],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "SequenceUpdate -> {:08x}", r.code);
    }

    let mut p = Writer::new();
    p.u16(1);
    p.bytes(b"c");
    p.u32(rh::NULL);
    let r = h.send(&command(
        st::SESSIONS,
        cc::SequenceComplete,
        &[sequence],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SequenceComplete -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let size = reader.u16().unwrap();
    assert_eq!(
        reader.take(size as usize).unwrap(),
        &swtrust::util::hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        .unwrap()[..]
    );

    // The sequence handle is gone.
    let r = h.send(&command(
        st::SESSIONS,
        cc::SequenceUpdate,
        &[sequence],
        Some(&password(b"")),
        &[0x00, 0x00],
    ));
    assert_eq!(r.code & 0x03f, rc::HANDLE & 0x03f);
}

#[test]
fn a_signature_from_a_created_key_verifies() {
    let h = Harness::started("sign");

    let template = signing_template();
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let key = Reader::new(&r.body).u32().unwrap();

    let digest = swtrust::tpm::crypto::hash::digest(alg::SHA256, b"message to sign").unwrap();
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&digest);
    p.u16(0x0010); // scheme TPM_ALG_NULL, so the key's scheme is used
    p.u16(0x8024); // TPM_ST_HASHCHECK
    p.u32(rh::NULL);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Sign,
        &[key],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "Sign -> {:08x}", r.code);

    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let signature = reader.take_rest();
    // Drop the trailing session area to isolate the signature.
    let signature = &signature[..signature.len() - 5];
    assert_eq!(
        u16::from_be_bytes([signature[0], signature[1]]),
        0x0018,
        "TPM_ALG_ECDSA"
    );

    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&digest);
    p.bytes(signature);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifySignature,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "VerifySignature -> {:08x}", r.code);

    // A different digest does not verify.
    let other = swtrust::tpm::crypto::hash::digest(alg::SHA256, b"another message").unwrap();
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&other);
    p.bytes(signature);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifySignature,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::SIGNATURE & 0x03f);
}

#[test]
fn the_version_185_signing_commands_follow_their_command_tables() {
    let h = Harness::started("sign185");

    let template = signing_template();
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let key = Reader::new(&r.body).u32().unwrap();

    let message = b"a message signed in pieces";
    let digest = swtrust::tpm::crypto::hash::digest(alg::SHA256, message).unwrap();

    // Part 3 Table 126: context, digest, validation. The key is unrestricted,
    // so a null hash check ticket is accepted.
    let mut p = Writer::new();
    p.u16(0); // context
    p.u16(32);
    p.bytes(&digest);
    p.u16(0x8024); // TPM_ST_HASHCHECK
    p.u32(rh::NULL);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::SignDigest,
        &[key],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SignDigest -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let rest = reader.take_rest();
    let signature = rest[..rest.len() - 5].to_vec();

    // Part 3 Table 120: context, digest, signature.
    let mut p = Writer::new();
    p.u16(0); // context
    p.u16(32);
    p.bytes(&digest);
    p.bytes(&signature);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifyDigestSignature,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "VerifyDigestSignature -> {:08x}", r.code);

    // Part 3 clause 20.4.1 requires the whole scheme, including its hash, to
    // be the one the key carries. Re-tagging the signature as SHA-384 is
    // refused rather than verified.
    let mut wrong = signature.clone();
    let hash_offset = 2;
    wrong[hash_offset] = 0x00;
    wrong[hash_offset + 1] = 0x0c; // TPM_ALG_SHA384
    let mut p = Writer::new();
    p.u16(0);
    p.u16(32);
    p.bytes(&digest);
    p.bytes(&wrong);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifyDigestSignature,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::SCHEME & 0x03f, "scheme -> {:08x}", r.code);

    // A supplied context is refused, because no implemented scheme takes one.
    let mut p = Writer::new();
    p.u16(1);
    p.u8(0);
    p.u16(32);
    p.bytes(&digest);
    p.bytes(&signature);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifyDigestSignature,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::VALUE & 0x03f);

    // Part 3 Table 89: auth, context. The key handle carries no authorization.
    let mut p = Writer::new();
    p.u16(0); // auth
    p.u16(0); // context
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::SignSequenceStart,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SignSequenceStart -> {:08x}", r.code);
    let sequence = Reader::new(&r.body).u32().unwrap();

    // The message is fed in, then Part 3 Table 124 completes with the sequence
    // handle first and the key second.
    let mut p = Writer::new();
    p.u16(6);
    p.bytes(&message[..6]);
    let r = h.send(&command(
        st::SESSIONS,
        cc::SequenceUpdate,
        &[sequence],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SequenceUpdate -> {:08x}", r.code);

    let mut auth = password(b"");
    auth.extend_from_slice(&password(b""));
    let mut p = Writer::new();
    p.u16((message.len() - 6) as u16);
    p.bytes(&message[6..]);
    let r = h.send(&command(
        st::SESSIONS,
        cc::SignSequenceComplete,
        &[sequence, key],
        Some(&auth),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SignSequenceComplete -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let rest = reader.take_rest();
    // Two response sessions follow the signature.
    let sequence_signature = rest[..rest.len() - 10].to_vec();

    // Part 3 Table 87: auth, hint, context.
    let mut p = Writer::new();
    p.u16(0); // auth
    p.u16(0); // hint
    p.u16(0); // context
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifySequenceStart,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "VerifySequenceStart -> {:08x}", r.code);
    let verify_sequence = Reader::new(&r.body).u32().unwrap();

    let mut p = Writer::new();
    p.u16(message.len() as u16);
    p.bytes(message);
    let r = h.send(&command(
        st::SESSIONS,
        cc::SequenceUpdate,
        &[verify_sequence],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SequenceUpdate -> {:08x}", r.code);

    // Part 3 Table 118: the sequence handle is authorized, the key is not, and
    // the only parameter is the signature.
    let r = h.send(&command(
        st::SESSIONS,
        cc::VerifySequenceComplete,
        &[verify_sequence, key],
        Some(&password(b"")),
        &sequence_signature,
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "VerifySequenceComplete -> {:08x}",
        r.code
    );
}

/// A keyed hash template that signs with HMAC-SHA256.
fn hmac_signing_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0008); // TPM_ALG_KEYEDHASH
    t.u16(alg::SHA256);
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000);
    t.u16(0); // authPolicy
    t.u16(0x0005); // scheme TPM_ALG_HMAC
    t.u16(alg::SHA256);
    t.u16(0); // unique
    t.finish().unwrap()
}

#[test]
fn an_hmac_key_signs_the_message_and_not_a_digest() {
    let h = Harness::started("hmacsign");

    let template = hmac_signing_template();
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let key = Reader::new(&r.body).u32().unwrap();

    // Part 3 Table 115 marks HMAC unsupported for the digest commands.
    let digest = swtrust::tpm::crypto::hash::digest(alg::SHA256, b"message").unwrap();
    let mut p = Writer::new();
    p.u16(0); // context
    p.u16(32);
    p.bytes(&digest);
    p.u16(0x8024); // TPM_ST_HASHCHECK
    p.u32(rh::NULL);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::SignDigest,
        &[key],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code & 0x03f, rc::SCHEME & 0x03f, "SignDigest -> {:08x}", r.code);

    // The sequence commands do take an HMAC key, and Table 115 has them sign
    // the message itself.
    let mut p = Writer::new();
    p.u16(0); // auth
    p.u16(0); // context
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::SignSequenceStart,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SignSequenceStart -> {:08x}", r.code);
    let sequence = Reader::new(&r.body).u32().unwrap();

    let mut auth = password(b"");
    auth.extend_from_slice(&password(b""));
    let mut p = Writer::new();
    p.u16(7);
    p.bytes(b"message");
    let r = h.send(&command(
        st::SESSIONS,
        cc::SignSequenceComplete,
        &[sequence, key],
        Some(&auth),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "SignSequenceComplete -> {:08x}",
        r.code
    );
    let mut reader = Reader::new(&r.body);
    let _param_size = reader.u32().unwrap();
    let rest = reader.take_rest();
    let signature = &rest[..rest.len() - 10];

    // The signature is TPM_ALG_HMAC over the message, so it round trips
    // through TPM2_VerifySequenceComplete.
    assert_eq!(
        u16::from_be_bytes([signature[0], signature[1]]),
        0x0005,
        "TPM_ALG_HMAC"
    );
    let signature = signature.to_vec();

    let mut p = Writer::new();
    p.u16(0);
    p.u16(0);
    p.u16(0);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::VerifySequenceStart,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "VerifySequenceStart -> {:08x}", r.code);
    let verify_sequence = Reader::new(&r.body).u32().unwrap();

    let mut p = Writer::new();
    p.u16(7);
    p.bytes(b"message");
    let r = h.send(&command(
        st::SESSIONS,
        cc::SequenceUpdate,
        &[verify_sequence],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "SequenceUpdate -> {:08x}", r.code);

    let r = h.send(&command(
        st::SESSIONS,
        cc::VerifySequenceComplete,
        &[verify_sequence, key],
        Some(&password(b"")),
        &signature,
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "VerifySequenceComplete -> {:08x}",
        r.code
    );
}

#[test]
fn a_saved_policy_session_keeps_the_restrictions_it_recorded() {
    let h = Harness::started("policyctx");

    // A real policy session, not a trial one, so the assertions bind.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0xa5u8; 32]);
    p.u16(0);
    p.u8(0x01); // TPM_SE_POLICY
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "StartAuthSession -> {:08x}", r.code);
    let session = Reader::new(&r.body).u32().unwrap();

    // Record two assertions: a command code and a command parameter digest.
    let mut p = Writer::new();
    p.u32(cc::Unseal);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCommandCode,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "PolicyCommandCode -> {:08x}", r.code);

    let cp_hash = [0x5au8; 32];
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&cp_hash);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCpHash,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "PolicyCpHash -> {:08x}", r.code);

    let get_digest = command(st::NO_SESSIONS, cc::PolicyGetDigest, &[session], None, &[]);
    let before = h.send(&get_digest).body;

    // Save the context and drop the loaded session.
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ContextSave,
        &[session],
        None,
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "ContextSave -> {:08x}", r.code);
    let context = r.body.clone();

    let r = h.send(&get_digest);
    assert_eq!(r.code & 0x03f, rc::HANDLE & 0x03f, "the session is gone");

    // Load it back. Part 1 clause 27.2.1 rebuilds the whole session.
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ContextLoad,
        &[],
        None,
        &context,
    ));
    assert_eq!(r.code, rc::SUCCESS, "ContextLoad -> {:08x}", r.code);
    let loaded = Reader::new(&r.body).u32().unwrap();
    assert_eq!(loaded, session, "a session returns to its own handle");

    // The digest came back.
    let get_digest = command(st::NO_SESSIONS, cc::PolicyGetDigest, &[loaded], None, &[]);
    assert_eq!(h.send(&get_digest).body, before);

    // So did the cpHash restriction: Part 3 clause 23.2.2 refuses a second
    // assertion that names a different command.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0x11u8; 32]);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCpHash,
        &[loaded],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::CPHASH, "a reloaded cpHash still binds");

    // And the digest did not move when that assertion was refused.
    assert_eq!(h.send(&get_digest).body, before);

    // Repeating the same value is accepted, which shows the restriction is
    // the one that was recorded before the save.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&cp_hash);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCpHash,
        &[loaded],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "the same cpHash is accepted");
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
