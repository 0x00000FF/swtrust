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
fn a_handle_the_command_syntax_forbids_is_refused() {
    let h = Harness::started("handletype");

    // TPM2_Clear takes TPMI_RH_CLEAR, which Part 2 Table 68 limits to
    // TPM_RH_LOCKOUT and TPM_RH_PLATFORM. Part 3 clause 5.4 refuses anything
    // else with TPM_RC_VALUE against the handle, so an ordinary object the
    // caller controls cannot authorize it.
    for handle in [rh::OWNER, rh::ENDORSEMENT, hc::TRANSIENT_FIRST] {
        let r = h.send(&command(
            st::SESSIONS,
            cc::Clear,
            &[handle],
            Some(&password(b"")),
            &[],
        ));
        assert_eq!(
            r.code & 0x03f,
            rc::VALUE & 0x03f,
            "TPM2_Clear accepted {handle:#010x} -> {:08x}",
            r.code
        );
    }

    // The two handles the type does allow get past the syntax check.
    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::LOCKOUT],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Clear -> {:08x}", r.code);
}

#[test]
fn a_dup_role_handle_needs_a_policy_session() {
    let h = Harness::started("duprole");

    // A duplicable key: fixedTPM and fixedParent both clear.
    let mut t = Writer::new();
    t.u16(0x0023); // TPM_ALG_ECC
    t.u16(alg::SHA256);
    t.u32(0x0020 | 0x0040 | 0x0004_0000); // sensitiveDataOrigin | userWithAuth | sign
    t.u16(0);
    t.u16(0x0010);
    t.u16(0x0018);
    t.u16(alg::SHA256);
    t.u16(0x0003);
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
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let key = Reader::new(&r.body).u32().unwrap();

    // Part 3 clause 5.6.4 gives objectHandle of TPM2_Duplicate the DUP role,
    // which only a policy session satisfies. A password is refused, so an
    // ordinary use authorization cannot export the private area.
    let mut p = Writer::new();
    p.u16(0); // encryptionKeyIn
    p.u16(alg::NULL); // symmetricAlg
    let r = h.send(&command(
        st::SESSIONS,
        cc::Duplicate,
        &[key, rh::NULL],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code & 0x03f,
        rc::AUTH_TYPE & 0x03f,
        "TPM2_Duplicate accepted a password -> {:08x}",
        r.code
    );
}

#[test]
fn trailing_parameter_octets_are_refused_without_changing_anything() {
    let h = Harness::started("trailing");

    // Set ownerAuth so a successful TPM2_Clear would be visible.
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

    // TPM2_Clear has no parameters. Part 3 clause 5.8.2 refuses a buffer that
    // carries more than the schematic defines.
    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::LOCKOUT],
        Some(&password(b"")),
        &[0xde, 0xad, 0xbe, 0xef],
    ));
    assert_eq!(r.code, rc::SIZE, "trailing octets -> {:08x}", r.code);

    // The refusal happened before the command ran, so ownerAuth is untouched.
    let mut p = Writer::new();
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code & 0x03f,
        rc::AUTH_FAIL & 0x03f,
        "TPM2_Clear ran despite the error"
    );

    // A command that does take parameters behaves the same way: appending an
    // octet to TPM2_HierarchyChangeAuth is refused and the authorization is
    // left as it was, rather than changed by a command that reported failure.
    let mut p = Writer::new();
    p.u16(7);
    p.bytes(b"changed");
    let mut params = p.finish().unwrap();
    params.push(0x00);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"secret")),
        &params,
    ));
    assert_eq!(r.code, rc::SIZE, "trailing octet -> {:08x}", r.code);

    // The old value still authorizes, so nothing was written.
    let mut p = Writer::new();
    p.u16(6);
    p.bytes(b"secret");
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"secret")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "the authorization was changed anyway");

    // A malformed TPM2_StartAuthSession leaves no session behind either.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0xa5u8; 32]);
    p.u16(0);
    p.u8(0x01);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let mut params = p.finish().unwrap();
    params.push(0x00);
    for _ in 0..8 {
        let r = h.send(&command(
            st::NO_SESSIONS,
            cc::StartAuthSession,
            &[rh::NULL, rh::NULL],
            None,
            &params,
        ));
        assert_eq!(r.code, rc::SIZE, "StartAuthSession -> {:08x}", r.code);
    }
    // The session slots are still free, so a well formed request succeeds.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0xa5u8; 32]);
    p.u16(0);
    p.u8(0x01);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "session slots were leaked");

    // The same command without the trailing octets is accepted.
    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::LOCKOUT],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Clear -> {:08x}", r.code);

    // And now the empty owner authorization works again.
    let mut p = Writer::new();
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyChangeAuth,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
}

#[test]
fn a_credential_round_trips_through_an_ecc_storage_key() {
    let h = Harness::started("ecccred");

    // The storage template is an ECC key on NIST P-256, which Part 1 clause
    // 20.3 protects a seed for with one pass Diffie-Hellman.
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
    let mut reader = Reader::new(&r.body);
    let key = reader.u32().unwrap();

    // The object the credential is bound to is the key itself, whose Name the
    // response carried after the public area and creation data.
    let mut p = Writer::new();
    p.u16(32); // credential
    p.bytes(&[0x5au8; 32]);
    let name = {
        // TPM2_ReadPublic gives the Name without unpicking the create response.
        let r = h.send(&command(st::NO_SESSIONS, cc::ReadPublic, &[key], None, &[]));
        assert_eq!(r.code, rc::SUCCESS, "ReadPublic -> {:08x}", r.code);
        let mut rd = Reader::new(&r.body);
        let public_size = rd.u16().unwrap() as usize;
        rd.take(public_size).unwrap();
        let name_size = rd.u16().unwrap() as usize;
        rd.take(name_size).unwrap().to_vec()
    };
    p.u16(name.len() as u16);
    p.bytes(&name);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::MakeCredential,
        &[key],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "MakeCredential -> {:08x}", r.code);

    // The blob and the secret come back, and the same TPM recovers the
    // credential from them with the private half of the key.
    let mut rd = Reader::new(&r.body);
    let blob_size = rd.u16().unwrap() as usize;
    let blob = rd.take(blob_size).unwrap().to_vec();
    let secret_size = rd.u16().unwrap() as usize;
    let secret = rd.take(secret_size).unwrap().to_vec();
    assert!(secret_size > 32, "an ECC secret carries a point");

    let mut auth = password(b"");
    auth.extend_from_slice(&password(b""));
    let mut p = Writer::new();
    p.u16(blob_size as u16);
    p.bytes(&blob);
    p.u16(secret_size as u16);
    p.bytes(&secret);
    let r = h.send(&command(
        st::SESSIONS,
        cc::ActivateCredential,
        &[key, key],
        Some(&auth),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "ActivateCredential -> {:08x}", r.code);

    let mut rd = Reader::new(&r.body);
    let _param_size = rd.u32().unwrap();
    let size = rd.u16().unwrap() as usize;
    assert_eq!(rd.take(size).unwrap(), &[0x5au8; 32], "credential recovered");
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

#[test]
fn load_external_refuses_an_asymmetric_key_that_is_not_there() {
    // A creation template may leave unique empty, so the shared validator
    // allows it. TPM2_LoadExternal is not creating anything, and Part 2 Table
    // 194 says of an RSA keyBits of zero that the value is only valid for
    // create. An Empty Point is not a point on any curve either.
    let h = Harness::started("emptykey");

    let load = |template: &[u8]| {
        let mut p = Writer::new();
        p.u16(0); // inPrivate absent
        p.u16(template.len() as u16);
        p.bytes(template);
        p.u32(rh::NULL);
        h.send(&command(
            st::NO_SESSIONS,
            cc::LoadExternal,
            &[],
            None,
            &p.finish().unwrap(),
        ))
    };

    // An RSA public area with no modulus.
    let mut t = Writer::new();
    t.u16(alg::RSA);
    t.u16(alg::SHA256);
    t.u32(0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010);
    t.u16(0x0016);
    t.u16(alg::SHA256);
    t.u16(2048);
    t.u32(0);
    t.u16(0); // no modulus
    let r = load(&t.finish().unwrap());
    assert_ne!(r.code, rc::SUCCESS, "an RSA key with no modulus loaded");

    // An ECC public area with an Empty Point.
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    t.u32(0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010);
    t.u16(0x0018);
    t.u16(alg::SHA256);
    t.u16(0x0003);
    t.u16(0x0010);
    t.u16(0); // no x
    t.u16(0); // no y
    let r = load(&t.finish().unwrap());
    assert_ne!(r.code, rc::SUCCESS, "an ECC key with no point loaded");
}

#[test]
fn an_rsa_key_whose_modulus_disagrees_with_key_bits_is_refused() {
    // Part 2 Table 195 makes keyBits the number of bits in the public modulus,
    // and Part 3 clause 12.2 answers TPM_RC_KEY_SIZE when the key size and the
    // public area disagree. Loading such a key used to succeed, and TPM2_Sign
    // then sized the PSS padding from keyBits while the block came from the
    // modulus, so the padding ran past the block.
    let h = Harness::started("rsakeybits");

    let mut t = Writer::new();
    t.u16(alg::RSA);
    t.u16(alg::SHA256);
    // userWithAuth | sign. An external object may not claim to be TPM resident.
    t.u32(0x0040 | 0x0004_0000);
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric TPM_ALG_NULL
    t.u16(0x0016); // scheme TPM_ALG_RSAPSS
    t.u16(alg::SHA256);
    t.u16(4096); // keyBits says 4096 bits
    t.u32(0); // exponent, the default
    t.u16(256); // but the modulus is 2048 bits
    t.bytes(&[0xab; 256]);
    let template = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(0); // inPrivate is absent
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u32(rh::NULL);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::LoadExternal,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    let expected = swtrust::tpm::error::TpmRc(rc::KEY_SIZE)
        .with_parameter(2)
        .value();
    assert_eq!(r.code, expected, "got {:08x}", r.code);

    // A modulus of the length keyBits names is loaded.
    let mut t = Writer::new();
    t.u16(alg::RSA);
    t.u16(alg::SHA256);
    t.u32(0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010);
    t.u16(0x0016);
    t.u16(alg::SHA256);
    t.u16(2048);
    t.u32(0);
    t.u16(256);
    t.bytes(&[0xab; 256]);
    let template = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u32(rh::NULL);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::LoadExternal,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "got {:08x}", r.code);

    // A 2047 bit modulus fits in the same 256 octets, so a check that counted
    // octets would let it through as a 2048 bit key.
    let mut short = [0xabu8; 256];
    short[0] = 0x7f;
    let mut t = Writer::new();
    t.u16(alg::RSA);
    t.u16(alg::SHA256);
    t.u32(0x0040 | 0x0004_0000);
    t.u16(0);
    t.u16(0x0010);
    t.u16(0x0016);
    t.u16(alg::SHA256);
    t.u16(2048);
    t.u32(0);
    t.u16(256);
    t.bytes(&short);
    let template = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u32(rh::NULL);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::LoadExternal,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, expected, "a 2047 bit modulus -> {:08x}", r.code);
}

/// Part 3 clause 29.2.1: "The command will fail if newTime is less than the
/// current value of Clock or if the new time is greater than
/// FF FF 00 00 00 00 00 00. If both of these checks succeed, Clock is set to
/// newTime. If either of these checks fails, the TPM shall return TPM_RC_VALUE
/// and make no change to Clock."
#[test]
fn clock_set_refuses_a_time_that_goes_back_or_past_the_maximum() {
    let h = Harness::started("clockset");
    let set = |value: u64| {
        let mut p = Writer::new();
        p.u64(value);
        h.send(&command(
            st::SESSIONS,
            cc::ClockSet,
            &[rh::OWNER],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ))
    };
    let read = || {
        let r = h.send(&command(st::NO_SESSIONS, cc::ReadClock, &[], None, &[]));
        let mut reader = Reader::new(&r.body);
        let _time = reader.u64().unwrap();
        let clock = reader.u64().unwrap();
        let _reset = reader.u32().unwrap();
        let _restart = reader.u32().unwrap();
        (clock, reader.u8().unwrap())
    };

    let (before, _) = read();

    // Going back is refused and changes nothing.
    let r = set(before.saturating_sub(1_000));
    assert_eq!(r.code & 0x03f, rc::VALUE & 0x03f, "a time in the past");
    assert!(read().0 >= before, "Clock must not have moved");

    // One past the maximum is refused too.
    let r = set(swtrust::tpm::config::MAX_CLOCK + 1);
    assert_eq!(r.code & 0x03f, rc::VALUE & 0x03f, "past the maximum");

    // The maximum itself is accepted. What comes back is at least that, since
    // Clock keeps advancing between the two commands.
    assert_eq!(set(swtrust::tpm::config::MAX_CLOCK).code, rc::SUCCESS);
    assert!(read().0 >= swtrust::tpm::config::MAX_CLOCK);
}

/// Part 1 clause 33.3.1: "If TPM2_ClockSet() causes the volatile and
/// non-volatile versions of Clock to differ by more than the
/// implementation-dependent update interval, then NV Clock will be updated
/// before TPM2_ClockSet() returns", and "After the next NV update of Clock,
/// safe is SET to indicate that Clock is not a repeat."
#[test]
fn a_large_clock_set_updates_nv_and_makes_the_clock_safe_again() {
    let h = Harness::started("clocksetsafe");
    // Put the TPM in the state a startup that was not orderly leaves.
    h.tpm.with_state_mut(|s| s.clock.safe = false);

    let read_safe = || {
        let r = h.send(&command(st::NO_SESSIONS, cc::ReadClock, &[], None, &[]));
        let mut reader = Reader::new(&r.body);
        let _ = reader.u64().unwrap();
        let _ = reader.u64().unwrap();
        let _ = reader.u32().unwrap();
        let _ = reader.u32().unwrap();
        reader.u8().unwrap()
    };
    assert_eq!(read_safe(), 0, "it starts unsafe");

    // A jump smaller than the interval does not reach an NV update.
    let now = h.tpm.with_state(|s| s.clock.clock);
    let mut p = Writer::new();
    p.u64(now + 1_000);
    let r = h.send(&command(
        st::SESSIONS,
        cc::ClockSet,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(read_safe(), 0, "a small step is not an NV update");

    // One larger than the interval does.
    let now = h.tpm.with_state(|s| s.clock.clock);
    let mut p = Writer::new();
    p.u64(now + u64::from(swtrust::tpm::config::NV_CLOCK_UPDATE_INTERVAL) + 1);
    let r = h.send(&command(
        st::SESSIONS,
        cc::ClockSet,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(read_safe(), 1, "the NV update puts safe back");
}

/// A run of small steps reaches the update interval just as one large step
/// does, so the copy of Clock in NV cannot be left behind for ever.
///
/// Part 3 clause 29.2.1: "If the value of Clock after the update makes the
/// volatile and non-volatile versions of TPMS_CLOCK_INFO.clock differ by more
/// than the reported update interval, then the TPM shall update the
/// non-volatile version of TPMS_CLOCK_INFO.clock before returning."
#[test]
fn small_clock_steps_add_up_to_an_nv_update() {
    let h = Harness::started("clockstep");
    h.tpm.with_state_mut(|s| {
        s.clock.safe = false;
        s.clock.nv_elapsed = 0;
    });

    let step = u64::from(swtrust::tpm::config::NV_CLOCK_UPDATE_INTERVAL) / 8;
    for _ in 0..7 {
        let now = h.tpm.with_state(|s| s.clock.clock);
        let mut p = Writer::new();
        p.u64(now + step);
        let r = h.send(&command(
            st::SESSIONS,
            cc::ClockSet,
            &[rh::OWNER],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS);
    }
    assert!(
        !h.tpm.with_state(|s| s.clock.safe),
        "seven eighths of an interval is not one"
    );

    // The eighth step takes the pair past the interval.
    let now = h.tpm.with_state(|s| s.clock.clock);
    let mut p = Writer::new();
    p.u64(now + step + 1);
    let r = h.send(&command(
        st::SESSIONS,
        cc::ClockSet,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    assert!(
        h.tpm.with_state(|s| s.clock.safe),
        "the steps together must reach an NV update"
    );
}

/// Decode a hex string that was captured from a command log.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has an odd length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_creation_template_with_a_zero_filled_unique_field_is_accepted() {
    // Part 3 clause 12.2.1 for TPM2_Create and clause 24.1.1 for
    // TPM2_CreatePrimary both say that "the size of the unique field shall not
    // be checked for consistency with the other object parameters", and clause
    // 24.1.1 adds that "an Empty Buffer is a legal unique field value".
    //
    // These two buffers are the TPM2_CreatePrimary commands Windows 11 Setup
    // sends, taken from a command log byte for byte. Each carries a 256 octet
    // unique field of zeros beside a keyBits of 2048. Counted in bits that is a
    // modulus of zero, so a TPM that checked the field against keyBits would
    // answer TPM_RC_KEY_SIZE and no key would ever be made.
    let h = Harness::started("windows-primary");

    // The storage primary, under the owner hierarchy.
    let srk = hex(concat!(
        "80020000015700000131400000010000001d4000000900000000140000000000",
        "000000000000000000000000000000000400000000011a0001000b0003047200",
        "0000060080004300100800000000000100000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000",
    ));
    let r = h.send(&srk);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "the storage primary was refused: {:#x}",
        r.code
    );

    // The endorsement primary, whose template also carries the authPolicy the
    // TCG EK Credential Profile defines.
    let ek = hex(concat!(
        "800200000177000001314000000b0000001d4000000900000000140000000000",
        "000000000000000000000000000000000400000000013a0001000b000300b200",
        "20837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469",
        "aa00060080004300100800000000000100000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000",
    ));
    let r = h.send(&ek);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "the endorsement primary was refused: {:#x}",
        r.code
    );

    // The key that came back has the modulus the template asked for, which is
    // the field the template itself was excused from stating.
    let mut rd = Reader::new(&r.body);
    let _handle = rd.u32().unwrap();
    let _size = rd.u32().unwrap();
    let public_size = rd.u16().unwrap() as usize;
    let public = rd.take(public_size).unwrap().to_vec();
    let mut pr = Reader::new(&public);
    assert_eq!(pr.u16().unwrap(), alg::RSA);
    assert_eq!(pr.u16().unwrap(), alg::SHA256);
    let _attrs = pr.u32().unwrap();
    let policy_size = pr.u16().unwrap() as usize;
    let _policy = pr.take(policy_size).unwrap();
    let _sym = (pr.u16().unwrap(), pr.u16().unwrap(), pr.u16().unwrap());
    let _scheme = pr.u16().unwrap();
    assert_eq!(pr.u16().unwrap(), 2048, "keyBits changed");
    let _exponent = pr.u32().unwrap();
    let modulus_size = pr.u16().unwrap() as usize;
    assert_eq!(modulus_size, 256, "a 2048 bit modulus is 256 octets");
    let modulus = pr.take(modulus_size).unwrap();
    assert_ne!(modulus, [0u8; 256], "the modulus is still the placeholder");
}

#[test]
fn a_loaded_public_area_is_still_checked_against_its_key_bits() {
    // The exemption above belongs to the creation templates. TPM2_LoadExternal
    // is given a key rather than asked to make one, so a modulus that does not
    // agree with keyBits is refused with TPM_RC_KEY_SIZE, Part 3 clause 12.2.
    let h = Harness::started("loaded-key-size");

    let mut public = Writer::new();
    public.u16(alg::RSA);
    public.u16(alg::SHA256);
    public.u32(0x0004_0000); // userWithAuth only, no sign or decrypt
    public.u16(0); // authPolicy
    public.u16(alg::NULL); // symmetric
    public.u16(alg::NULL); // scheme
    public.u16(2048); // keyBits
    public.u32(0); // exponent
    public.u16(128); // a 1024 bit modulus beside a keyBits of 2048
    public.bytes(&{
        let mut m = vec![0xabu8; 128];
        m[0] = 0x80;
        m
    });
    let public = public.finish().unwrap();

    let mut p = Writer::new();
    p.u16(0); // inPrivate, absent
    p.u16(public.len() as u16);
    p.bytes(&public);
    p.u32(rh::NULL);

    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::LoadExternal,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::KEY_SIZE | 0x080 | 0x040 | (2 << 8),
        "a modulus that disagrees with keyBits was loaded: {:#x}",
        r.code
    );
}

/// A Derivation Parent: a keyed hash object with the Parent Key attributes.
///
/// Part 1 clause 20.2 says "keyedHash objects with these attributes are
/// Derivation Parents", and clause 25.2 puts the KDF in the parent's scheme, so
/// the scheme is TPM_ALG_XOR naming KDF1_SP800_108 and SHA-256.
fn derivation_parent_template() -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0008); // TPM_ALG_KEYEDHASH
    t.u16(alg::SHA256);
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth |
    // restricted | decrypt
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0001_0000 | 0x0002_0000);
    t.u16(0); // authPolicy
    t.u16(0x000A); // scheme TPM_ALG_XOR
    t.u16(alg::SHA256); // the hash of the KDF
    t.u16(0x0022); // TPM_ALG_KDF1_SP800_108
    t.u16(0); // unique
    t.finish().unwrap()
}

/// An ECC template for a Derived Object, with sensitiveDataOrigin CLEAR.
///
/// `unique` carries the TPMS_DERIVE that Part 2 clause 12.2.6 puts there when
/// the parent is a Derivation Parent.
fn derived_template(attrs: u32, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0023); // TPM_ALG_ECC
    t.u16(alg::SHA256);
    t.u32(attrs);
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric TPM_ALG_NULL
    t.u16(0x0018); // scheme TPM_ALG_ECDSA
    t.u16(alg::SHA256);
    t.u16(0x0003); // curve NIST P-256
    t.u16(0x0010); // kdf TPM_ALG_NULL
    t.u16(label.len() as u16);
    t.bytes(label);
    t.u16(context.len() as u16);
    t.bytes(context);
    t.finish().unwrap()
}

/// Build a TPM2_CreateLoaded command.
fn create_loaded(parent: u32, sensitive_data: &[u8], template: &[u8]) -> Vec<u8> {
    let mut p = Writer::new();
    p.u16((4 + sensitive_data.len()) as u16); // inSensitive
    p.u16(0); // userAuth
    p.u16(sensitive_data.len() as u16);
    p.bytes(sensitive_data);
    p.u16(template.len() as u16);
    p.bytes(template);
    command(
        st::SESSIONS,
        cc::CreateLoaded,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    )
}

/// Read outPrivate and the public area out of a TPM2_CreateLoaded response.
fn split_created(body: &[u8]) -> (u32, Vec<u8>, Vec<u8>) {
    let mut r = Reader::new(body);
    let handle = r.u32().unwrap();
    let _param_size = r.u32().unwrap();
    let private_size = r.u16().unwrap() as usize;
    let private = r.take(private_size).unwrap().to_vec();
    let public_size = r.u16().unwrap() as usize;
    let public = r.take(public_size).unwrap().to_vec();
    (handle, private, public)
}

/// Make a Derivation Parent and return its handle.
fn load_derivation_parent(h: &Harness) -> u32 {
    let template = derivation_parent_template();
    let mut p = Writer::new();
    p.u16(4); // inSensitive
    p.u16(0); // userAuth
    p.u16(0); // data
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "the derivation parent was refused: {:#x}",
        r.code
    );
    Reader::new(&r.body).u32().unwrap()
}

/// sign | fixedTPM | fixedParent | userWithAuth, sensitiveDataOrigin CLEAR.
const DERIVED_SIGNING: u32 = 0x0002 | 0x0010 | 0x0040 | 0x0004_0000;

#[test]
fn a_derivation_parent_derives_a_repeatable_object() {
    // Part 3 clause 12.9.1: "if parentHandle references a Derivation Parent,
    // then a Derived Object is generated". Part 1 clause 25.4.2 warns that "if
    // the same Derivation Parent, label, and context are provided in two
    // different invocations of CreateLoaded", the same object comes back, which
    // is the property under test here.
    let h = Harness::started("derive");
    let parent = load_derivation_parent(&h);

    let cmd = create_loaded(
        parent,
        &[],
        &derived_template(DERIVED_SIGNING, b"label", b"context"),
    );
    let r = h.send(&cmd);
    assert_eq!(r.code, rc::SUCCESS, "derivation failed: {:#x}", r.code);
    let (_handle, private, public) = split_created(&r.body);

    // Clause 12.9.1: "If parentHandle references a Derivation Parent or a
    // Primary Seed, then outPrivate will be an Empty Buffer."
    assert!(
        private.is_empty(),
        "a derived object cannot be loaded, so outPrivate must be empty"
    );

    // The same parent, label and context give the same object.
    let again = h.send(&cmd);
    assert_eq!(again.code, rc::SUCCESS);
    let (_, _, public_again) = split_created(&again.body);
    assert_eq!(public, public_again, "the derivation is not repeatable");

    // A different label gives a different one.
    let other = h.send(&create_loaded(
        parent,
        &[],
        &derived_template(DERIVED_SIGNING, b"other", b"context"),
    ));
    assert_eq!(other.code, rc::SUCCESS);
    let (_, _, public_other) = split_created(&other.body);
    assert_ne!(public, public_other, "the label did not reach the KDF");

    // So does a different context.
    let ctx = h.send(&create_loaded(
        parent,
        &[],
        &derived_template(DERIVED_SIGNING, b"label", b"other"),
    ));
    assert_eq!(ctx.code, rc::SUCCESS);
    let (_, _, public_ctx) = split_created(&ctx.body);
    assert_ne!(public, public_ctx, "the context did not reach the KDF");
}

#[test]
fn derived_objects_with_different_attributes_share_a_key() {
    // Part 3 clause 12.9.1: "If parentHandle references a Derivation Parent,
    // the bits of the Label and Context are used in the creation of the key.
    // This differs from TPM2_CreatePrimary(), where the bits of the template
    // are used. This means that different templates (specifically, different
    // public attributes) will result in the same key for the same Label and
    // Context."
    let h = Harness::started("derive-attrs");
    let parent = load_derivation_parent(&h);

    const DECRYPTING: u32 = 0x0002 | 0x0010 | 0x0040 | 0x0002_0000;

    let a = h.send(&create_loaded(
        parent,
        &[],
        &derived_template(DERIVED_SIGNING, b"shared", b"context"),
    ));
    assert_eq!(a.code, rc::SUCCESS);
    let b = h.send(&create_loaded(
        parent,
        &[],
        &derived_template(DECRYPTING, b"shared", b"context"),
    ));
    assert_eq!(b.code, rc::SUCCESS);

    let (_, _, public_a) = split_created(&a.body);
    let (_, _, public_b) = split_created(&b.body);
    assert_ne!(
        public_a, public_b,
        "the attributes are part of the public area"
    );

    // The public areas differ only in their attributes, so the points agree.
    // A P-256 point is two 32 octet coordinates, each behind a UINT16 size.
    let point = |p: &[u8]| p[p.len() - 68..].to_vec();
    assert_eq!(
        point(&public_a),
        point(&public_b),
        "the attributes changed the derived key"
    );
}

#[test]
fn a_label_may_come_from_the_sensitive_area_instead() {
    // Part 2 clause 11.1.11: "The values in the unique field of inPublic area
    // template take precedence over the values in the inSensitive parameter."
    // What the template leaves empty the sensitive area supplies.
    let h = Harness::started("derive-sensitive");
    let parent = load_derivation_parent(&h);

    // A TPMS_DERIVE in the sensitive area carrying both values.
    let mut s = Writer::new();
    s.u16(5);
    s.bytes(b"label");
    s.u16(7);
    s.bytes(b"context");
    let from_sensitive = s.finish().unwrap();

    let a = h.send(&create_loaded(
        parent,
        &from_sensitive,
        &derived_template(DERIVED_SIGNING, b"", b""),
    ));
    assert_eq!(a.code, rc::SUCCESS, "derivation failed: {:#x}", a.code);

    // The same values placed in the template give the same object.
    let b = h.send(&create_loaded(
        parent,
        &[],
        &derived_template(DERIVED_SIGNING, b"label", b"context"),
    ));
    assert_eq!(b.code, rc::SUCCESS);

    let (_, _, public_a) = split_created(&a.body);
    let (_, _, public_b) = split_created(&b.body);
    assert_eq!(
        public_a, public_b,
        "the sensitive area did not supply the label and context"
    );

    // A template value wins over the one beside it in the sensitive area.
    let c = h.send(&create_loaded(
        parent,
        &from_sensitive,
        &derived_template(DERIVED_SIGNING, b"other", b""),
    ));
    assert_eq!(c.code, rc::SUCCESS);
    let (_, _, public_c) = split_created(&c.body);
    assert_ne!(
        public_a, public_c,
        "the template label did not take precedence"
    );
}

#[test]
fn a_derived_object_refuses_sensitive_data_origin_and_rsa() {
    // Clause 12.9.1: "The input validation is the same as for TPM2_Create() and
    // TPM2_CreatePrimary() with one exception: when parentHandle references a
    // Derivation Parent, then sensitiveDataOrigin in inPublic is required to be
    // CLEAR." And: "the TPM may return TPM_RC_TYPE if the key type to be
    // generated is an RSA key."
    let h = Harness::started("derive-refuse");
    let parent = load_derivation_parent(&h);

    const WITH_ORIGIN: u32 = 0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000;
    let r = h.send(&create_loaded(
        parent,
        &[],
        &derived_template(WITH_ORIGIN, b"label", b"context"),
    ));
    assert_eq!(
        r.code,
        rc::ATTRIBUTES | 0x080 | 0x040 | (2 << 8),
        "sensitiveDataOrigin was accepted on a derived object: {:#x}",
        r.code
    );

    // An RSA template under the same parent.
    let mut t = Writer::new();
    t.u16(0x0001); // TPM_ALG_RSA
    t.u16(alg::SHA256);
    t.u32(DERIVED_SIGNING);
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric TPM_ALG_NULL
    t.u16(0x0014); // scheme TPM_ALG_RSASSA
    t.u16(alg::SHA256);
    t.u16(2048);
    t.u32(0);
    t.u16(5);
    t.bytes(b"label");
    t.u16(0);
    let r = h.send(&create_loaded(parent, &[], &t.finish().unwrap()));
    assert_eq!(
        r.code,
        rc::TYPE | 0x080 | 0x040 | (2 << 8),
        "an RSA key was derived: {:#x}",
        r.code
    );
}

#[test]
fn a_storage_parent_still_creates_an_ordinary_object() {
    // Clause 12.9.1: "if parentHandle references a Storage Parent, then an
    // Ordinary Object is created". Telling the two kinds of parent apart must
    // not have taken the ordinary path away.
    let h = Harness::started("create-loaded-ordinary");

    let template = storage_template();
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let parent = Reader::new(&r.body).u32().unwrap();

    // The sealed template has sensitiveDataOrigin CLEAR, so the data to seal
    // comes from the caller.
    let r = h.send(&create_loaded(parent, b"sealed", &sealed_template()));
    assert_eq!(r.code, rc::SUCCESS, "CreateLoaded -> {:#x}", r.code);
    let (_, private, _) = split_created(&r.body);
    assert!(
        !private.is_empty(),
        "an ordinary object is loadable, so outPrivate carries it"
    );
}


/// A Derivation Parent whose nameAlg and scheme hash disagree.
///
/// Part 1 clause 25.4.1 names the nameAlg of the parent as the KDF hash, so a
/// parent built this way tells the two apart.
fn derivation_parent_template_with(name_alg: u16, scheme_hash: u16) -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(0x0008); // TPM_ALG_KEYEDHASH
    t.u16(name_alg);
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0001_0000 | 0x0002_0000);
    t.u16(0); // authPolicy
    t.u16(0x000A); // scheme TPM_ALG_XOR
    t.u16(scheme_hash);
    t.u16(0x0022); // TPM_ALG_KDF1_SP800_108
    t.u16(0); // unique
    t.finish().unwrap()
}

/// Create a primary from a raw template and return its handle and public area.
fn primary_from(h: &Harness, template: &[u8]) -> (u32, Vec<u8>) {
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(template);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:#x}", r.code);
    let mut reader = Reader::new(&r.body);
    let handle = reader.u32().unwrap();
    let _param = reader.u32().unwrap();
    let size = reader.u16().unwrap() as usize;
    (handle, reader.take(size).unwrap().to_vec())
}

#[test]
fn parents_that_differ_derive_different_objects() {
    // Part 1 clause 25.4.1 keys the derivation on the parent's own sensitive
    // value, so no two parents share a derived object. Which of the parent's
    // hashes drives the KDF is settled in a unit test, because two parents
    // built through TPM2_CreatePrimary never share a sensitive value and so
    // cannot show it from out here.
    let h = Harness::started("derive-parents");

    let (a, _) = primary_from(&h, &derivation_parent_template_with(alg::SHA256, alg::SHA256));
    let (b, _) = primary_from(&h, &derivation_parent_template_with(alg::SHA256, alg::SHA384));
    let (c, _) = primary_from(&h, &derivation_parent_template_with(alg::SHA384, alg::SHA256));

    let derive = |parent: u32| {
        let r = h.send(&create_loaded(
            parent,
            &[],
            &derived_template(DERIVED_SIGNING, b"label", b"context"),
        ));
        assert_eq!(r.code, rc::SUCCESS, "derivation failed: {:#x}", r.code);
        let (_, _, public) = split_created(&r.body);
        public
    };

    assert_eq!(derive(a), derive(a), "the derivation is not repeatable");
    assert_ne!(derive(a), derive(b));
    assert_ne!(derive(a), derive(c));
    assert_ne!(derive(b), derive(c));

    // A parent whose nameAlg is SHA-384 derives just as well as one whose
    // nameAlg is SHA-256, so the KDF is not tied to a single hash.
    let r = h.send(&create_loaded(
        c,
        &[],
        &derived_template(DERIVED_SIGNING, b"label", b"context"),
    ));
    assert_eq!(r.code, rc::SUCCESS, "a SHA-384 parent could not derive");
}

#[test]
fn a_symmetric_and_a_keyed_hash_object_can_be_derived() {
    // Part 1 clause 25.4.1 gives the symmetric case outright: "For a 128-bit
    // AES key in a SYMCIPHER object having SHA-256 as its nameAlg, the most
    // significant 16 bytes of the KDF data are used for the AES key and the
    // next-most-significant 32 bytes are used for the seedValue." A derived
    // object never takes its sensitive value from the caller, clause 25.3, so
    // the ordinary rule that sensitiveDataOrigin decides where it comes from
    // must not be applied here.
    let h = Harness::started("derive-sym");
    let parent = load_derivation_parent(&h);

    // A SYMCIPHER template: decrypt, sensitiveDataOrigin CLEAR.
    let mut t = Writer::new();
    t.u16(0x0025); // TPM_ALG_SYMCIPHER
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0040 | 0x0002_0000);
    t.u16(0); // authPolicy
    t.u16(0x0006); // AES
    t.u16(128);
    t.u16(0x0043); // CFB
    t.u16(5);
    t.bytes(b"label");
    t.u16(0);
    let sym = t.finish().unwrap();

    let r = h.send(&create_loaded(parent, &[], &sym));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a symmetric object could not be derived: {:#x}",
        r.code
    );
    let (_, private, public_sym) = split_created(&r.body);
    assert!(private.is_empty());

    // Deriving it again gives the same key.
    let again = h.send(&create_loaded(parent, &[], &sym));
    assert_eq!(again.code, rc::SUCCESS);
    let (_, _, public_again) = split_created(&again.body);
    assert_eq!(public_sym, public_again);

    // A keyed hash object, which is what a derived HMAC key is.
    let mut t = Writer::new();
    t.u16(0x0008); // TPM_ALG_KEYEDHASH
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0040 | 0x0004_0000); // sign
    t.u16(0); // authPolicy
    t.u16(0x0005); // scheme TPM_ALG_HMAC
    t.u16(alg::SHA256);
    t.u16(5);
    t.bytes(b"label");
    t.u16(0);
    let keyed = t.finish().unwrap();

    let r = h.send(&create_loaded(parent, &[], &keyed));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a keyed hash object could not be derived: {:#x}",
        r.code
    );
    let (_, private, _) = split_created(&r.body);
    assert!(private.is_empty());
}

#[test]
fn a_primary_key_does_not_depend_on_its_authorization_value() {
    // Part 3 clause 24.1.1: "If this command is called multiple times with the
    // same inPublic parameter, inSensitive.data, and Primary Seed, the TPM
    // shall produce the same Primary Object." The authorization value is not
    // among them; Part 1 clause 24.7.3 has it copied from userAuth into the
    // object after the key is made.
    let h = Harness::started("primary-auth");
    let template = storage_template();

    let with_auth = |auth: &[u8]| {
        let mut p = Writer::new();
        p.u16((4 + auth.len()) as u16); // inSensitive
        p.u16(auth.len() as u16);
        p.bytes(auth);
        p.u16(0); // data
        p.u16(template.len() as u16);
        p.bytes(&template);
        p.u16(0); // outsideInfo
        p.u32(0); // creationPCR
        let r = h.send(&command(
            st::SESSIONS,
            cc::CreatePrimary,
            &[rh::OWNER],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:#x}", r.code);
        let mut reader = Reader::new(&r.body);
        let _handle = reader.u32().unwrap();
        let _param = reader.u32().unwrap();
        let size = reader.u16().unwrap() as usize;
        reader.take(size).unwrap().to_vec()
    };

    let none = with_auth(b"");
    let some = with_auth(b"secret");
    assert_eq!(
        none, some,
        "the authorization value changed the primary key"
    );
}

#[test]
fn a_template_that_can_neither_sign_nor_decrypt_is_refused() {
    // Part 3 clause 12.1: "If the Object is a not a keyedHash object, and the
    // sign and encrypt attributes are CLEAR, the TPM shall return
    // TPM_RC_ATTRIBUTES." The rule belongs to creation, so it reaches
    // TPM2_Create, TPM2_CreatePrimary and TPM2_CreateLoaded alike.
    let h = Harness::started("inert-template");

    // An ECC template with neither sign nor decrypt.
    let mut t = Writer::new();
    t.u16(0x0023); // TPM_ALG_ECC
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040); // no sign, no decrypt
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric TPM_ALG_NULL
    t.u16(0x0010); // scheme TPM_ALG_NULL
    t.u16(0x0003); // curve NIST P-256
    t.u16(0x0010); // kdf TPM_ALG_NULL
    t.u16(0);
    t.u16(0);
    let inert = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(inert.len() as u16);
    p.bytes(&inert);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::ATTRIBUTES | 0x080 | 0x040 | (2 << 8),
        "an object that can do nothing was created: {:#x}",
        r.code
    );

    // A sealed data object is a keyed hash and is exempt, which is the whole
    // point of the exception.
    let mut p = Writer::new();
    p.u16(4 + 6);
    p.u16(0);
    p.u16(6);
    p.bytes(b"sealed");
    let sealed = sealed_template();
    p.u16(sealed.len() as u16);
    p.bytes(&sealed);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a sealed data object was refused: {:#x}",
        r.code
    );
}

