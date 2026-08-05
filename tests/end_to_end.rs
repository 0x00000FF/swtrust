//! End to end tests that drive the TPM through its command interface.
//!
//! Every test builds real command buffers, hands them to the device, and reads
//! the response buffers back, so the header handling, dispatch, authorization
//! and marshalling are all exercised together.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::constants::{alg, cap, cc, hc, pt, rc, rh, se, st};
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

/// Two password authorization areas, for a command with two auth handles.
fn password_sessions(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.extend_from_slice(&password(b""));
    }
    out
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

/// Part 3 clause 6.1: "If the tag of the command is not a recognized command
/// tag, the TPM error response will differ depending on TPM 1.2 compatibility.
/// If the TPM supports 1.2 compatibility, the TPM shall return a tag of
/// TPM_TAG_RSP_COMMAND and an appropriate TPM 1.2 response code (TPM_BADTAG =
/// 00 00 00 1E). If the TPM does not have compatibility with TPM 1.2, the TPM
/// shall return TPM_ST_NO_SESSION and a response code of TPM_RC_TAG." This TPM
/// has no 1.2 compatibility.
#[test]
fn a_bad_tag_is_reported_as_a_tpm_without_1_2_compatibility_reports_it() {
    let h = Harness::started("badtag");
    // TPM_TAG_RQU_COMMAND is what a caller that expects a TPM 1.2 sends, which
    // is how firmware tells the two families apart. The response is in the
    // shape of this family, so that the caller learns which one answered.
    let mut w = Writer::new();
    w.u16(0x00c1);
    w.u32(10);
    w.u32(cc::GetRandom);
    let r = h.send(&w.finish().unwrap());
    assert_eq!(r.code, rc::TAG);
    assert_eq!(r.tag, st::NO_SESSIONS);
    assert_ne!(
        r.tag,
        st::RSP_COMMAND,
        "a caller that expects a TPM 1.2 must not read this as one"
    );

    // A tag this family defines but which is not a command tag is refused the
    // same way.
    let mut w = Writer::new();
    w.u16(st::NULL);
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

/// Ask for an ECC primary key on P-256 with the given attributes, scheme and
/// kdf, and give back the whole response so a refusal can be read.
///
/// Part 1 clause 44.4.1 says an ECC key "can be used as a Key Encapsulation
/// Mechanism (KEM) key" if its kdf is not TPM_ALG_NULL, and Part 2 Table 229
/// gives that field to "an unrestricted decryption TPM_ALG_ECDH key" and says
/// it "shall be NULL in all other cases (TPM_RC_KDF)".
fn ask_for_ecc_key(h: &Harness, attrs: u32, scheme: u16, kdf: Option<u16>) -> Answer {
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256); // nameAlg
    t.u32(attrs);
    t.u16(0); // authPolicy
    t.u16(alg::NULL); // symmetric
    t.u16(scheme);
    if scheme != alg::NULL {
        t.u16(alg::SHA256); // the scheme's hash
    }
    t.u16(swtrust::tpm::constants::curve::NIST_P256);
    match kdf {
        Some(hash) => {
            t.u16(alg::HKDF);
            t.u16(hash);
        }
        None => t.u16(alg::NULL),
    }
    t.u16(0); // unique x
    t.u16(0); // unique y
    let template = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(4); // inSensitive
    p.u16(0); // userAuth
    p.u16(0); // data
    p.u16(template.len() as u16);
    p.bytes(&template);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::OWNER],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ))
}

/// An unrestricted ECDH decryption key, which is what a KEM key is.
fn ecc_kem_key(h: &Harness, kdf: Option<u16>) -> u32 {
    let scheme = if kdf.is_some() { alg::ECDH } else { alg::NULL };
    // fixedTPM fixedParent sensitiveDataOrigin userWithAuth decrypt
    let r = ask_for_ecc_key(h, 0x0002_0072, scheme, kdf);
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]])
}

#[test]
fn only_an_unrestricted_ecdh_decryption_key_may_name_a_kdf() {
    // Part 2 Table 229: the kdf field belongs to "an unrestricted decryption
    // TPM_ALG_ECDH key" and "shall be NULL in all other cases (TPM_RC_KDF)".
    let h = Harness::started("kemkdf");
    // A restricted key, which is a storage key rather than a KEM key.
    let r = ask_for_ecc_key(&h, 0x0003_0072, alg::ECDH, Some(alg::SHA256));
    assert_eq!(r.code, rc::KDF | 0x040 | (2 << 8), "restricted -> {:08x}", r.code);
    // A signing key, which does not decrypt.
    let r = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, Some(alg::SHA256));
    assert_eq!(r.code, rc::KDF | 0x040 | (2 << 8), "signing -> {:08x}", r.code);
    // A decryption key whose scheme is not ECDH.
    let r = ask_for_ecc_key(&h, 0x0002_0072, alg::NULL, Some(alg::SHA256));
    assert_eq!(r.code, rc::KDF | 0x040 | (2 << 8), "not ECDH -> {:08x}", r.code);
    // The one the table describes.
    let r = ask_for_ecc_key(&h, 0x0002_0072, alg::ECDH, Some(alg::SHA256));
    assert_eq!(r.code, rc::SUCCESS, "an ECDH decryption key -> {:08x}", r.code);
}

#[test]
fn a_kem_key_encapsulates_and_decapsulates_the_same_secret() {
    let h = Harness::started("kem");
    // An unrestricted decryption key with a kdf, which is what Part 2 Table 195
    // makes usable with these two commands.
    let handle = ecc_kem_key(&h, Some(alg::SHA256));

    let r = h.send(&command(st::NO_SESSIONS, cc::Encapsulate, &[handle], None, &[]));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Encapsulate -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let secret_size = reader.u16().unwrap() as usize;
    let secret = reader.take(secret_size).unwrap().to_vec();
    assert_eq!(secret_size, 32, "the shared secret is a SHA-256 worth");

    // Part 1 clause 44.4.2 item 6 returns pkE_serialized as the ciphertext, and
    // item 3.1 says "for NIST P-curves, the serialization of a point is
    // (0x04 || X || Y)", so on P-256 that is 65 octets inside the one size
    // TPM2B_KEM_CIPHERTEXT carries.
    let ct_size = reader.u16().unwrap() as usize;
    let ciphertext = reader.take(ct_size).unwrap().to_vec();
    assert!(reader.is_empty(), "the response has more after the ciphertext");
    assert_eq!(ct_size, 65, "the ciphertext is not an uncompressed point");
    assert_eq!(ciphertext[0], 0x04, "the point is not uncompressed");

    // The same ciphertext must give the same secret back.
    let mut p = Writer::new();
    p.u16(ct_size as u16);
    p.bytes(&ciphertext);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Decapsulate,
        &[handle],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Decapsulate -> {:08x}", r.code);
    let mut reader = Reader::new(&r.body);
    let _parameter_size = reader.u32().unwrap();
    let size = reader.u16().unwrap() as usize;
    assert_eq!(reader.take(size).unwrap(), &secret[..], "a different secret came back");
}

#[test]
fn a_key_without_a_kdf_is_not_a_kem_key() {
    // Part 3 clause 14.10.1 and 14.11.1 both say the key "shall be a KEM key
    // (TPM_RC_KEY)", and Part 2 Table 195 makes a non NULL kdf what says so.
    let h = Harness::started("kemnokdf");
    let handle = ecc_kem_key(&h, None);
    // TPM2_Encapsulate takes no authorization; TPM2_Decapsulate uses the key.
    for code in [cc::Encapsulate, cc::Decapsulate] {
        let mut p = Writer::new();
        let (tag, auth) = if code == cc::Decapsulate {
            // A serialized point of the right shape, so the command gets
            // past unmarshalling and reaches the key.
            p.u16(65);
            p.u8(0x04);
            p.bytes(&[0u8; 64]);
            (st::SESSIONS, Some(password(b"")))
        } else {
            (st::NO_SESSIONS, None)
        };
        let r = h.send(&command(
            tag,
            code,
            &[handle],
            auth.as_deref(),
            &p.finish().unwrap(),
        ));
        assert_eq!(
            r.code,
            rc::KEY | (1 << 8),
            "a key with no kdf was taken -> {:08x}",
            r.code
        );
    }
}

#[test]
fn decapsulate_refuses_a_restricted_key() {
    // Part 3 clause 14.11.1: the key "shall be a KEM key (TPM_RC_KEY) with
    // restricted CLEAR and decrypt SET (TPM_RC_ATTRIBUTES)". Without this a
    // storage key would answer as a decapsulation oracle. Such a key cannot
    // name a kdf, so it is refused for its attributes before the question of
    // whether it is a KEM key arises.
    let h = Harness::started("kemrestricted");
    let r = ask_for_ecc_key(&h, 0x0003_0072, alg::NULL, None);
    assert_eq!(r.code, rc::SUCCESS, "a storage key -> {:08x}", r.code);
    let handle = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let mut p = Writer::new();
    p.u16(65);
    p.u8(0x04);
    p.bytes(&[0u8; 64]);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Decapsulate,
        &[handle],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::ATTRIBUTES | (1 << 8),
        "a restricted key decapsulated -> {:08x}",
        r.code
    );
}

#[test]
fn a_public_area_on_its_own_may_say_fixed_tpm() {
    // Part 2 clause 8.3.3.1 says the External column of the attribute table
    // "indicates settings that apply to the inPublic parameter in
    // TPM2_LoadExternal() if both the public and sensitive portions of the
    // object are loaded", and that when only the public portion is loaded "the
    // only attribute checks are the checks in the validation code following
    // Table 37 and the reserved attributes check". The public half of a key
    // that does live on some TPM is loaded this way to compute its Name or to
    // make a credential for it, and it says fixedTPM and restricted.
    let h = Harness::started("external");
    let handle = ecc_kem_key(&h, Some(alg::SHA256));
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ReadPublic,
        &[handle],
        None,
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap() as usize;
    let public = reader.take(size).unwrap().to_vec();

    let mut p = Writer::new();
    p.u16(0); // inPrivate, the Empty Buffer
    p.u16(public.len() as u16);
    p.bytes(&public);
    p.u32(rh::OWNER);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::LoadExternal,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a public area saying fixedTPM was refused -> {:08x}",
        r.code
    );
}

#[test]
fn a_public_only_object_may_be_made_persistent() {
    // Part 3 clause 28.5.1 has a note beside its rules: "older versions of the
    // specification did not allow an object to be persisted when only the
    // public portion of the object was loaded (for NV space efficiency).
    // Support for persisting public-only objects was added in version 185."
    let h = Harness::started("evictpublic");
    let handle = ecc_kem_key(&h, Some(alg::SHA256));
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ReadPublic,
        &[handle],
        None,
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let size = reader.u16().unwrap() as usize;
    let public = reader.take(size).unwrap().to_vec();

    // Load it as an external public area, which gives an object with no
    // sensitive half, and then persist that.
    let mut p = Writer::new();
    p.u16(0);
    p.u16(public.len() as u16);
    p.bytes(&public);
    p.u32(rh::OWNER);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::LoadExternal,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let external = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let mut p = Writer::new();
    p.u32(0x8100_0010);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::OWNER, external],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a public-only object was refused -> {:08x}",
        r.code
    );

    // It has to come back after a restart, which is where the restore
    // validation runs.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS, "the state did not load -> {:08x}", r.code);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ReadPublic,
        &[0x8100_0010],
        None,
        &[],
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "the persistent object did not survive -> {:08x}",
        r.code
    );
}

#[test]
fn a_context_of_a_state_clear_object_does_not_survive_startup_clear() {
    // Part 1 clause 30.4.2: "objects that have the stateClear property are
    // invalidated by Startup(CLEAR). To enforce this, the TPM will include
    // clearCount in the integrity value of the Object."
    let h = Harness::started("stclearctx");
    // fixedTPM fixedParent sensitiveDataOrigin userWithAuth sign, with stClear.
    let r = ask_for_ecc_key(&h, 0x0004_0076, alg::ECDSA, None);
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let handle = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[handle], None, &[]));
    assert_eq!(r.code, rc::SUCCESS, "ContextSave -> {:08x}", r.code);
    let context = r.body.clone();
    // Clause 30.4.2 item 3 gives such an object its own savedHandle value.
    let saved_handle = u32::from_be_bytes([
        context[8],
        context[9],
        context[10],
        context[11],
    ]);
    assert_eq!(saved_handle, 0x8000_0002, "the context does not say stateClear");

    // The same context loads while the count stands still.
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_eq!(r.code, rc::SUCCESS, "ContextLoad -> {:08x}", r.code);

    // A Startup(CLEAR) advances the count, and the context stops verifying.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_ne!(
        r.code,
        rc::SUCCESS,
        "a stateClear context survived Startup(CLEAR)"
    );
}

#[test]
fn a_state_clear_object_may_not_be_made_persistent() {
    // Part 3 clause 28.5.1 rule 1.2 refuses an object when "the stClear is SET
    // in the object or in an ancestor key".
    let h = Harness::started("stclearevict");
    let r = ask_for_ecc_key(&h, 0x0004_0076, alg::ECDSA, None);
    assert_eq!(r.code, rc::SUCCESS);
    let handle = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let mut p = Writer::new();
    p.u32(0x8100_0020);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::OWNER, handle],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::ATTRIBUTES | (2 << 8),
        "a stClear object was persisted -> {:08x}",
        r.code
    );
}

#[test]
fn an_owner_object_is_not_persisted_under_platform_authorization() {
    // Part 3 clause 28.5.1 rule 2: "if auth is TPM_RH_PLATFORM, the proper
    // hierarchy is the Platform hierarchy. If auth is TPM_RH_OWNER, the proper
    // hierarchy is either the Storage or the Endorsement hierarchy."
    let h = Harness::started("evicthierarchy");
    let handle = ecc_kem_key(&h, None);

    let mut p = Writer::new();
    p.u32(0x8180_0001);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::PLATFORM, handle],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::HIERARCHY | (2 << 8),
        "the platform persisted an owner object -> {:08x}",
        r.code
    );
}

#[test]
fn the_platform_may_remove_a_persistent_object_the_owner_made() {
    // Rule 8: "if auth is TPM_RH_OWNER, objectHandle shall be in the inclusive
    // range of 81 00 00 00 to 81 7F FF FF. If auth is TPM_RH_PLATFORM,
    // objectHandle may be any valid persistent object handle."
    let h = Harness::started("evictremove");
    let handle = ecc_kem_key(&h, None);

    let mut p = Writer::new();
    p.u32(0x8100_0030);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::OWNER, handle],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "EvictControl -> {:08x}", r.code);

    let mut p = Writer::new();
    p.u32(0x8100_0030);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::PLATFORM, 0x8100_0030],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "the platform could not remove it -> {:08x}",
        r.code
    );
}

#[test]
fn a_reset_invalidates_every_context_and_a_restart_only_the_state_clear_ones() {
    // Part 1 Equation 52 puts resetValue in front of every context and adds
    // clearCount only for a saved handle of 80 00 00 02. resetValue "increments
    // on each TPM Reset", clearCount "is incremented on each TPM Restart", and
    // Part 2 clause 8.3.3.3 says a saved context of an object without stClear
    // survives when "the TPM received TPM2_Shutdown(TPM_SU_STATE)".
    let h = Harness::started("resetvalue");
    let plain = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, None);
    assert_eq!(plain.code, rc::SUCCESS);
    let plain = u32::from_be_bytes([plain.body[0], plain.body[1], plain.body[2], plain.body[3]]);
    let stc = ask_for_ecc_key(&h, 0x0004_0076, alg::ECDSA, None);
    assert_eq!(stc.code, rc::SUCCESS);
    let stc = u32::from_be_bytes([stc.body[0], stc.body[1], stc.body[2], stc.body[3]]);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[plain], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let plain_context = r.body.clone();
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[stc], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let stc_context = r.body.clone();

    // A TPM Restart: Shutdown(STATE) then Startup(CLEAR).
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &plain_context));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a restart invalidated an ordinary context -> {:08x}",
        r.code
    );
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &stc_context));
    assert_ne!(
        r.code,
        rc::SUCCESS,
        "a stateClear context survived a restart"
    );

    // A TPM Reset takes the other one with it.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &plain_context));
    assert_ne!(
        r.code,
        rc::SUCCESS,
        "an ordinary context survived a reset"
    );
}

#[test]
fn a_child_of_a_state_clear_parent_carries_the_property() {
    // Part 1 clause 30.4.2: "an Object has the stateClear property when stClear
    // is SET in the Object or in any of its ancestor keys." The child below
    // does not say stClear itself, so only inheritance can give it the
    // property, and TPM2_EvictControl is where that shows.
    let h = Harness::started("inherit");
    // A storage key with stClear, to be the parent. A storage key names a
    // symmetric algorithm, which is what makes it able to protect a child.
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    t.u32(0x0003_0076); // fixedTPM fixedParent sensitiveDataOrigin userWithAuth
                        // restricted decrypt, with stClear
    t.u16(0); // authPolicy
    t.u16(alg::AES);
    t.u16(128);
    t.u16(alg::CFB);
    t.u16(alg::NULL); // scheme
    t.u16(swtrust::tpm::constants::curve::NIST_P256);
    t.u16(alg::NULL); // kdf
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
    assert_eq!(r.code, rc::SUCCESS, "the parent -> {:08x}", r.code);
    let parent = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    // TPM2_CreateLoaded makes the child under it in one step.
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    t.u32(0x0004_0072); // fixedTPM fixedParent userWithAuth sign, no stClear
    t.u16(0); // authPolicy
    t.u16(alg::NULL); // symmetric
    t.u16(alg::ECDSA);
    t.u16(alg::SHA256);
    t.u16(swtrust::tpm::constants::curve::NIST_P256);
    t.u16(alg::NULL); // kdf
    t.u16(0);
    t.u16(0);
    let template = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(4); // inSensitive
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(&template);
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreateLoaded,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreateLoaded -> {:08x}", r.code);
    let child = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    // Part 3 clause 28.5.1 rule 1.2 refuses an object when stClear is set "in
    // the object or in an ancestor key".
    let mut p = Writer::new();
    p.u32(0x8100_0040);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::OWNER, child],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::ATTRIBUTES | (2 << 8),
        "the child did not inherit stateClear -> {:08x}",
        r.code
    );

    // Its saved context says so too.
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[child], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let saved_handle =
        u32::from_be_bytes([r.body[8], r.body[9], r.body[10], r.body[11]]);
    assert_eq!(
        saved_handle, 0x8000_0002,
        "the context does not say stateClear"
    );
}

#[test]
fn a_kem_key_names_the_hash_its_curve_is_registered_with() {
    // Part 2 Table 229 makes the KEM "equivalent to DHKEM(curveID, kdf) from
    // RFC 9180", which registers one hash per curve, and answers a KDF the TPM
    // does not support with TPM_RC_KDF where the key is described.
    let h = Harness::started("kemsuite");
    let r = ask_for_ecc_key(&h, 0x0002_0072, alg::ECDH, Some(alg::SHA384));
    assert_eq!(
        r.code,
        rc::KDF | 0x040 | (2 << 8),
        "P-256 took SHA-384 -> {:08x}",
        r.code
    );
    let r = ask_for_ecc_key(&h, 0x0002_0072, alg::ECDH, Some(alg::SHA256));
    assert_eq!(r.code, rc::SUCCESS, "P-256 with SHA-256 -> {:08x}", r.code);
}

#[test]
fn a_saved_session_survives_a_restart_and_not_a_reset() {
    // Part 1 clause 27.5: "saved session contexts are not invalidated and may
    // be reloaded after a TPM Restart or TPM Resume. Saved session contexts are
    // invalidated on a TPM Reset." A session is protected under the NULL
    // hierarchy, so this is what says nullProof may not change on a restart.
    let h = Harness::started("sessionctx");
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]); // nonceCaller
    p.u16(0); // encryptedSalt
    p.u8(se::HMAC);
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
    let session = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[session], None, &[]));
    assert_eq!(r.code, rc::SUCCESS, "ContextSave -> {:08x}", r.code);
    let context = r.body.clone();

    // A TPM Restart: Shutdown(STATE) then Startup(CLEAR).
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a restart invalidated a saved session -> {:08x}",
        r.code
    );

    // A TPM Reset does invalidate it.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_ne!(r.code, rc::SUCCESS, "a saved session survived a reset");
}

#[test]
fn clear_changes_the_endorsement_proof_but_not_its_seed() {
    // Part 3 clause 24.6.1: TPM2_Clear will "change the storage primary seed
    // (SPS) to a new value" and "change shProof and ehProof". The Endorsement
    // Primary Seed is not in that list, so an endorsement primary key comes
    // back the same while a context saved under that hierarchy does not.
    let h = Harness::started("clearproof");
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    t.u32(0x0004_0072); // fixedTPM fixedParent userWithAuth sign
    t.u16(0);
    t.u16(alg::NULL);
    t.u16(alg::ECDSA);
    t.u16(alg::SHA256);
    t.u16(swtrust::tpm::constants::curve::NIST_P256);
    t.u16(alg::NULL);
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
    let params = p.finish().unwrap();

    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::ENDORSEMENT],
        Some(&password(b"")),
        &params,
    ));
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let handle = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);
    // Only outPublic: the creation ticket beside it is made with the proof,
    // which does change.
    let size = u16::from_be_bytes([r.body[8], r.body[9]]) as usize;
    let public_before = r.body[10..10 + size].to_vec();

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[handle], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let context = r.body.clone();

    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Clear -> {:08x}", r.code);

    // The seed did not change, so the same template gives the same key.
    let r = h.send(&command(
        st::SESSIONS,
        cc::CreatePrimary,
        &[rh::ENDORSEMENT],
        Some(&password(b"")),
        &params,
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let size = u16::from_be_bytes([r.body[8], r.body[9]]) as usize;
    assert_eq!(
        r.body[10..10 + size].to_vec(),
        public_before,
        "TPM2_Clear changed the endorsement seed"
    );

    // The proof did, so the context saved under it no longer verifies.
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_ne!(
        r.code,
        rc::SUCCESS,
        "an endorsement context survived TPM2_Clear"
    );
}

#[test]
fn test_parms_refuses_a_kem_the_tpm_cannot_run() {
    // Part 2 Table 229 says of an ECC key's kdf that "in the context of object
    // creation, TPM2_LoadExternal(), or TPM2_TestParms(), TPM_RC_KDF indicates
    // the TPM does not support the requested KDF".
    let h = Harness::started("testparms");
    let mut p = Writer::new();
    p.u16(alg::ECC);
    p.u16(alg::NULL); // symmetric
    p.u16(alg::ECDH); // scheme
    p.u16(alg::SHA256);
    p.u16(swtrust::tpm::constants::curve::NIST_P256);
    p.u16(alg::HKDF);
    p.u16(alg::SHA384); // the hash P-256 is not registered with
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::TestParms,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::KDF | 0x040 | (1 << 8),
        "TestParms took a KEM the TPM cannot run -> {:08x}",
        r.code
    );

    let mut p = Writer::new();
    p.u16(alg::ECC);
    p.u16(alg::NULL);
    p.u16(alg::ECDH);
    p.u16(alg::SHA256);
    p.u16(swtrust::tpm::constants::curve::NIST_P256);
    p.u16(alg::HKDF);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::TestParms,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "the registered pair -> {:08x}", r.code);
}

#[test]
fn a_startup_flushes_every_transient_context() {
    // Part 3 clause 9.3.3: on any TPM2_Startup "all transient contexts
    // (objects, sessions, and sequences) shall be flushed from TPM memory".
    // The command can be reached without the platform cycling the power, so
    // the flush belongs to the command and not to the power.
    let h = Harness::started("startupflush");
    let handle = ecc_kem_key(&h, None);
    let r = h.send(&command(st::NO_SESSIONS, cc::ReadPublic, &[handle], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);

    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    // No power cycle: the next command is the startup itself.
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS, "Startup(STATE) -> {:08x}", r.code);

    let r = h.send(&command(st::NO_SESSIONS, cc::ReadPublic, &[handle], None, &[]));
    assert_ne!(
        r.code,
        rc::SUCCESS,
        "a loaded object survived TPM2_Startup"
    );
}

#[test]
fn a_restart_leaves_the_pcr_update_counter_alone() {
    // Part 3 clause 9.3.2 has a TPM Reset clear pcrUpdateCounter to zero, and
    // the note in clause 9.3.3 says of a TPM Restart that "the PCR Update
    // Counter (pcrUpdateCounter) is not modified".
    let h = Harness::started("restartpcr");
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&alg::SHA256.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    let mut p = Writer::new();
    p.bytes(&body);
    let r = h.send(&command(
        st::SESSIONS,
        cc::PCR_Extend,
        &[hc::PCR_FIRST + 8],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "PCR_Extend -> {:08x}", r.code);
    let before = pcr_update_counter(&h);
    assert_ne!(before, 0, "the extend did not move the counter");

    // A TPM Restart: Shutdown(STATE) then Startup(CLEAR).
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(
        pcr_update_counter(&h),
        before,
        "a restart moved the PCR update counter"
    );

    // A TPM Reset clears it.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(pcr_update_counter(&h), 0, "a reset did not clear the counter");
}

#[test]
fn a_saved_session_outlives_clear() {
    // Part 1 clause 27.1: "saved session contexts remain valid until the
    // session is closed, or TPM Reset." TPM2_Clear is neither of those, and a
    // session is protected under the NULL hierarchy rather than under the seed
    // the command replaces.
    let h = Harness::started("clearsession");
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    p.u8(se::HMAC);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let session = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[session], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let context = r.body.clone();

    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Clear -> {:08x}", r.code);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "TPM2_Clear invalidated a saved session -> {:08x}",
        r.code
    );
}

#[test]
fn stir_random_takes_the_hundred_and_twenty_eight_octets_it_is_given() {
    // Part 3 Table 77 gives inData as a TPM2B_SENSITIVE_DATA and clause 16.2.1
    // says it "may not be larger than 128 octets".
    let h = Harness::started("stir");
    for size in [1usize, 64, 128] {
        let mut p = Writer::new();
        p.u16(size as u16);
        p.bytes(&vec![0x5au8; size]);
        let r = h.send(&command(
            st::NO_SESSIONS,
            cc::StirRandom,
            &[],
            None,
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "{size} octets -> {:08x}", r.code);
    }
    let mut p = Writer::new();
    p.u16(129);
    p.bytes(&vec![0x5au8; 129]);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StirRandom,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_ne!(r.code, rc::SUCCESS, "129 octets were taken");
}

#[test]
fn a_session_bound_to_an_object_outlives_it() {
    // Part 1 clause 27.5: a session "is active until closed by the
    // continueSession flag being FALSE or until the session context is flushed
    // from the TPM by TPM2_FlushContext()". Flushing the object it was bound
    // to is neither.
    let h = Harness::started("boundflush");
    let object = ecc_kem_key(&h, None);

    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    p.u8(se::HMAC);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, object],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "StartAuthSession -> {:08x}", r.code);
    let session = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let mut p = Writer::new();
    p.u32(object);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::FlushContext,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "FlushContext -> {:08x}", r.code);

    // The session is still there, which saving its context proves.
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[session], None, &[]));
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "the session went with the object -> {:08x}",
        r.code
    );
}

#[test]
fn read_only_mode_refuses_what_table_207_names() {
    // Part 3 clause 24.9.1: in Read-Only mode the TPM "will return
    // TPM_RC_READ_ONLY on any attempt to create new objects, to define new NV
    // space, and to modify existing NV space", and Part 1 clause 42.2 has the
    // refusal come "before performing authorization checks".
    let h = Harness::started("readonly");
    let mut p = Writer::new();
    p.u8(1);
    let r = h.send(&command(
        st::SESSIONS,
        cc::ReadOnlyControl,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "ReadOnlyControl -> {:08x}", r.code);

    // Creating an object is not permitted.
    let r = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, None);
    assert_eq!(r.code, rc::READ_ONLY, "CreatePrimary -> {:08x}", r.code);

    // Nor is defining NV space. The authorization here is deliberately wrong,
    // because the refusal comes before it is looked at.
    let mut p = Writer::new();
    p.u16(0); // auth
    p.u16(14); // publicInfo
    p.u32(0x01c0_0001);
    p.u16(alg::SHA256);
    p.u32(0x2000_0002);
    p.u16(0);
    p.u16(8);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_DefineSpace,
        &[rh::OWNER],
        Some(&password(b"wrong")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::READ_ONLY, "NV_DefineSpace -> {:08x}", r.code);

    // Reading is permitted.
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0x00, 0x08]));
    assert_eq!(r.code, rc::SUCCESS, "GetRandom -> {:08x}", r.code);

    // Table 207 permits TPM2_NV_Write "only when the NV index is defined with
    // TPMA_NV_ORDERLY and TPMA_NV_CLEAR_STCLEAR", whose data goes away on the
    // next reset in any case. The Index below has neither.
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_Write,
        &[hc::NV_INDEX_FIRST, hc::NV_INDEX_FIRST],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::HANDLE | (1 << 8),
        "a write to an Index that is not there was not reported as such -> {:08x}",
        r.code
    );

    // Part 1 clause 42.2: the mode "will remain enabled during TPM Resume".
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, None);
    assert_eq!(r.code, rc::READ_ONLY, "a resume left Read-Only mode");

    // A TPM Restart takes it away.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    let r = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, None);
    assert_eq!(r.code, rc::SUCCESS, "a restart kept Read-Only mode");
}

/// A TPML_PCR_SELECTION of one bank with the given registers.
fn selection(banks: &[(u16, &[usize])]) -> Vec<u8> {
    let mut p = Writer::new();
    p.u32(banks.len() as u32);
    for (alg, indices) in banks {
        p.u16(*alg);
        p.u8(3);
        let mut bits = [0u8; 3];
        for i in *indices {
            bits[i / 8] |= 1 << (i % 8);
        }
        p.bytes(&bits);
    }
    p.finish().unwrap()
}

#[test]
fn pcr_allocate_changes_only_the_banks_it_names() {
    // Part 3 clause 22.5.1: "this command will only change the allocations of
    // banks that are listed in pcrAllocation", a selection with nothing in it
    // takes a bank away, and "if a bank is listed more than once, then the last
    // selection in the pcrAllocation list is the one that the TPM will attempt
    // to allocate". Part 1 clause 14.8 allocates per register.
    let h = Harness::started("pcralloc");

    // Give SHA-256 two registers and say nothing about SHA-384.
    let r = h.send(&command(
        st::SESSIONS,
        cc::PCR_Allocate,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &selection(&[(alg::SHA256, &[0, 1])]),
    ));
    assert_eq!(r.code, rc::SUCCESS, "PCR_Allocate -> {:08x}", r.code);

    // It takes effect at the next reset.
    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);

    // SHA-256 now has two registers, and asking for a third gets nothing.
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PCR_Read,
        &[],
        None,
        &selection(&[(alg::SHA256, &[0, 1, 2])]),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let _counter = reader.u32().unwrap();
    assert_eq!(reader.u32().unwrap(), 1, "one selection comes back");
    assert_eq!(reader.u16().unwrap(), alg::SHA256);
    let size = reader.u8().unwrap() as usize;
    let bits = reader.take(size).unwrap();
    assert_eq!(bits[0], 0b011, "the reply named registers that are not there");

    // SHA-384 was not listed, so it kept every register it had.
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PCR_Read,
        &[],
        None,
        &selection(&[(alg::SHA384, &[0, 1, 2])]),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let mut reader = Reader::new(&r.body);
    let _counter = reader.u32().unwrap();
    assert_eq!(reader.u32().unwrap(), 1);
    assert_eq!(reader.u16().unwrap(), alg::SHA384);
    let size = reader.u8().unwrap() as usize;
    let bits = reader.take(size).unwrap();
    assert_eq!(
        bits[0], 0b111,
        "a bank the command did not name lost registers"
    );
}

#[test]
fn a_disabled_hierarchy_hides_its_persistent_object_from_every_command() {
    // Part 3 clause 24.3.1: clearing an enable "will disable use of any
    // persistent entity associated with the disabled hierarchy". A command
    // that takes no authorization reaches such an object too, so the check
    // belongs to the handle area rather than to the authorization.
    let h = Harness::started("disabledpersistent");
    let handle = ecc_kem_key(&h, None);
    let mut p = Writer::new();
    p.u32(0x8100_0050);
    let r = h.send(&command(
        st::SESSIONS,
        cc::EvictControl,
        &[rh::OWNER, handle],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "EvictControl -> {:08x}", r.code);

    // TPM2_ReadPublic takes no authorization at all.
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ReadPublic,
        &[0x8100_0050],
        None,
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "ReadPublic -> {:08x}", r.code);

    let mut p = Writer::new();
    p.u32(rh::OWNER);
    p.u8(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyControl,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "HierarchyControl -> {:08x}", r.code);

    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::ReadPublic,
        &[0x8100_0050],
        None,
        &[],
    ));
    assert_eq!(
        r.code,
        rc::HIERARCHY | (1 << 8),
        "a disabled hierarchy's object was still read -> {:08x}",
        r.code
    );

    // The hierarchy's own authorization is barred as well.
    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::OWNER],
        Some(&password(b"")),
        &[],
    ));
    assert_ne!(r.code, rc::SUCCESS, "a disabled hierarchy authorized a command");
}

#[test]
fn an_rsa_exponent_is_odd_and_greater_than_two() {
    // Part 2 Table 228: the exponent is "an odd number greater than 2", and
    // zero names the default rather than being a value of its own. Part 3
    // clause 30.4.1 has TPM2_TestParms answer for parameters the TPM cannot
    // use.
    let h = Harness::started("exponent");
    for (exponent, ok) in [(0u32, true), (65537, true), (2, false), (4, false), (1, false)] {
        let mut p = Writer::new();
        p.u16(alg::RSA);
        p.u16(alg::NULL); // symmetric
        p.u16(alg::NULL); // scheme
        p.u16(2048);
        p.u32(exponent);
        let r = h.send(&command(
            st::NO_SESSIONS,
            cc::TestParms,
            &[],
            None,
            &p.finish().unwrap(),
        ));
        if ok {
            assert_eq!(r.code, rc::SUCCESS, "exponent {exponent} -> {:08x}", r.code);
        } else {
            assert_ne!(r.code, rc::SUCCESS, "exponent {exponent} was accepted");
        }
    }
}

#[test]
fn a_resume_brings_back_the_pcr_the_platform_preserves() {
    // Part 3 clause 9.4.1 has TPM2_Shutdown(TPM_SU_STATE) save the PCR the
    // platform marks preserved along with pcrUpdateCounter, and clause 9.3.3
    // has the resume put them back. The PC Client profile marks PCR 0 to 15.
    let h = Harness::started("resumepcr");
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&alg::SHA256.to_be_bytes());
    body.extend_from_slice(&[0xab; 32]);
    let mut p = Writer::new();
    p.bytes(&body);
    let r = h.send(&command(
        st::SESSIONS,
        cc::PCR_Extend,
        &[hc::PCR_FIRST + 8],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "PCR_Extend -> {:08x}", r.code);

    let read = selection(&[(alg::SHA256, &[8])]);
    let r = h.send(&command(st::NO_SESSIONS, cc::PCR_Read, &[], None, &read));
    assert_eq!(r.code, rc::SUCCESS);
    let before = r.body.clone();

    let r = h.send(&command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = h.send(&command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS, "Startup(STATE) -> {:08x}", r.code);

    let r = h.send(&command(st::NO_SESSIONS, cc::PCR_Read, &[], None, &read));
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(
        r.body, before,
        "the resume did not bring the register back"
    );
}

#[test]
fn a_context_of_a_disabled_hierarchy_does_not_load() {
    // Part 3 clause 28.3.1: "the TPM will return TPM_RC_HIERARCHY if the
    // context is associated with a hierarchy that is disabled."
    let h = Harness::started("ctxhierarchy");
    let handle = ecc_kem_key(&h, None);
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[handle], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let context = r.body.clone();

    // Turn the storage hierarchy off with TPM2_HierarchyControl.
    let mut p = Writer::new();
    p.u32(rh::OWNER);
    p.u8(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyControl,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "HierarchyControl -> {:08x}", r.code);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &context));
    assert_eq!(
        r.code,
        rc::HIERARCHY | 0x040 | (1 << 8),
        "a context of a disabled hierarchy loaded -> {:08x}",
        r.code
    );
}

#[test]
fn an_older_saved_session_context_does_not_load_again() {
    // Part 1 clause 27.5: "a saved session context may only be loaded once",
    // and the counter assigned at each save "serves as a version number for the
    // session context", so the TPM can tell an older blob of the same session
    // from the current one.
    let h = Harness::started("sessionreplay");
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    p.u8(se::HMAC);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let session = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[session], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);
    let first = r.body.clone();

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &first));
    assert_eq!(r.code, rc::SUCCESS, "the first load -> {:08x}", r.code);

    // Saving again gives the session a new version, and the older blob is no
    // longer the one the TPM is tracking.
    let r = h.send(&command(st::NO_SESSIONS, cc::ContextSave, &[session], None, &[]));
    assert_eq!(r.code, rc::SUCCESS);

    let r = h.send(&command(st::NO_SESSIONS, cc::ContextLoad, &[], None, &first));
    assert_ne!(r.code, rc::SUCCESS, "an older session context loaded again");
}

#[test]
fn clear_turns_the_hierarchies_back_on_and_moves_the_pcr_counter() {
    // Part 3 clause 24.6.1 lists "SET shEnable and ehEnable" and ends with
    // "increment pcrUpdateCounter", the second so that a policy session built
    // on TPM2_PolicyPCR stops being usable.
    let h = Harness::started("clearflags");
    let before = pcr_update_counter(&h);

    let mut p = Writer::new();
    p.u32(rh::OWNER);
    p.u8(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::HierarchyControl,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    // With the hierarchy off, a primary key of it cannot be made.
    let r = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, None);
    assert_ne!(r.code, rc::SUCCESS, "a disabled hierarchy made a key");

    let r = h.send(&command(
        st::SESSIONS,
        cc::Clear,
        &[rh::PLATFORM],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(r.code, rc::SUCCESS, "TPM2_Clear -> {:08x}", r.code);

    let r = ask_for_ecc_key(&h, 0x0004_0072, alg::ECDSA, None);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "TPM2_Clear did not set shEnable -> {:08x}",
        r.code
    );
    assert_ne!(
        pcr_update_counter(&h),
        before,
        "TPM2_Clear did not move pcrUpdateCounter"
    );
}

/// The pcrUpdateCounter, read through TPM2_PCR_Read.
fn pcr_update_counter(h: &Harness) -> u32 {
    let mut p = Writer::new();
    p.u32(0); // an empty selection is enough to be told the counter
    let r = h.send(&command(st::NO_SESSIONS, cc::PCR_Read, &[], None, &p.finish().unwrap()));
    assert_eq!(r.code, rc::SUCCESS, "PCR_Read -> {:08x}", r.code);
    u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]])
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

    // A second, different command code is taken by a trial session, which the
    // note beside Part 3 clause 23.1 allows: "Policy context other than the
    // policySession->policyDigest may be updated for a trial policy but it is
    // not required", and such a session returns TPM_RC_SUCCESS "unless there is
    // an unmarshaling error in the parameters of the command". The refusal a
    // real session makes is checked in
    // the_assertions_that_share_the_cp_hash_exclude_one_another.
    let mut p = Writer::new();
    p.u32(cc::Quote);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyCommandCode,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "a trial session was held to the first code");

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
fn an_error_in_a_parameter_carries_its_number() {
    // Part 2 clause 6.6.2 works the example through: startupType is the first
    // parameter, so TPM_RC_1 (0x100) plus TPM_RC_P (0x040) is 0x140, and
    // TPM_RC_VALUE (0x080 + 0x004) with it is 0x1c4.
    let h = Harness::new("numbered");
    h.tpm.power_on();
    let mut p = Writer::new();
    p.u16(0x00ff);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::Startup,
        &[],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, 0x1c4, "TPM2_Startup -> {:08x}", r.code);

    // A parameter that cannot be unmarshalled is that parameter's error too,
    // not an unattributed one. TPM2_StartAuthSession names TPM_ALG_AES in its
    // symmetric, the fourth parameter, and then stops before its keyBits, so
    // the TPM runs out of octets inside that one parameter.
    let h = Harness::started("numbered2");
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]); // nonceCaller
    p.u16(0); // encryptedSalt
    p.u8(se::HMAC);
    p.u16(alg::AES); // symmetric, cut short of keyBits and mode
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::INSUFFICIENT | 0x040 | (4 << 8),
        "TPM2_StartAuthSession -> {:08x}",
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


#[test]
fn a_derived_rsa_template_reports_the_required_error_first() {
    // Part 1 clause 5 says "the order in which checks are performed is not
    // normative", so a template that breaks two rules could be answered with
    // either code and this test pins down the choice rather than a
    // requirement. Clause 12.9.1 requires sensitiveDataOrigin to be CLEAR and
    // only permits TPM_RC_TYPE for an RSA key ("the TPM may return"), so the
    // required answer is the more useful one to give.
    let h = Harness::started("derive-order");
    let parent = load_derivation_parent(&h);

    let mut t = Writer::new();
    t.u16(0x0001); // TPM_ALG_RSA
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000); // sensitiveDataOrigin SET
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
        rc::ATTRIBUTES | 0x080 | 0x040 | (2 << 8),
        "the permitted error was chosen over the required one: {:#x}",
        r.code
    );
}

#[test]
fn make_credential_refuses_a_derivation_parent() {
    // Part 3 clause 12.6.1: "The loaded public area referenced by handle is
    // required to be the public area of a Storage key." Part 1 clause 20.2
    // puts a keyed hash parent in the other class, so it is not one.
    let h = Harness::started("makecredential-parent");
    let parent = load_derivation_parent(&h);

    let mut p = Writer::new();
    p.u16(32); // credential
    p.bytes(&[0xaa; 32]);
    p.u16(34); // objectName
    p.bytes(&[0x00, 0x0b]);
    p.bytes(&[0xbb; 32]);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::MakeCredential,
        &[parent],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::TYPE | 0x080 | (1 << 8),
        "a derivation parent protected a credential: {:#x}",
        r.code
    );
}

#[test]
fn load_refuses_an_object_that_can_neither_sign_nor_decrypt() {
    // Part 3 clause 12.2.1 repeats the creation rule for TPM2_Load: "If the
    // Object is a not a keyedHash object, and the sign and encrypt attributes
    // are CLEAR, the TPM shall return TPM_RC_ATTRIBUTES."
    let h = Harness::started("load-inert");

    // A parent to load under, and a child made through it.
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
    assert_eq!(r.code, rc::SUCCESS);
    let parent = Reader::new(&r.body).u32().unwrap();

    // An ECC signing child, created normally.
    let mut t = Writer::new();
    t.u16(0x0023); // TPM_ALG_ECC
    t.u16(alg::SHA256);
    t.u32(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000); // sign
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric TPM_ALG_NULL
    t.u16(0x0018); // scheme TPM_ALG_ECDSA
    t.u16(alg::SHA256);
    t.u16(0x0003); // curve NIST P-256
    t.u16(0x0010); // kdf TPM_ALG_NULL
    t.u16(0);
    t.u16(0);
    let child = t.finish().unwrap();

    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(child.len() as u16);
    p.bytes(&child);
    p.u16(0);
    p.u32(0);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Create,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "Create -> {:#x}", r.code);
    let mut reader = Reader::new(&r.body);
    let _param = reader.u32().unwrap();
    let private_size = reader.u16().unwrap() as usize;
    let private = reader.take(private_size).unwrap().to_vec();
    let public_size = reader.u16().unwrap() as usize;
    let public = reader.take(public_size).unwrap().to_vec();

    // It loads as it stands.
    let load = |public: &[u8]| {
        let mut p = Writer::new();
        p.u16(private.len() as u16);
        p.bytes(&private);
        p.u16(public.len() as u16);
        p.bytes(public);
        h.send(&command(
            st::SESSIONS,
            cc::Load,
            &[parent],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ))
    };
    assert_eq!(load(&public).code, rc::SUCCESS, "the child does not load");

    // With sign cleared it can do nothing, and the load is refused before the
    // integrity of the private area is even reached.
    let mut inert = public.clone();
    let attrs = u32::from_be_bytes([inert[4], inert[5], inert[6], inert[7]]);
    let cleared = (attrs & !0x0004_0000u32).to_be_bytes();
    inert[4..8].copy_from_slice(&cleared);
    assert_eq!(
        load(&inert).code,
        rc::ATTRIBUTES | 0x080 | 0x040 | (2 << 8),
        "an object that can do nothing was loaded"
    );
}



/// Part 3 clause 23.23.1: TPM2_PolicyCapability is an immediate assertion. "The
/// TPM will use the parameters of this command to fetch the indicated property
/// that is used by the TPM in the requested logical operation... If the
/// operands do not have the desired relationship, then the TPM returns
/// TPM_RC_POLICY."
#[test]
fn a_capability_assertion_is_held_to_the_property_the_tpm_reports() {
    use swtrust::tpm::constants::eo;

    let h = Harness::started("policycap");

    let session = |trial: bool| -> u32 {
        let mut p = Writer::new();
        p.u16(16);
        p.bytes(&[0u8; 16]);
        p.u16(0);
        p.u8(if trial { se::TRIAL } else { se::POLICY });
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
        u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]])
    };

    let assert_capability =
        |handle: u32, operand: &[u8], offset: u16, operation: u16, capability: u32, property: u32| {
            let mut p = Writer::new();
            p.u16(operand.len() as u16);
            p.bytes(operand);
            p.u16(offset);
            p.u16(operation);
            p.u32(capability);
            p.u32(property);
            h.send(&command(
                st::NO_SESSIONS,
                cc::PolicyCapability,
                &[handle],
                None,
                &p.finish().unwrap(),
            ))
        };

    // The manufacturer this TPM reports, read the way the example beside
    // Table 184 reads TPM_PT_REVISION: TPMS_TAGGED_PROPERTY is the property and
    // then the value, so an offset of 4 reaches the value.
    let s = session(false);
    let r = assert_capability(s, b"SWT ", 4, eo::EQ, cap::TPM_PROPERTIES, pt::MANUFACTURER);
    assert_eq!(r.code, rc::SUCCESS, "the manufacturer did not match -> {:08x}", r.code);

    // The same property with a value the TPM does not have.
    let r = assert_capability(s, b"XXXX", 4, eo::EQ, cap::TPM_PROPERTIES, pt::MANUFACTURER);
    assert_eq!(r.code, rc::POLICY, "an assertion that is false was allowed");

    // And the tag of the structure itself, which sits at offset zero.
    let r = assert_capability(
        s,
        &pt::MANUFACTURER.to_be_bytes(),
        0,
        eo::EQ,
        cap::TPM_PROPERTIES,
        pt::MANUFACTURER,
    );
    assert_eq!(r.code, rc::SUCCESS, "the property tag did not match -> {:08x}", r.code);

    // A property the TPM does not have: refused, "unless the operation is
    // TPM_EO_NEQ".
    let absent = 0x0000_7fffu32;
    let r = assert_capability(s, &[0, 0, 0, 0], 0, eo::EQ, cap::TPM_PROPERTIES, absent);
    assert_eq!(r.code, rc::POLICY, "a property that does not exist was compared");
    let r = assert_capability(s, &[0, 0, 0, 0], 0, eo::NEQ, cap::TPM_PROPERTIES, absent);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "TPM_EO_NEQ was refused a property that does not exist -> {:08x}",
        r.code
    );

    // "If property is other than a value listed above, then the TPM returns
    // TPM_RC_VALUE", and the example names TPM_CAP_PCRS.
    let r = assert_capability(s, &[0, 0, 0, 0], 0, eo::EQ, cap::PCRS, 0);
    assert_eq!(
        r.code,
        rc::VALUE | 0x080 | 0x040 | (4 << 8),
        "TPM_CAP_PCRS was accepted -> {:08x}",
        r.code
    );

    // A property that the capability itself refuses is reported against the
    // parameter that carried it, which Table 185 makes the fifth here and
    // TPM2_GetCapability makes the second.
    let r = assert_capability(s, &[0, 0, 0, 0], 0, eo::EQ, cap::ACT, rh::OWNER);
    assert_eq!(
        r.code,
        rc::VALUE | 0x080 | 0x040 | (5 << 8),
        "the property was reported against another parameter -> {:08x}",
        r.code
    );

    // An offset that reaches past the property structure has no operandA.
    let r = assert_capability(s, &[0, 0, 0, 0], 6, eo::EQ, cap::TPM_PROPERTIES, pt::MANUFACTURER);
    assert_eq!(
        r.code,
        rc::VALUE | 0x080 | 0x040 | (2 << 8),
        "an offset past the structure was accepted -> {:08x}",
        r.code
    );

    // "This command may be used with a trial policy", and clause 23.1 has such
    // a session update "the policySession->policyDigest" while "the indicated
    // validations are not performed", returning TPM_RC_SUCCESS unless the
    // parameters failed to unmarshal. The policy being computed is for the TPM
    // it will be used on, which may hold properties this one does not.
    let t = session(true);
    let r = assert_capability(t, b"XXXX", 4, eo::EQ, cap::TPM_PROPERTIES, pt::MANUFACTURER);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a trial policy was held to the assertion -> {:08x}",
        r.code
    );
    let r = assert_capability(t, &[0, 0, 0, 0], 0, eo::EQ, cap::PCRS, 0);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a trial policy was held to the capability it named -> {:08x}",
        r.code
    );
    let r = assert_capability(t, &[0, 0, 0, 0], 999, eo::EQ, cap::TPM_PROPERTIES, absent);
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a trial policy was held to the offset it gave -> {:08x}",
        r.code
    );

    // The digest a trial session reaches is the one the real session has, so a
    // policy built with a trial can be satisfied by the assertion itself.
    let digest = |handle: u32| -> Vec<u8> {
        let r = h.send(&command(st::NO_SESSIONS, cc::PolicyGetDigest, &[handle], None, &[]));
        assert_eq!(r.code, rc::SUCCESS);
        r.body[2..].to_vec()
    };
    let t2 = session(true);
    let r = assert_capability(t2, b"SWT ", 4, eo::EQ, cap::TPM_PROPERTIES, pt::MANUFACTURER);
    assert_eq!(r.code, rc::SUCCESS);
    let s2 = session(false);
    let r = assert_capability(s2, b"SWT ", 4, eo::EQ, cap::TPM_PROPERTIES, pt::MANUFACTURER);
    assert_eq!(r.code, rc::SUCCESS);
    assert_eq!(
        digest(t2),
        digest(s2),
        "a trial policy and a real one reached different digests"
    );
}


/// Part 3 clauses 23.13.1, 23.14.1, 23.21.1 and 23.24.1: only one of a bound
/// session, TPM2_PolicyCpHash, TPM2_PolicyNameHash, TPM2_PolicyParameters and
/// TPM2_PolicyTemplate "can be used for a policy session. Because they are
/// mutually exclusive, they can share policySession->cpHash."
#[test]
fn the_assertions_that_share_the_cp_hash_exclude_one_another() {
    let h = Harness::started("cphashslot");

    // The exclusivity belongs to a session that can authorize: Part 3 clause
    // 23.1 leaves a trial session out of the validations and makes the context
    // they read optional.
    let session = || -> u32 {
        let mut p = Writer::new();
        p.u16(16);
        p.bytes(&[0u8; 16]);
        p.u16(0);
        p.u8(se::POLICY);
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
        u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]])
    };

    let digest = |code: u32, handle: u32, value: &[u8]| -> u32 {
        let mut p = Writer::new();
        p.u16(value.len() as u16);
        p.bytes(value);
        h.send(&command(
            st::NO_SESSIONS,
            code,
            &[handle],
            None,
            &p.finish().unwrap(),
        ))
        .code
    };

    let a = [0xaau8; 32];
    let b = [0xbbu8; 32];
    let sharing = [
        cc::PolicyCpHash,
        cc::PolicyNameHash,
        cc::PolicyParameters,
        cc::PolicyTemplate,
    ];
    for first in sharing {
        for second in sharing {
            let s = session();
            assert_eq!(digest(first, s, &a), rc::SUCCESS, "{first:08x} was refused");
            let expected = if first == second && first == cc::PolicyTemplate {
                // Clause 23.21.1 answers a second templateHash that differs
                // with TPM_RC_VALUE rather than TPM_RC_CPHASH.
                rc::VALUE | 0x080 | 0x040 | (1 << 8)
            } else {
                rc::CPHASH
            };
            assert_eq!(
                digest(second, s, &b),
                expected,
                "{first:08x} then {second:08x} shared the slot"
            );
        }
    }

    // Repeating TPM2_PolicyCpHash with the same value is allowed, which the
    // note in clause 23.13.1 calls a policy expression that is probably
    // improperly formed rather than an error.
    let s = session();
    assert_eq!(digest(cc::PolicyCpHash, s, &a), rc::SUCCESS);
    assert_eq!(
        digest(cc::PolicyCpHash, s, &a),
        rc::SUCCESS,
        "the same cpHashA twice was refused"
    );
    assert_eq!(
        digest(cc::PolicyCpHash, s, &b),
        rc::CPHASH,
        "a second cpHashA replaced the first"
    );

    // The same for TPM2_PolicyTemplate, which the clause reads the same way.
    let s = session();
    assert_eq!(digest(cc::PolicyTemplate, s, &a), rc::SUCCESS);
    assert_eq!(
        digest(cc::PolicyTemplate, s, &a),
        rc::SUCCESS,
        "the same templateHash twice was refused"
    );

    // A session bound to an entity has already used the slot.
    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    p.u8(se::POLICY);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::OWNER],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "StartAuthSession -> {:08x}", r.code);
    let bound = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);
    assert_eq!(
        digest(cc::PolicyCpHash, bound, &a),
        rc::CPHASH,
        "a bound policy session took a cpHash as well"
    );
}


/// Part 2 clause 9.29 gives TPMI_RH_AC the range {AC_FIRST:AC_LAST} and
/// "TPM_RC_VALUE — error returned if the handle is out of range".
#[test]
fn an_attached_component_handle_is_held_to_its_range() {
    let h = Harness::started("achandle");

    let get_capability = |ac: u32| -> u32 {
        let mut p = Writer::new();
        p.u32(0); // capability
        p.u32(1); // count
        h.send(&command(
            st::NO_SESSIONS,
            cc::AC_GetCapability,
            &[ac],
            None,
            &p.finish().unwrap(),
        ))
        .code
    };

    // No attached component is present, so the list comes back empty, but the
    // handle still has to be one that could name one.
    assert_eq!(
        get_capability(hc::AC_FIRST),
        rc::SUCCESS,
        "a handle in range was refused"
    );
    assert_eq!(get_capability(hc::AC_LAST), rc::SUCCESS);
    assert_eq!(
        get_capability(hc::AC_LAST + 1),
        rc::VALUE | 0x080 | (1 << 8),
        "a handle above the range was accepted"
    );
    assert_eq!(
        get_capability(rh::OWNER),
        rc::VALUE | 0x080 | (1 << 8),
        "a permanent handle was taken for an attached component"
    );
}


/// Part 3 clause 23.1: "If the policySession parameter indicates a trial policy
/// session, then the policySession->policyDigest will be updated and the
/// indicated validations are not performed", and the note below it: "Unless
/// there is an unmarshaling error in the parameters of the command, these
/// commands will return TPM_RC_SUCCESS when policySession references a trial
/// session."
#[test]
fn a_trial_session_reaches_the_digest_without_the_validations() {
    use swtrust::tpm::constants::eo;

    let h = Harness::started("trialskip");

    let session = |trial: bool| -> u32 {
        let mut p = Writer::new();
        p.u16(16);
        p.bytes(&[0u8; 16]);
        p.u16(0);
        p.u8(if trial { se::TRIAL } else { se::POLICY });
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
        u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]])
    };
    let digest = |handle: u32| -> Vec<u8> {
        let r = h.send(&command(st::NO_SESSIONS, cc::PolicyGetDigest, &[handle], None, &[]));
        assert_eq!(r.code, rc::SUCCESS);
        r.body[2..].to_vec()
    };
    let counter_timer = |handle: u32, operand: &[u8], offset: u16, operation: u16| -> u32 {
        let mut p = Writer::new();
        p.u16(operand.len() as u16);
        p.bytes(operand);
        p.u16(offset);
        p.u16(operation);
        h.send(&command(
            st::NO_SESSIONS,
            cc::PolicyCounterTimer,
            &[handle],
            None,
            &p.finish().unwrap(),
        ))
        .code
    };

    // Part 3 clause 23.10.1 tells the two offset failures apart: "If the
    // number of octets to be compared overflows the TPMS_TIME_INFO structure,
    // the TPM returns TPM_RC_RANGE. If offset is greater than the size of the
    // marshaled TPMS_TIME_INFO structure, the TPM returns TPM_RC_VALUE." The
    // structure is Time, Clock, resetCount, restartCount and safe.
    let info_size = 8 + 8 + 4 + 4 + 1;
    let s = session(false);
    assert_eq!(
        counter_timer(s, &[0u8; 8], 60, eo::EQ),
        rc::VALUE | 0x080 | 0x040 | (2 << 8),
        "an offset past the structure was not a value error"
    );
    assert_eq!(
        counter_timer(s, &[0u8; 8], info_size - 4, eo::EQ),
        rc::RANGE | 0x080 | 0x040 | (2 << 8),
        "a comparison that overflows the structure was not a range error"
    );
    let t = session(true);
    assert_eq!(
        counter_timer(t, &[0u8; 8], 60, eo::EQ),
        rc::SUCCESS,
        "a trial session was held to the offset"
    );

    // An assertion that is simply false is refused for a real session and not
    // for a trial one. Time is never that large.
    let s2 = session(false);
    assert_eq!(
        counter_timer(s2, &[0xffu8; 8], 0, eo::UNSIGNED_GT),
        rc::POLICY,
        "a real session took an assertion that does not hold"
    );
    let t2 = session(true);
    assert_eq!(counter_timer(t2, &[0xffu8; 8], 0, eo::UNSIGNED_GT), rc::SUCCESS);

    // The digest a trial reaches is the one a real session reaches, because it
    // covers the operand and not what the operand was compared against. Time is
    // always at or above zero, so the real session is satisfied.
    let t3 = session(true);
    let s3 = session(false);
    assert_eq!(counter_timer(t3, &[0u8; 8], 0, eo::UNSIGNED_GE), rc::SUCCESS);
    assert_eq!(counter_timer(s3, &[0u8; 8], 0, eo::UNSIGNED_GE), rc::SUCCESS);
    assert_eq!(
        digest(t3),
        digest(s3),
        "a trial policy and a real one reached different digests"
    );
}


/// Part 3 clause 15.2.1: "keyHandle shall reference a symmetric cipher object
/// (TPM_RC_KEY)... If the mode of the key is not TPM_ALG_NULL, then that is the
/// only mode that can be used with the key and the caller is required to set
/// mode either to TPM_ALG_NULL or to the same mode as the key (TPM_RC_MODE)."
#[test]
fn encrypt_decrypt_names_the_key_and_the_mode_the_way_the_clause_does() {
    let h = Harness::started("encdec");

    // A symmetric key whose mode is fixed to CFB, under a storage parent.
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
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let parent = Reader::new(&r.body).u32().unwrap();

    let mut p = Writer::new();
    p.u16(4); // TPM2B_SENSITIVE_CREATE: an empty auth and no data
    p.u16(0);
    p.u16(0);
    let public = {
        let mut w = Writer::new();
        w.u16(alg::SYMCIPHER);
        w.u16(alg::SHA256);
        // fixedTPM fixedParent sensitiveDataOrigin userWithAuth sign decrypt
        w.u32(0x0000_0002 | 0x0000_0010 | 0x0000_0020 | 0x0000_0040 | 0x0004_0000 | 0x0002_0000);
        w.u16(0); // authPolicy
        w.u16(alg::AES);
        w.u16(128);
        w.u16(alg::CFB);
        w.u16(0); // unique
        w.finish().unwrap()
    };
    p.u16(public.len() as u16);
    p.bytes(&public);
    p.u16(0); // outsideInfo
    p.u32(0); // creationPCR
    let r = h.send(&command(
        st::SESSIONS,
        cc::Create,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "Create -> {:08x}", r.code);

    let mut r2 = Reader::new(&r.body);
    // A response with sessions puts parameterSize before the parameters.
    let _param_size = r2.u32().unwrap();
    let private = {
        let n = r2.u16().unwrap() as usize;
        r2.take(n).unwrap().to_vec()
    };
    let pub_area = {
        let n = r2.u16().unwrap() as usize;
        r2.take(n).unwrap().to_vec()
    };
    let mut p = Writer::new();
    p.u16(private.len() as u16);
    p.bytes(&private);
    p.u16(pub_area.len() as u16);
    p.bytes(&pub_area);
    let r = h.send(&command(
        st::SESSIONS,
        cc::Load,
        &[parent],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "Load -> {:08x}", r.code);
    let key = Reader::new(&r.body).u32().unwrap();

    let encrypt = |handle: u32, mode: u16| -> u32 {
        let mut p = Writer::new();
        p.u8(0); // decrypt
        p.u16(mode);
        p.u16(16); // ivIn
        p.bytes(&[0u8; 16]);
        p.u16(16); // inData
        p.bytes(&[0u8; 16]);
        h.send(&command(
            st::SESSIONS,
            cc::EncryptDecrypt,
            &[handle],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ))
        .code
    };

    // The mode the key fixed, and TPM_ALG_NULL which means that mode.
    assert_eq!(encrypt(key, alg::CFB), rc::SUCCESS, "the fixed mode was refused");
    assert_eq!(encrypt(key, alg::NULL), rc::SUCCESS, "TPM_ALG_NULL was refused");

    // Another mode is TPM_RC_MODE, not TPM_RC_VALUE.
    assert_eq!(
        encrypt(key, alg::CBC),
        rc::MODE | 0x080 | 0x040 | (2 << 8),
        "a mode the key does not have was not a mode error"
    );
    // And a value that is no mode at all is refused the same way.
    assert_eq!(
        encrypt(key, alg::SHA256),
        rc::MODE | 0x080 | 0x040 | (2 << 8),
        "a value that is not a cipher mode was accepted as one"
    );

    // A key that is not a symmetric cipher object is TPM_RC_KEY.
    assert_eq!(
        encrypt(parent, alg::CFB),
        rc::KEY | 0x080 | (1 << 8),
        "a key of another type was not a key error"
    );
}


/// Part 3 clause 23.7.1: for a trial session "the TPM will not check any PCR
/// and will compute policyDigest := H(policyDigest || TPM_CC_PolicyPCR || pcrs
/// || pcrDigest). In this computation, pcrs is the input parameter without
/// modification", because "the pcrs parameter is expected to match the
/// configuration of the TPM for which the policy is being computed which may
/// not be the same as the TPM on which the trial policy is being computed."
#[test]
fn a_trial_policy_pcr_takes_the_selection_it_was_given() {
    let h = Harness::started("trialpcr");

    let session = |kind: u8| -> u32 {
        let mut p = Writer::new();
        p.u16(16);
        p.bytes(&[0u8; 16]);
        p.u16(0);
        p.u8(kind);
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
        u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]])
    };
    let digest = |handle: u32| -> Vec<u8> {
        let r = h.send(&command(st::NO_SESSIONS, cc::PolicyGetDigest, &[handle], None, &[]));
        assert_eq!(r.code, rc::SUCCESS);
        r.body[2..].to_vec()
    };

    // A bank this TPM does not have, named beside one it does. A real session
    // would drop the bank it cannot answer for; a trial keeps the selection.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0xab; 32]); // the caller's pcrDigest
    p.u32(2); // two selections
    p.u16(alg::SHA256);
    p.u8(3);
    p.bytes(&[0x01, 0x00, 0x00]);
    p.u16(alg::SM3_256);
    p.u8(3);
    p.bytes(&[0x01, 0x00, 0x00]);
    let selection = p.finish().unwrap();
    let t = session(se::TRIAL);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyPCR,
        &[t],
        None,
        &selection,
    ));
    assert_eq!(r.code, rc::SUCCESS, "PolicyPCR -> {:08x}", r.code);

    // The digest the clause gives, over the selection as sent.
    let mut data = selection[34..].to_vec();
    data.extend_from_slice(&[0xab; 32]);
    let expected = swtrust::tpm::crypto::hash::digest_parts(
        alg::SHA256,
        &[&[0u8; 32], &cc::PolicyPCR.to_be_bytes(), &data],
    )
    .unwrap();
    assert_eq!(
        digest(t),
        expected,
        "the trial session modified the selection it was given"
    );
}


/// Part 3 clause 23.7.1: "When this command is executed,
/// policySession->pcrUpdateCounter is checked to see if it has been previously
/// set... If it has been set, it will be compared with the current value of
/// pcrUpdateCounter to determine if any PCR changes have occurred. If the
/// values are different, the TPM shall return TPM_RC_PCR_CHANGED."
#[test]
fn a_second_policy_pcr_after_a_pcr_changed_is_refused() {
    let h = Harness::started("pcrchanged");

    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    p.u8(se::POLICY);
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
    let session = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let policy_pcr = |index: u8| -> u32 {
        let mut p = Writer::new();
        p.u16(0); // no pcrDigest, so the TPM uses its own
        p.u32(1);
        p.u16(alg::SHA256);
        p.u8(3);
        let mut bits = [0u8; 3];
        bits[(index / 8) as usize] = 1 << (index % 8);
        p.bytes(&bits);
        h.send(&command(
            st::NO_SESSIONS,
            cc::PolicyPCR,
            &[session],
            None,
            &p.finish().unwrap(),
        ))
        .code
    };

    assert_eq!(policy_pcr(16), rc::SUCCESS, "the first assertion was refused");
    // A second one while nothing has changed is allowed: the counter is the
    // one the session recorded.
    assert_eq!(policy_pcr(17), rc::SUCCESS, "an unchanged counter was refused");

    // Extend a register that counts, which moves pcrUpdateCounter.
    let mut p = Writer::new();
    p.u32(1);
    p.u16(alg::SHA256);
    p.bytes(&[0xcd; 32]);
    let r = h.send(&command(
        st::SESSIONS,
        cc::PCR_Extend,
        &[10],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "PCR_Extend -> {:08x}", r.code);

    assert_eq!(
        policy_pcr(16),
        rc::PCR_CHANGED,
        "a policy collected assertions from two different PCR states"
    );
}


/// Part 2 clause 10.4.3: "If size is four, then the Name is a handle. If size
/// is zero, then no Name is present. Otherwise, the size shall be the size of a
/// TPM_ALG_ID plus the size of the digest produced by the indicated hash
/// algorithm." A permanent entity has a Name of the first kind, and
/// TPM2_PolicySecret makes tickets for such entities.
#[test]
fn a_ticket_may_name_a_permanent_entity() {
    let h = Harness::started("ticketname");

    let mut p = Writer::new();
    p.u16(16);
    p.bytes(&[0u8; 16]);
    p.u16(0);
    p.u8(se::POLICY);
    p.u16(alg::NULL);
    p.u16(alg::SHA256);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::StartAuthSession,
        &[rh::NULL, rh::NULL],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS);
    let session = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    // A ticket that names TPM_RH_OWNER, whose Name is the handle. The ticket
    // itself is not one this TPM produced, so the answer says so rather than
    // complaining about the Name.
    let mut p = Writer::new();
    p.u16(8); // timeout
    p.bytes(&[0u8; 8]);
    p.u16(0); // cpHashA
    p.u16(0); // policyRef
    p.u16(4); // authName: a handle
    p.u32(rh::OWNER);
    p.u16(st::AUTH_SECRET);
    p.u32(rh::OWNER);
    p.u16(32);
    p.bytes(&[0xaa; 32]);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyTicket,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code,
        rc::TICKET | 0x080 | 0x040 | (5 << 8),
        "a Name in handle form was taken for a malformed one -> {:08x}",
        r.code
    );

    // A Name that is neither a handle nor a digest is still refused.
    let mut p = Writer::new();
    p.u16(8);
    p.bytes(&[0u8; 8]);
    p.u16(0);
    p.u16(0);
    // A hash algorithm followed by too few octets is no shape a Name has.
    p.u16(7);
    p.u16(alg::SHA256);
    p.bytes(&[0u8; 5]);
    p.u16(st::AUTH_SECRET);
    p.u32(rh::OWNER);
    p.u16(32);
    p.bytes(&[0xaa; 32]);
    let r = h.send(&command(
        st::NO_SESSIONS,
        cc::PolicyTicket,
        &[session],
        None,
        &p.finish().unwrap(),
    ));
    assert_eq!(
        r.code & 0x03f,
        rc::SIZE & 0x03f,
        "a Name of no shape was accepted -> {:08x}",
        r.code
    );
}


/// Part 3 clause 10.4.1: "This command will operate when the TPM is in Failure
/// mode so that software can determine the test status of the TPM and so that
/// diagnostic information can be obtained for use in failure analysis. If the
/// TPM is in Failure mode, then tag is required to be TPM_ST_NO_SESSIONS or the
/// TPM shall return TPM_RC_FAILURE."
#[test]
fn a_tpm_in_failure_mode_answers_only_a_command_without_sessions() {
    let h = Harness::started("failuretag");
    h.tpm.with_state_mut(|s| s.failure_mode = true);

    // Without sessions the command answers, which is what failure analysis
    // depends on.
    let r = h.send(&command(st::NO_SESSIONS, cc::GetTestResult, &[], None, &[]));
    assert_eq!(r.code, rc::SUCCESS, "GetTestResult -> {:08x}", r.code);
    assert_eq!(
        u32::from_be_bytes([r.body[34], r.body[35], r.body[36], r.body[37]]),
        rc::FAILURE,
        "the test result did not report the failure"
    );

    // With a session it does not.
    let r = h.send(&command(
        st::SESSIONS,
        cc::GetTestResult,
        &[],
        Some(&password(b"")),
        &[],
    ));
    assert_eq!(
        r.code,
        rc::FAILURE,
        "a session tagged command was answered in failure mode -> {:08x}",
        r.code
    );

    // And a command that is not one of the two is refused either way.
    let r = h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0, 8]));
    assert_eq!(r.code, rc::FAILURE);
}


/// Part 3 clause 17.8.1: "Regardless of the contents of the first octets of the
/// hashed message, if the first buffer sent to the TPM had fewer than
/// sizeof(TPM_GENERATED) octets, then the TPM will operate as if digest is not
/// safe to sign."
#[test]
fn a_sequence_whose_first_buffer_was_short_gets_no_ticket() {
    let h = Harness::started("shortfirst");

    let start = || -> u32 {
        let mut p = Writer::new();
        p.u16(0); // auth
        p.u16(alg::SHA256);
        // The command names no handle, so it carries no authorization.
        let r = h.send(&command(
            st::NO_SESSIONS,
            cc::HashSequenceStart,
            &[],
            None,
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "HashSequenceStart -> {:08x}", r.code);
        Reader::new(&r.body).u32().unwrap()
    };
    let update = |handle: u32, data: &[u8]| {
        let mut p = Writer::new();
        p.u16(data.len() as u16);
        p.bytes(data);
        let r = h.send(&command(
            st::SESSIONS,
            cc::SequenceUpdate,
            &[handle],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "SequenceUpdate -> {:08x}", r.code);
    };
    // The ticket is the second response parameter, after the digest.
    let complete = |handle: u32, data: &[u8]| -> Vec<u8> {
        let mut p = Writer::new();
        p.u16(data.len() as u16);
        p.bytes(data);
        p.u32(rh::OWNER);
        let r = h.send(&command(
            st::SESSIONS,
            cc::SequenceComplete,
            &[handle],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "SequenceComplete -> {:08x}", r.code);
        let mut rd = Reader::new(&r.body);
        let _param_size = rd.u32().unwrap();
        let n = rd.u16().unwrap() as usize;
        rd.take(n).unwrap();
        rd.rest().to_vec()
    };

    // A long first buffer that does not begin with TPM_GENERATED_VALUE: the
    // digest is safe to sign and the ticket carries a digest of its own.
    let s = start();
    update(s, b"a long enough first buffer");
    let ticket = complete(s, b"the rest");
    let hmac = u16::from_be_bytes([ticket[6], ticket[7]]);
    assert_ne!(hmac, 0, "a safe digest was given a null ticket");

    // The same message, delivered with a short first buffer.
    let s = start();
    update(s, b"a l");
    let ticket = complete(s, b"ong enough first bufferthe rest");
    assert_eq!(
        u16::from_be_bytes([ticket[6], ticket[7]]),
        0,
        "a short first buffer was still called safe to sign"
    );

    // And when the completion carries the only buffer there was.
    let s = start();
    let ticket = complete(s, b"abc");
    assert_eq!(
        u16::from_be_bytes([ticket[6], ticket[7]]),
        0,
        "a sequence with one short buffer was called safe to sign"
    );
}


/// Part 3 clause 31.16.1: "If size and offset are both zero (0), then
/// certifyInfo in the response will contain a TPMS_NV_DIGEST_CERTIFY_INFO,
/// otherwise, it will contain a TPMS_NV_CERTIFY_INFO. The digest in the
/// TPMS_NV_DIGEST_CERTIFY_INFO is created using the hash algorithm of the
/// selected signing scheme."
#[test]
fn nv_certify_with_no_range_certifies_a_digest() {
    let h = Harness::started("nvdigest");

    // An ordinary Index the owner may read and write.
    let index = 0x0150_0020u32;
    let mut p = Writer::new();
    p.u16(0); // auth
    let public = {
        let mut w = Writer::new();
        w.u32(index);
        w.u16(alg::SHA256);
        // AUTHWRITE (bit 2), AUTHREAD (bit 18), NO_DA (bit 25)
        w.u32((1 << 2) | (1 << 18) | (1 << 25));
        w.u16(0); // authPolicy
        w.u16(32); // dataSize
        w.finish().unwrap()
    };
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

    let contents = [0x5au8; 32];
    let mut p = Writer::new();
    p.u16(contents.len() as u16);
    p.bytes(&contents);
    p.u16(0); // offset
    let r = h.send(&command(
        st::SESSIONS,
        cc::NV_Write,
        &[index, index],
        Some(&password(b"")),
        &p.finish().unwrap(),
    ));
    assert_eq!(r.code, rc::SUCCESS, "NV_Write -> {:08x}", r.code);

    // Certify with no signing key, naming the hash in the scheme.
    let certify = |size: u16, offset: u16, scheme: Option<u16>| -> Answer {
        let mut p = Writer::new();
        p.u16(0); // qualifyingData
        match scheme {
            Some(hash) => {
                p.u16(alg::HMAC);
                p.u16(hash);
            }
            None => p.u16(alg::NULL),
        }
        p.u16(size);
        p.u16(offset);
        h.send(&command(
            st::SESSIONS,
            cc::NV_Certify,
            &[rh::NULL, index, index],
            Some(&password_sessions(2)),
            &p.finish().unwrap(),
        ))
    };

    let r = certify(0, 0, Some(alg::SHA256));
    assert_eq!(r.code, rc::SUCCESS, "NV_Certify -> {:08x}", r.code);
    // The attest structure is TPM_GENERATED, then the type: the digest form.
    let mut rd = Reader::new(&r.body);
    let _param_size = rd.u32().unwrap();
    let n = rd.u16().unwrap() as usize;
    let attest = rd.take(n).unwrap();
    assert_eq!(
        u16::from_be_bytes([attest[4], attest[5]]),
        0x801c,
        "the attestation was not TPM_ST_ATTEST_NV_DIGEST"
    );
    // The digest of the whole Index is at the end, after the Name.
    let expected = swtrust::tpm::crypto::hash::digest(alg::SHA256, &contents).unwrap();
    assert!(
        attest.ends_with(&expected),
        "the digest is not of the contents of the Index"
    );

    // A range gives the ordinary form.
    let r = certify(32, 0, Some(alg::SHA256));
    assert_eq!(r.code, rc::SUCCESS);
    let mut rd = Reader::new(&r.body);
    let _param_size = rd.u32().unwrap();
    let n = rd.u16().unwrap() as usize;
    let attest = rd.take(n).unwrap();
    assert_eq!(
        u16::from_be_bytes([attest[4], attest[5]]),
        0x8014,
        "the attestation was not TPM_ST_ATTEST_NV"
    );

    // "unless the scheme or hash algorithm is TPM_ALG_NULL, in which case the
    // TPM shall return TPM_RC_SCHEME."
    let r = certify(0, 0, None);
    assert_eq!(
        r.code,
        rc::SCHEME | 0x080 | 0x040 | (2 << 8),
        "a null scheme was accepted for a digest certification -> {:08x}",
        r.code
    );
}


/// Part 3 clause 29.3.1: TPM2_ClockRateAdjust "adjusts the rate of advance of
/// Clock and Time to provide a better approximation to real time. The
/// rateAdjust value is relative to the current rate and not the nominal rate of
/// advance", and repeated adjustments accumulate.
#[test]
fn the_clock_rate_can_be_adjusted_and_accumulates() {
    let h = Harness::started("clockrate");

    let adjust = |value: i8| -> u32 {
        h.send(&command(
            st::SESSIONS,
            cc::ClockRateAdjust,
            &[rh::OWNER],
            Some(&password(b"")),
            &[value as u8],
        ))
        .code
    };
    let rate = || h.tpm.with_state(|s| s.clock.rate_adjust);

    assert_eq!(rate(), 0, "a manufactured TPM runs at the nominal rate");
    assert_eq!(adjust(1), rc::SUCCESS, "a fine step was refused");
    assert_eq!(rate(), 1);
    assert_eq!(adjust(3), rc::SUCCESS, "a coarse step was refused");
    assert_eq!(rate(), 11, "the adjustments did not accumulate");
    // The example in the clause: three slower and one faster leave two slower.
    for _ in 0..3 {
        assert_eq!(adjust(-3), rc::SUCCESS);
    }
    assert_eq!(adjust(3), rc::SUCCESS);
    assert_eq!(rate(), 11 - 20, "the example of the clause did not hold");

    // "If the requested adjustment would make the rate advance faster or slower
    // than the nominal accuracy of the input frequency, the TPM shall return
    // TPM_RC_VALUE."
    for _ in 0..9 {
        assert_eq!(adjust(-3), rc::SUCCESS);
    }
    assert_eq!(rate(), -99);
    assert_eq!(
        adjust(-3),
        rc::VALUE | 0x080 | 0x040 | (1 << 8),
        "the rate went past the accuracy of the input frequency"
    );
    assert_eq!(rate(), -99, "a refused adjustment still moved the rate");

    // And an adjustment that is no adjustment at all is accepted.
    assert_eq!(adjust(0), rc::SUCCESS);
    assert_eq!(rate(), -99);
    assert_eq!(
        adjust(4),
        rc::VALUE | 0x080 | 0x040 | (1 << 8),
        "a value outside TPM_CLOCK_ADJUST was accepted"
    );
}


/// Part 3 clause 15.5.1 and clause 17.2.1: "If the sign attribute is not SET in
/// the key referenced by handle, then the TPM shall return TPM_RC_KEY... If the
/// key referenced by handle has the restricted attribute SET, the TPM shall
/// return TPM_RC_ATTRIBUTES", because "TPM2_HMAC() has no ticket parameter,
/// which is required with a restricted key."
#[test]
fn hmac_refuses_a_restricted_key_and_names_a_key_that_cannot_sign() {
    let h = Harness::started("hmackeys");

    // A keyed hash key under a storage parent, built from a template the
    // caller supplies so the attributes can be varied.
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
    assert_eq!(r.code, rc::SUCCESS);
    let parent = Reader::new(&r.body).u32().unwrap();

    let keyed_hash = |attrs: u32| -> u32 {
        let public = {
            let mut w = Writer::new();
            w.u16(0x0008); // TPM_ALG_KEYEDHASH
            w.u16(alg::SHA256);
            w.u32(attrs);
            w.u16(0); // authPolicy
            w.u16(alg::HMAC);
            w.u16(alg::SHA256);
            w.u16(0); // unique
            w.finish().unwrap()
        };
        let mut p = Writer::new();
        p.u16(4);
        p.u16(0);
        p.u16(0);
        p.u16(public.len() as u16);
        p.bytes(&public);
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
        let mut rd = Reader::new(&r.body);
        let _param_size = rd.u32().unwrap();
        let n = rd.u16().unwrap() as usize;
        let private = rd.take(n).unwrap().to_vec();
        let n = rd.u16().unwrap() as usize;
        let pub_area = rd.take(n).unwrap().to_vec();

        let mut p = Writer::new();
        p.u16(private.len() as u16);
        p.bytes(&private);
        p.u16(pub_area.len() as u16);
        p.bytes(&pub_area);
        let r = h.send(&command(
            st::SESSIONS,
            cc::Load,
            &[parent],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ));
        assert_eq!(r.code, rc::SUCCESS, "Load -> {:08x}", r.code);
        Reader::new(&r.body).u32().unwrap()
    };
    let hmac = |handle: u32| -> u32 {
        let mut p = Writer::new();
        p.u16(4);
        p.bytes(b"data");
        p.u16(alg::NULL);
        h.send(&command(
            st::SESSIONS,
            cc::HMAC,
            &[handle],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ))
        .code
    };

    // fixedTPM fixedParent sensitiveDataOrigin userWithAuth sign
    let signing = keyed_hash(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000);
    assert_eq!(hmac(signing), rc::SUCCESS, "an ordinary HMAC key was refused");

    // The same with restricted SET, which needs the ticket TPM2_Sign carries.
    let restricted = keyed_hash(0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000 | 0x0001_0000);
    assert_eq!(
        hmac(restricted),
        rc::ATTRIBUTES | 0x080 | (1 << 8),
        "a restricted key produced a MAC"
    );

    // And a keyed hash object that cannot sign at all is a key error.
    let sealed = keyed_hash(0x0002 | 0x0010 | 0x0020 | 0x0040);
    assert_eq!(
        hmac(sealed),
        rc::KEY | 0x080 | (1 << 8),
        "a key that cannot sign was not reported as a key error"
    );
}


/// Part 1 clause 34.7.2.2: "When an external device is used for non-volatile
/// storage, that device may not always be accessible to the TPM command
/// execution engine. When the memory is not accessible, operations that require
/// update of NV will return TPM_RC_NV_UNAVAILABLE."
#[test]
fn a_command_that_writes_nv_is_refused_while_nv_is_away() {
    let h = Harness::started("nvaway");

    // A command that writes NV, and one that does not.
    let extend = || -> u32 {
        let mut p = Writer::new();
        p.u32(1);
        p.u16(alg::SHA256);
        p.bytes(&[0xab; 32]);
        h.send(&command(
            st::SESSIONS,
            cc::PCR_Extend,
            &[10],
            Some(&password(b"")),
            &p.finish().unwrap(),
        ))
        .code
    };
    let read = || -> u32 {
        h.send(&command(st::NO_SESSIONS, cc::GetRandom, &[], None, &[0, 8])).code
    };
    let counter = || h.tpm.with_state(|s| s.pcr.update_counter());

    h.tpm.nv_off();
    let before = counter();
    assert_eq!(
        extend(),
        rc::NV_UNAVAILABLE,
        "a command that writes NV ran while NV was away"
    );
    assert_eq!(
        counter(),
        before,
        "the command changed a register before it was refused"
    );
    // A command that does not write NV is unaffected.
    assert_eq!(read(), rc::SUCCESS, "a command that writes nothing was refused");

    h.tpm.nv_on();
    assert_eq!(extend(), rc::SUCCESS, "NV did not come back");
    assert_ne!(counter(), before);
}
