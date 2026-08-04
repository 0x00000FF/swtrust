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
//!
//! These are the rules a TPM started with `--ptp` follows, so the binary
//! selects that profile. The default is measured in `legacy.rs`.

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
        swtrust::tpm::profile::set(swtrust::tpm::profile::Profile::Strict);
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

    /// Send a command that names one handle and authorizes it with a password.
    fn send_auth(&self, command: u32, handle: u32, parameters: &[u8]) -> Vec<u8> {
        let mut auth = 0x4000_0009u32.to_be_bytes().to_vec(); // TPM_RS_PW
        auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
        auth.push(0); // session attributes
        auth.extend_from_slice(&0u16.to_be_bytes()); // password

        let mut body = handle.to_be_bytes().to_vec();
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth);
        body.extend_from_slice(parameters);

        let mut v = st::SESSIONS.to_be_bytes().to_vec();
        v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        v.extend_from_slice(&command.to_be_bytes());
        v.extend_from_slice(&body);
        self.tpm.execute(0, &v)
    }

    /// The timer this TPM reports, as a timeout and its attributes.
    fn act(&self) -> (u32, u32) {
        let mut body = cap::ACT.to_be_bytes().to_vec();
        body.extend_from_slice(&0x4000_0110u32.to_be_bytes()); // TPM_RH_ACT_0
        body.extend_from_slice(&4u32.to_be_bytes());
        let r = self.send(cc::GetCapability, &body);
        assert_eq!(code_of(&r), rc::SUCCESS);
        let count = u32::from_be_bytes(r[15..19].try_into().unwrap()) as usize;
        assert_eq!(count, 1, "the profile asks for one timer");
        // TPMS_ACT_DATA is the handle, the timeout and the attributes.
        (
            u32::from_be_bytes(r[23..27].try_into().unwrap()),
            u32::from_be_bytes(r[27..31].try_into().unwrap()),
        )
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

/// True when `code` is TPM_RC_VALUE, whichever handle or parameter it names.
///
/// Part 2 clause 6.6.2 builds a format-one code from the error number in
/// bits 5:0, so the qualifier has to be taken off before comparing.
fn is_value_error(code: u32) -> bool {
    code & rc::RC_FMT1 != 0 && code & 0x3f == rc::VALUE & 0x3f
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
    for (name, id) in [("TPM_ALG_SHA1", alg::SHA1), ("TPM_ALG_TDES", alg::TDES)] {
        assert!(
            !reported.contains(&id),
            "{name} is reported as implemented but the profile forbids it"
        );
    }

    // Reporting is not enough on its own: the algorithm must not work either.
    let mut body = 3u16.to_be_bytes().to_vec();
    body.extend_from_slice(b"abc");
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.extend_from_slice(&0x4000_0007u32.to_be_bytes());
    let r = h.send(cc::Hash, &body);
    assert_ne!(code_of(&r), rc::SUCCESS, "TPM2_Hash accepted SHA-1");

    // Part 2 clause 6.6.2: "When an error is associated with a parameter,
    // TPM_RC_P ... is added and N is set to the parameter number." Refusing an
    // algorithm while a parameter is being read is such an error, so the
    // selection TPM2_PCR_Read was given is named.
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&alg::SHA1.to_be_bytes());
    body.push(3);
    body.extend_from_slice(&[0x00, 0x08, 0x00]);
    let r = h.send(cc::PCR_Read, &body);
    assert_eq!(
        code_of(&r),
        rc::HASH | 0x080 | 0x040 | (1 << 8),
        "a selection naming SHA-1 was refused without saying which parameter: {:#x}",
        code_of(&r)
    );
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

/// Clause 5.1.2: "If a TPM implements the optional TPM2_ACT_SetTimeout command:
/// 1. The TPM SHALL support one ACT instance".
///
/// The timer is driven through the command interface and read back through
/// TPM2_GetCapability(TPM_CAP_ACT), which is how Part 2 clause 8.12 says the
/// attributes are read.
#[test]
fn the_timer_the_profile_asks_for_is_there_and_counts() {
    /// TPMA_ACT.signaled, Part 2 Table 46 bit 0.
    const SIGNALED: u32 = 1;

    let h = Harness::new("act");
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 0, "a started TPM has no countdown running");
    assert_eq!(attributes & SIGNALED, 0);

    // Part 3 clause 33.2.1 state 1: zero and non-zero leaves signaled CLEAR.
    let r = h.send_auth(cc::ACT_SetTimeout, 0x4000_0110, &60u32.to_be_bytes());
    assert_eq!(code_of(&r), rc::SUCCESS, "setting the timeout failed");
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 60);
    assert_eq!(attributes & SIGNALED, 0);

    // State 4: non-zero and zero signals, because the timer went to zero.
    let r = h.send_auth(cc::ACT_SetTimeout, 0x4000_0110, &0u32.to_be_bytes());
    assert_eq!(code_of(&r), rc::SUCCESS);
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 0);
    assert_eq!(attributes & SIGNALED, SIGNALED, "reaching zero is a signal");

    // "When ACT Timeout is zero and the signaled attribute is SET, writing a
    // startTimeout of FF FF FF FF will clear signaled and stop the counting."
    let r = h.send_auth(cc::ACT_SetTimeout, 0x4000_0110, &u32::MAX.to_be_bytes());
    assert_eq!(code_of(&r), rc::SUCCESS);
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 0, "no new countdown is started");
    assert_eq!(attributes & SIGNALED, 0, "the signal is cleared");

    // There is one timer, so no other handle names one.
    let r = h.send_auth(cc::ACT_SetTimeout, 0x4000_0111, &60u32.to_be_bytes());
    assert_ne!(code_of(&r), rc::SUCCESS, "a second timer answered");
}

/// Part 1 clause 40.2: an ACT "will decrement by one each second that the TPM
/// is powered", and signals on reaching zero.
///
/// The seconds are handed to the TPM rather than waited for, so the test says
/// what it means and takes no time. Without this the timer could stand still
/// and every other ACT test would still pass.
#[test]
fn the_timer_counts_down_while_the_tpm_is_powered() {
    const SIGNALED: u32 = 1;

    let h = Harness::new("actcount");
    let r = h.send_auth(cc::ACT_SetTimeout, 0x4000_0110, &3u32.to_be_bytes());
    assert_eq!(code_of(&r), rc::SUCCESS);
    assert_eq!(h.act().0, 3);

    h.tpm.with_state_mut(|s| {
        s.advance_time(2_000);
    });
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 1, "two of the three seconds have gone");
    assert_eq!(attributes & SIGNALED, 0, "it has not reached zero yet");

    h.tpm.with_state_mut(|s| {
        s.advance_time(1_000);
    });
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 0);
    assert_eq!(attributes & SIGNALED, SIGNALED, "reaching zero signals");

    // It stays signalled until something clears it, and does not wrap round.
    h.tpm.with_state_mut(|s| {
        s.advance_time(60_000);
    });
    let (timeout, attributes) = h.act();
    assert_eq!(timeout, 0);
    assert_eq!(attributes & SIGNALED, SIGNALED);
}

/// Real time passing counts the timer down, and time while the TPM has no
/// power does not.
///
/// The other timer tests hand the seconds to the state directly, so they would
/// pass even if nothing ever credited the time or if time off the power were
/// credited too. This one waits, which is the only way to go through the whole
/// path: the monotonic reference, the elapsed calculation and the check that
/// the TPM is powered.
#[test]
fn real_time_counts_the_timer_down_and_time_without_power_does_not() {
    let h = Harness::new("actreal");
    let r = h.send_auth(cc::ACT_SetTimeout, 0x4000_0110, &5u32.to_be_bytes());
    assert_eq!(code_of(&r), rc::SUCCESS);
    assert_eq!(h.act().0, 5);

    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert_eq!(h.act().0, 4, "a real second must be credited");

    // Part 1 clause 40.2 counts "each second that the TPM is powered", so an
    // interval with the power removed is worth nothing. Reading the signal
    // goes through the same path as a command, so it is what is asked here.
    let before = h.tpm.with_state(|s| s.act.timeout());
    h.tpm.power_off();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let _ = h.tpm.act_get_signaled(0);
    assert_eq!(
        h.tpm.with_state(|s| s.act.timeout()),
        before,
        "time with no power must not be credited"
    );
}

/// Clause 4.7 item 7: "The optional TPM2_PCR_SetAuthPolicy and
/// TPM2_PCR_SetAuthValue commands, if implemented, SHALL return TPM_RC_VALUE."
#[test]
fn the_pcr_authorization_commands_refuse_with_the_value_the_profile_names() {
    let h = Harness::new("pcrauth");

    // TPM2_PCR_SetAuthValue takes the PCR handle and an authorization value.
    let r = h.send_auth(cc::PCR_SetAuthValue, 0, &[0x00, 0x00]);
    assert!(is_value_error(code_of(&r)), "SetAuthValue answered {:#06x}", code_of(&r));

    // TPM2_PCR_SetAuthPolicy takes the platform handle, then the policy, the
    // hash and the PCR the policy is for.
    let mut body = 32u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&alg::SHA256.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    let r = h.send_auth(cc::PCR_SetAuthPolicy, 0x4000_000C, &body);
    assert!(is_value_error(code_of(&r)), "SetAuthPolicy answered {:#06x}", code_of(&r));
}

/// Clause 5.3.2 item 1: "The TPM2_Startup command SHALL come from Locality 0
/// or 3, else a TPM SHALL return TPM_RC_Locality."
#[test]
fn startup_is_refused_from_a_locality_the_profile_does_not_allow() {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "swtrust-ptp-startloc-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
    let tpm = Tpm::new(dir.join("state"), logger).unwrap();
    tpm.power_on();

    let startup = {
        let body = [0x00u8, 0x00];
        let mut v = st::NO_SESSIONS.to_be_bytes().to_vec();
        v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        v.extend_from_slice(&cc::Startup.to_be_bytes());
        v.extend_from_slice(&body);
        v
    };

    for locality in [1u8, 2, 4] {
        let r = tpm.execute(locality, &startup);
        assert_eq!(
            code_of(&r),
            rc::LOCALITY,
            "startup was accepted from locality {locality}"
        );
    }
    // Locality 0 is the ordinary one and is accepted.
    assert_eq!(code_of(&tpm.execute(0, &startup)), rc::SUCCESS);
    std::fs::remove_dir_all(&dir).ok();
}

/// Clause 4.6.1 item 1.b: a read of TPM_PT_MEMORY "SHALL return TPMA_MEMORY"
/// with "sharedRAM SHALL be CLEAR".
#[test]
fn the_memory_attributes_say_ram_is_not_shared() {
    /// TPMA_MEMORY.sharedRAM, Part 2 Table 42 bit 0.
    const SHARED_RAM: u32 = 1;
    let h = Harness::new("memory");
    assert_eq!(h.property(pt::MEMORY) & SHARED_RAM, 0);
}

/// Clause 5.1.1 item 3: "A TPM SHALL NOT return TPM_RC_OBJECT_HANDLES."
#[test]
fn the_response_code_the_profile_forbids_is_never_returned() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tpm/error.rs"))
        .unwrap_or_default();
    let _ = source;
    // The code is defined so that a caller's value can be named, but nothing
    // builds one. A scan of the tree is what keeps that true.
    let mut found = Vec::new();
    for entry in walk(concat!(env!("CARGO_MANIFEST_DIR"), "/src")) {
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        for (number, line) in text.lines().enumerate() {
            if line.contains("rc::OBJECT_HANDLES") && !line.contains("pub const") {
                found.push(format!("{}:{}", entry.display(), number + 1));
            }
        }
    }
    assert!(found.is_empty(), "TPM_RC_OBJECT_HANDLES is used at {found:?}");
}

/// Every Rust source file under `dir`.
fn walk(dir: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(at) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&at) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// Clause 4.7 item 8: "the D-RTM PCR SHALL be PCR 17 and the S-HCRTM PCR SHALL
/// be PCR 0."
#[test]
fn the_drtm_and_hcrtm_registers_are_the_ones_the_profile_names() {
    let h = Harness::new("hcrtm");

    let read = |index: u16| -> Vec<u8> {
        h.tpm
            .with_state(|s| s.pcr.read(alg::SHA256, index).unwrap().to_vec())
    };

    // A D-RTM register starts at all ones, which is what marks it as one.
    assert!(read(17).iter().all(|v| *v == 0xff), "PCR 17 starts at ones");
    let hcrtm_before = read(0);
    let restarts_before = h.tpm.with_state(|s| s.clock.restart_count);

    // Run an H-CRTM event sequence the way the interface delivers one. The
    // harness has already started the TPM, so this is the after-Startup case.
    h.tpm.hash_start();
    h.tpm.hash_data(b"a measurement");
    h.tpm.hash_end();

    // Part 3 clause 22.11: the registers the platform marks resettable by this
    // event are set, restartCount is incremented, and the digest is extended
    // into the D-RTM register, which clause 4.7 item 8 of the profile names as
    // PCR 17.
    let after = read(17);
    assert!(
        after.iter().any(|v| *v != 0xff),
        "the D-RTM register was left at its initial value"
    );
    assert!(
        after.iter().any(|v| *v != 0),
        "the digest was not extended into the D-RTM register"
    );
    assert_eq!(
        read(0),
        hcrtm_before,
        "an event after Startup does not touch the S-HCRTM register"
    );
    assert_eq!(
        h.tpm.with_state(|s| s.clock.restart_count),
        restarts_before + 1,
        "restartCount must be incremented"
    );
    assert!(
        read(18).iter().all(|v| *v == 0),
        "the other registers the event resets go to zero"
    );

    // And they are the registers the configuration names, so nothing else in
    // the TPM is looking at a different pair.
    assert_eq!(config::DRTM_PCR, 17);
    assert_eq!(config::HCRTM_PCR, 0);
}
