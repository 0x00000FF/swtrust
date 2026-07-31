//! Tests for the debug console.
//!
//! The console reaches state the command interface does not report, so these
//! tests drive it the way a person would and check what it says against the
//! state underneath.

use std::sync::Arc;

use swtrust::console::{execute, serve, Outcome};
use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::constants::{alg, curve, hc, rh};
use swtrust::tpm::core::nv::NvIndex;
use swtrust::tpm::core::object::{Object, Slot};
use swtrust::tpm::device::Tpm;
use swtrust::tpm::structures::attributes::{nt, NvAttributes, ObjectAttributes};
use swtrust::tpm::structures::base::Tpm2bDigest;
use swtrust::tpm::structures::keys::{PublicId, PublicParms, TpmtPublic};
use swtrust::tpm::structures::nv::NvPublic;
use swtrust::tpm::structures::schemes::{Scheme, SymDef};
use swtrust::util::hex;

/// A powered TPM whose state lives in a temporary directory.
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
        "swtrust-console-{tag}-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
    let tpm = Tpm::new(dir.join("state"), logger).unwrap();
    tpm.power_on();
    Harness { tpm, dir }
}

/// The text one console line produced.
fn run(h: &Harness, line: &str) -> String {
    match execute(&h.tpm, line) {
        Outcome::Output(s) => s,
        Outcome::Quit => "quit".to_string(),
    }
}

#[test]
fn an_empty_line_and_an_unknown_command_are_harmless() {
    let h = harness("basic");
    assert_eq!(run(&h, ""), "");
    assert_eq!(run(&h, "   "), "");
    assert!(run(&h, "wibble").contains("unknown command wibble"));
    assert_eq!(execute(&h.tpm, "quit"), Outcome::Quit);
    assert_eq!(execute(&h.tpm, "exit"), Outcome::Quit);
    assert!(run(&h, "help").contains("pcr read"));
}

#[test]
fn status_reports_the_state_the_command_interface_hides() {
    let h = harness("status");
    let out = run(&h, "status");
    assert!(out.contains("powered        true"), "{out}");
    assert!(out.contains("started        false"), "{out}");
    assert!(out.contains("failure mode   false"), "{out}");
    assert!(out.contains("pcr counter"), "{out}");
    assert!(run(&h, "banks").contains("sha256"));
}

#[test]
fn a_register_is_read_extended_written_and_reset() {
    let h = harness("pcr");
    // A register starts at zero.
    assert_eq!(run(&h, "pcr read 0"), "0".repeat(64));

    // Extending gives the digest of the old value followed by the new one.
    let out = run(&h, &format!("pcr extend 0 {}", "ab".repeat(32)));
    let extended = out.rsplit(' ').next().unwrap().to_string();
    let expected =
        swtrust::tpm::crypto::hash::digest_parts(alg::SHA256, &[&[0u8; 32], &[0xabu8; 32][..]])
            .unwrap();
    assert_eq!(extended, hex::encode(&expected));
    assert_eq!(run(&h, "pcr read 0"), extended);

    // Writing puts a value straight in, which no command can do.
    let target = "cd".repeat(32);
    assert!(run(&h, &format!("pcr write 0 {target}")).contains(&target));
    assert_eq!(run(&h, "pcr read 0"), target);

    // The update counter moves for a write, so a reader can tell it changed.
    let before = h.tpm.with_state(|s| s.pcr.update_counter());
    run(&h, &format!("pcr write 0 {}", "01".repeat(32)));
    assert_eq!(h.tpm.with_state(|s| s.pcr.update_counter()), before + 1);

    // Part 1 clause 17.4 gives PCR 0 through 15 no locality that may reset
    // them, so the console says so rather than clearing the register.
    assert!(run(&h, "pcr reset 0").contains("cannot be reset"));
    assert_eq!(run(&h, "pcr read 0"), "01".repeat(32));

    // PCR 23 resets from locality zero, so that one does clear.
    run(&h, &format!("pcr write 23 {}", "99".repeat(32)));
    assert!(run(&h, "pcr reset 23").contains("reset"));
    assert_eq!(run(&h, "pcr read 23"), "0".repeat(64));

    // A listing covers every implemented register.
    let list = run(&h, "pcr list");
    assert_eq!(
        list.lines().count(),
        swtrust::tpm::config::IMPLEMENTATION_PCR as usize
    );

    // A bank may be named, and an unknown one is refused.
    assert_eq!(run(&h, "pcr read 0 sha1").len(), 40);
    assert!(run(&h, "pcr read 0 sha999").contains("unknown hash algorithm"));
    // A digest of the wrong length is refused rather than stored.
    assert!(run(&h, "pcr write 0 abcd").contains("error"));
    // So is a register that does not exist.
    assert!(run(&h, "pcr read 99").contains("error"));
}

#[test]
fn an_index_is_listed_read_written_and_removed() {
    let h = harness("nv");
    assert_eq!(run(&h, "nv list"), "no index is defined");

    let handle = hc::NV_INDEX_FIRST + 7;
    h.tpm.with_state_mut(|s| {
        s.nv.define(NvIndex {
            public: NvPublic {
                nv_index: handle,
                name_alg: alg::SHA256,
                attributes: NvAttributes(NvAttributes::AUTHWRITE | NvAttributes::AUTHREAD)
                    .with_index_type(nt::ORDINARY),
                auth_policy: Tpm2bDigest::empty(),
                data_size: 8,
            },
            auth: Vec::new(),
            data: Vec::new(),
            read_locked: false,
            write_locked: false,
        })
        .unwrap();
    });

    assert!(run(&h, "nv list").contains(&format!("{handle:08x}")));
    assert!(run(&h, &format!("nv write {handle} 0 0011223344556677")).contains("8 octets"));
    assert_eq!(run(&h, &format!("nv read {handle}")), "0011223344556677");
    // An offset and a size may be given, and a hex handle works too.
    assert_eq!(run(&h, &format!("nv read 0x{handle:x} 2 2")), "2233");
    // Writing past the end is refused.
    assert!(run(&h, &format!("nv write {handle} 6 00112233")).contains("error"));
    assert!(run(&h, &format!("nv undefine {handle}")).contains("removed"));
    assert!(run(&h, &format!("nv read {handle}")).contains("error"));
}

#[test]
fn the_generator_state_is_shown_seeded_and_drawn_from() {
    let h = harness("rng");
    let before = run(&h, "rng show");
    assert!(before.contains("reseed counter"), "{before}");
    let key_before = h.tpm.with_state(|s| s.rng.key().to_vec());

    // A reseed changes the working state and clears the counter.
    assert!(run(&h, &format!("rng seed {}", "5a".repeat(48))).contains("reseeded"));
    assert_ne!(h.tpm.with_state(|s| s.rng.key().to_vec()), key_before);
    // SP800-90A sets the counter to one after a reseed.
    assert_eq!(h.tpm.with_state(|s| s.rng.reseed_counter()), 1);

    // Stirring changes it too.
    let after_seed = h.tpm.with_state(|s| s.rng.key().to_vec());
    assert!(run(&h, "rng stir 00ff").contains("stirred"));
    assert_ne!(h.tpm.with_state(|s| s.rng.key().to_vec()), after_seed);

    // Drawing gives the count asked for, and two draws differ.
    let a = run(&h, "rng bytes 16");
    let b = run(&h, "rng bytes 16");
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
    // A draw larger than the TPM would ever answer is refused.
    assert!(run(&h, "rng bytes 100000").contains("at most"));
    assert!(run(&h, "rng bytes").contains("count is needed"));
}

#[test]
fn a_key_is_listed_shown_and_changed() {
    let h = harness("key");
    assert_eq!(run(&h, "key list"), "no object is loaded");

    let handle = h.tpm.with_state_mut(|s| {
        let public = TpmtPublic {
            object_type: alg::ECC,
            name_alg: alg::SHA256,
            object_attributes: ObjectAttributes(
                ObjectAttributes::SIGN_ENCRYPT | ObjectAttributes::USER_WITH_AUTH,
            ),
            auth_policy: Tpm2bDigest::empty(),
            parameters: PublicParms::Ecc {
                symmetric: SymDef::null(),
                scheme: Scheme::hash(alg::ECDSA, alg::SHA256),
                curve_id: curve::NIST_P256,
                kdf: Scheme::null(),
            },
            unique: PublicId::Ecc(Default::default()),
        };
        let object = Object::new(public, None, rh::OWNER, &rh::OWNER.to_be_bytes(), true).unwrap();
        s.objects.insert(Slot::Object(Box::new(object))).unwrap()
    });

    let list = run(&h, "key list");
    assert!(list.contains(&format!("{handle:08x}")), "{list}");
    assert!(list.contains("transient"), "{list}");
    assert!(list.contains("ecc"), "{list}");
    assert!(list.contains("public"), "{list}");

    let shown = run(&h, &format!("key show {handle}"));
    assert!(shown.contains("type           ecc"), "{shown}");
    assert!(shown.contains("nameAlg        sha256"), "{shown}");
    assert!(shown.contains("name           "), "{shown}");
    assert!(shown.contains("qualifiedName  "), "{shown}");
    assert!(shown.contains("public only"), "{shown}");

    // A public only object has no authorization value to set.
    assert!(run(&h, &format!("key auth {handle} 00ff")).contains("no sensitive area"));
    // An oversized authorization value is refused.
    assert!(run(&h, &format!("key auth {handle} {}", "00".repeat(65))).contains("at most"));

    assert!(run(&h, &format!("key flush {handle}")).contains("flushed"));
    assert_eq!(run(&h, "key list"), "no object is loaded");
    assert!(run(&h, &format!("key show {handle}")).contains("error"));
}

#[test]
fn arguments_are_reported_rather_than_guessed() {
    let h = harness("args");
    assert!(run(&h, "pcr").contains("try pcr"));
    assert!(run(&h, "nv").contains("try nv"));
    assert!(run(&h, "rng").contains("try rng"));
    assert!(run(&h, "key").contains("try key"));
    assert!(run(&h, "pcr read").contains("index is needed"));
    assert!(run(&h, "pcr read xyz").contains("index xyz is not a number"));
    assert!(run(&h, "pcr extend 0 nothex").contains("digest is not hex"));
}

#[test]
fn the_loop_reads_lines_and_stops_on_quit() {
    let h = harness("loop");
    let input = b"status\nbanks\nquit\nstatus\n";
    let mut output = Vec::new();
    let logger = Logger::new(h.dir.join("logs2"), false).unwrap();
    serve(&h.tpm, &logger, &input[..], &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("swtrust console"));
    assert!(text.contains("powered        true"));
    assert!(text.contains("allocated banks"));
    assert!(text.contains("leaving the console"));
    // Nothing after quit is acted on.
    assert_eq!(text.matches("powered").count(), 1);
}

#[test]
fn save_writes_the_state_file() {
    let h = harness("save");
    run(&h, &format!("pcr write 0 {}", "77".repeat(32)));
    assert_eq!(run(&h, "save"), "state written");
    assert!(h.tpm.store().load().unwrap().is_some());
}
