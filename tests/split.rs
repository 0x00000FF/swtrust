//! End to end tests for the split ECC operations of Part 1 clause 44.2.
//!
//! A split operation is two commands. The first, TPM2_Commit or
//! TPM2_EC_Ephemeral, produces a commit value and returns points derived from
//! it along with a counter. The second, an ECDAA signature or
//! TPM2_ZGen_2Phase, names that counter and gets the same value back. These
//! tests drive both halves through the command interface and check the
//! arithmetic against the equations the specification gives.

use std::sync::Arc;

use swtrust::logging::Logger;
use swtrust::server::Device;
use swtrust::tpm::constants::{alg, cc, curve, rc, rh, st};
use swtrust::tpm::crypto::bn::{BigNum, BnCtx};
use swtrust::tpm::crypto::ecc;
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
        "swtrust-split-{tag}-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
    let tpm = Tpm::new(dir.join("state"), logger).unwrap();
    tpm.power_on();
    let h = Harness { tpm, dir };
    let r = send(&h, &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0, 0]));
    assert_eq!(r.code, rc::SUCCESS, "startup -> {:08x}", r.code);
    h
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

fn send_to(tpm: &Tpm, buf: &[u8]) -> Answer {
    let out = tpm.execute(0, buf);
    Answer {
        code: u32::from_be_bytes([out[6], out[7], out[8], out[9]]),
        body: out[10..].to_vec(),
    }
}

fn send(h: &Harness, buf: &[u8]) -> Answer {
    send_to(&h.tpm, buf)
}

const PASSWORD: [u8; 9] = [0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00];

/// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
const SIGNING: u32 = 0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000;
/// The same, with decrypt in place of sign and restricted clear, which is
/// what Part 3 Table 54 calls an unrestricted ECC decryption key.
const DECRYPTING: u32 = 0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0002_0000;

/// The template an ECDAA signing key uses, which several tests want.
fn ecdaa_template() -> Vec<u8> {
    template_for(SIGNING, 0x001A, Some(0))
}

/// A primary ECC key on P-256 with the given attributes and signing scheme.
fn primary_with(h: &Harness, attrs: u32, scheme: u16, count: Option<u16>) -> (u32, Vec<u8>) {
    create_primary(&h.tpm, &template_for(attrs, scheme, count))
}

/// Create a primary key from a marshalled template.
fn create_primary(tpm: &Tpm, template: &[u8]) -> (u32, Vec<u8>) {
    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(template.len() as u16);
    p.bytes(template);
    p.u16(0);
    p.u32(0);
    let r = send_to(
        tpm,
        &command(
            st::SESSIONS,
            cc::CreatePrimary,
            &[rh::OWNER],
            Some(&PASSWORD),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "CreatePrimary -> {:08x}", r.code);
    let handle = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);
    let mut rd = Reader::new(&r.body[4..]);
    rd.u32().unwrap();
    let public_size = rd.u16().unwrap() as usize;
    let public = rd.take(public_size).unwrap().to_vec();
    (handle, public)
}

/// The marshalled template for those attributes and scheme.
fn template_for(attrs: u32, scheme: u16, count: Option<u16>) -> Vec<u8> {
    let mut t = Writer::new();
    t.u16(alg::ECC);
    t.u16(alg::SHA256);
    t.u32(attrs);
    t.u16(0); // authPolicy
    t.u16(0x0010); // symmetric NULL
    t.u16(scheme);
    if scheme != 0x0010 {
        t.u16(alg::SHA256);
    }
    if let Some(c) = count {
        t.u16(c); // TPMS_SCHEME_ECDAA carries a count
    }
    t.u16(0x0003); // NIST P-256
    t.u16(0x0010); // kdf NULL
    t.u16(0);
    t.u16(0);
    t.finish().unwrap()
}

/// A primary ECC signing key, which is what the commit tests want.
fn primary(h: &Harness, scheme: u16, count: Option<u16>) -> (u32, Vec<u8>) {
    primary_with(h, SIGNING, scheme, count)
}

/// The x and y of the public point in a marshalled TPMT_PUBLIC.
fn public_point(public: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rd = Reader::new(public);
    rd.u16().unwrap(); // type
    rd.u16().unwrap(); // nameAlg
    rd.u32().unwrap(); // objectAttributes
    let policy = rd.u16().unwrap() as usize;
    rd.take(policy).unwrap();
    rd.u16().unwrap(); // symmetric
    let scheme = rd.u16().unwrap();
    if scheme != 0x0010 {
        rd.u16().unwrap(); // hash
        if scheme == 0x001A {
            rd.u16().unwrap(); // count
        }
    }
    rd.u16().unwrap(); // curve
    rd.u16().unwrap(); // kdf
    let xn = rd.u16().unwrap() as usize;
    let x = rd.take(xn).unwrap().to_vec();
    let yn = rd.u16().unwrap() as usize;
    let y = rd.take(yn).unwrap().to_vec();
    (x, y)
}

/// Read the three points and the counter out of a TPM2_Commit response.
fn commit_response(body: &[u8]) -> (Vec<(Vec<u8>, Vec<u8>)>, u16) {
    let mut rd = Reader::new(body);
    rd.u32().unwrap(); // parameterSize
    let mut points = Vec::new();
    for _ in 0..3 {
        let n = rd.u16().unwrap() as usize;
        let inner = rd.take(n).unwrap().to_vec();
        let mut ir = Reader::new(&inner);
        let xn = ir.u16().unwrap() as usize;
        let x = ir.take(xn).unwrap().to_vec();
        let yn = ir.u16().unwrap() as usize;
        let y = ir.take(yn).unwrap().to_vec();
        points.push((x, y));
    }
    (points, rd.u16().unwrap())
}

fn commit(h: &Harness, handle: u32, params: &[u8]) -> Answer {
    send(
        h,
        &command(st::SESSIONS, cc::Commit, &[handle], Some(&PASSWORD), params),
    )
}

/// P1, s2 and y2 all absent, which is the shortest well formed encoding.
fn empty_commit_params() -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(4); // TPM2B_ECC_POINT holding two empty coordinates
    p.u16(0);
    p.u16(0);
    p.u16(0); // s2
    p.u16(0); // y2
    p.finish().unwrap()
}

#[test]
fn commit_with_nothing_supplied_returns_r_times_g() {
    // Part 1 clause 44.2.3 step 11: with P1 an Empty Point and s2 an Empty
    // Buffer, E is [r]G. K and L stay empty.
    let h = harness("empty");
    let (handle, _) = primary(&h, 0x001A, Some(0));
    let r = commit(&h, handle, &empty_commit_params());
    assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
    let (points, counter) = commit_response(&r.body);
    assert!(points[0].0.is_empty(), "K should be empty");
    assert!(points[1].0.is_empty(), "L should be empty");
    assert!(!points[2].0.is_empty(), "E should be a point");
    assert_eq!(counter, 0, "the first commit is counter zero");

    // E has to be on the curve.
    let group = ecc::Curve::new(curve::NIST_P256).unwrap();
    assert!(ecc::Point::from_coordinates(&group, &points[2].0, &points[2].1).is_ok());

    // The next commit gives a different counter and a different point.
    let r2 = commit(&h, handle, &empty_commit_params());
    assert_eq!(r2.code, rc::SUCCESS);
    let (points2, counter2) = commit_response(&r2.body);
    assert_eq!(counter2, 1);
    assert_ne!(points[2].0, points2[2].0, "each commit uses a new value");
}

#[test]
fn commit_with_p1_returns_r_times_p1() {
    // Step 10: E := [r]P1. Taking P1 as the generator makes E the same value
    // the empty form produces for the same counter, which is what ties the
    // two branches together.
    let h = harness("p1");
    let (handle, _) = primary(&h, 0x001A, Some(0));
    let group = ecc::Curve::new(curve::NIST_P256).unwrap();
    let (gx, gy) = group.generator_coordinates().unwrap();

    let mut p = Writer::new();
    let mut inner = Writer::new();
    inner.u16(gx.len() as u16);
    inner.bytes(&gx);
    inner.u16(gy.len() as u16);
    inner.bytes(&gy);
    let inner = inner.finish().unwrap();
    p.u16(inner.len() as u16);
    p.bytes(&inner);
    p.u16(0); // s2
    p.u16(0); // y2
    let r = commit(&h, handle, &p.finish().unwrap());
    assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
    let (points, counter) = commit_response(&r.body);
    assert_eq!(counter, 0);
    assert!(points[0].0.is_empty(), "K should be empty without s2");
    assert!(points[1].0.is_empty(), "L should be empty without s2");
    assert!(!points[2].0.is_empty());
    assert!(ecc::Point::from_coordinates(&group, &points[2].0, &points[2].1).is_ok());
}

#[test]
fn commit_with_s2_and_y2_returns_k_and_l() {
    // Steps 3, 4 and 9: x2 is the digest of s2 reduced by the field modulus,
    // and with (x2, y2) on the curve the TPM returns K := [ds](x2,y2) and
    // L := [r](x2,y2).
    let h = harness("s2");
    let (handle, public) = primary(&h, 0x001A, Some(0));
    let group = ecc::Curve::new(curve::NIST_P256).unwrap();
    let (p_mod, _, _) = group.parameters().unwrap();
    let ctx = BnCtx::new().unwrap();

    // Search for an s2 whose digest is the x coordinate of a real point.
    let mut chosen = None;
    for i in 0..200u32 {
        let s2 = i.to_be_bytes().to_vec();
        let digest = swtrust::tpm::crypto::hash::digest(alg::SHA256, &s2).unwrap();
        let x2 = BigNum::from_bytes(&digest)
            .unwrap()
            .modulo(&p_mod, &ctx)
            .unwrap()
            .to_bytes_padded(32)
            .unwrap();
        // y^2 = x^3 - 3x + b, so try both roots by asking the library.
        if let Some(y2) = y_for_x(&group, &x2) {
            chosen = Some((s2, x2, y2));
            break;
        }
    }
    let (s2, x2, y2) = chosen.expect("no s2 gave a point on the curve");

    let mut p = Writer::new();
    p.u16(4);
    p.u16(0);
    p.u16(0);
    p.u16(s2.len() as u16);
    p.bytes(&s2);
    p.u16(y2.len() as u16);
    p.bytes(&y2);
    let r = commit(&h, handle, &p.finish().unwrap());
    assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
    let (points, _) = commit_response(&r.body);
    assert!(!points[0].0.is_empty(), "K should be a point");
    assert!(!points[1].0.is_empty(), "L should be a point");
    assert!(points[2].0.is_empty(), "E is empty when only s2 is given");

    // K := [ds](x2, y2), and the TPM holds ds. What can be checked from
    // outside is that K is on the curve and is not the base point itself.
    assert!(ecc::Point::from_coordinates(&group, &points[0].0, &points[0].1).is_ok());
    assert!(ecc::Point::from_coordinates(&group, &points[1].0, &points[1].1).is_ok());
    assert_ne!(points[0].0, x2);
    assert_ne!(points[0], points[1], "K and L come from different scalars");
    let _ = public;
}

/// A y coordinate for `x` on the curve, if one exists.
fn y_for_x(group: &ecc::Curve, x: &[u8]) -> Option<Vec<u8>> {
    // y^2 = x^3 + ax + b. Solve by trying the square root of the right side.
    let ctx = BnCtx::new().unwrap();
    let (p, a, b) = group.parameters().unwrap();
    let xb = BigNum::from_bytes(x).unwrap();
    let x3 = xb
        .mul(&xb, &ctx)
        .unwrap()
        .modulo(&p, &ctx)
        .unwrap()
        .mul(&xb, &ctx)
        .unwrap()
        .modulo(&p, &ctx)
        .unwrap();
    let ax = a.mul(&xb, &ctx).unwrap().modulo(&p, &ctx).unwrap();
    let rhs = x3.add(&ax).unwrap().add(&b).unwrap().modulo(&p, &ctx).unwrap();
    // The modulus of P-256 is congruent to 3 modulo 4, so a square root is
    // rhs raised to (p + 1) / 4.
    let exponent = p.add_word(1).unwrap().shift_right(2).unwrap();
    let y = rhs.mod_exp(&exponent, &p, &ctx).ok()?;
    // Only half the values have a root, so the result is checked.
    if y.mul(&y, &ctx).unwrap().modulo(&p, &ctx).unwrap().cmp(&rhs) != 0 {
        return None;
    }
    let y = y.to_bytes_padded(32).ok()?;
    // Confirm through the library that the pair really is a point.
    ecc::Point::from_coordinates(group, x, &y).ok()?;
    Some(y)
}

#[test]
fn a_commit_completes_an_ecdaa_signature_and_is_then_spent() {
    // Part 1 clause 44.3.3.1: an ECDAA key may be used in any command that
    // produces a signature, and clause 44.2.2 allows the commit to be used
    // once.
    let h = harness("ecdaa");
    let (handle, _) = primary(&h, 0x001A, Some(0));

    let r = commit(&h, handle, &empty_commit_params());
    assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
    let (_, counter) = commit_response(&r.body);

    // TPM2_Sign names the counter in the scheme.
    let sign = |counter: u16| {
        let mut p = Writer::new();
        p.u16(32);
        p.bytes(&[0x5au8; 32]);
        p.u16(0x001A); // ECDAA
        p.u16(alg::SHA256);
        p.u16(counter);
        p.u16(st::HASHCHECK);
        p.u32(rh::NULL);
        p.u16(0);
        send(
            &h,
            &command(
                st::SESSIONS,
                cc::Sign,
                &[handle],
                Some(&PASSWORD),
                &p.finish().unwrap(),
            ),
        )
    };

    let r = sign(counter);
    assert_eq!(r.code, rc::SUCCESS, "Sign with ECDAA -> {:08x}", r.code);
    let mut rd = Reader::new(&r.body);
    rd.u32().unwrap();
    assert_eq!(rd.u16().unwrap(), 0x001A, "the signature is an ECDAA one");
    rd.u16().unwrap(); // hash
    let rn = rd.u16().unwrap() as usize;
    let sig_r = rd.take(rn).unwrap().to_vec();
    let sn = rd.u16().unwrap() as usize;
    let sig_s = rd.take(sn).unwrap().to_vec();
    assert_eq!(sig_r.len(), 32);
    assert_eq!(sig_s.len(), 32);
    assert_ne!(sig_r, vec![0u8; 32]);
    assert_ne!(sig_s, vec![0u8; 32]);

    // The commit has been spent, so the same counter cannot be used again.
    let again = sign(counter);
    assert_ne!(again.code, rc::SUCCESS, "a commit was used twice");

    // A counter that was never committed is refused as well.
    assert_ne!(sign(9999).code, rc::SUCCESS);
}

#[test]
fn full_mqv_returns_one_point_computed_from_both_keys() {
    // Part 1 clause 44.8.4.3. The scheme produces a single value in outZ1,
    // built from the static and ephemeral private keys and both peer points,
    // so it has to differ from what the Full Unified Model gives and it has
    // to be a real point.
    let h = harness("mqv");
    let (handle, _) = primary_with(&h, DECRYPTING, 0x0010, None);
    let group = ecc::Curve::new(curve::NIST_P256).unwrap();

    let mut rng = swtrust::tpm::crypto::rand::Drbg::new(&[0x71u8; 48], b"peer").unwrap();
    let qs_b = ecc::generate(curve::NIST_P256, &mut rng).unwrap();
    let qe_b = ecc::generate(curve::NIST_P256, &mut rng).unwrap();

    let two_phase = |scheme: u16| {
        let mut p = Writer::new();
        p.u16(curve::NIST_P256);
        let r = send(
            &h,
            &command(st::NO_SESSIONS, cc::EC_Ephemeral, &[], None, &p.finish().unwrap()),
        );
        assert_eq!(r.code, rc::SUCCESS, "EC_Ephemeral -> {:08x}", r.code);
        let mut rd = Reader::new(&r.body);
        let n = rd.u16().unwrap() as usize;
        rd.take(n).unwrap();
        let counter = rd.u16().unwrap();

        let mut p = Writer::new();
        for k in [&qs_b, &qe_b] {
            let mut inner = Writer::new();
            inner.u16(k.public_x.len() as u16);
            inner.bytes(&k.public_x);
            inner.u16(k.public_y.len() as u16);
            inner.bytes(&k.public_y);
            let inner = inner.finish().unwrap();
            p.u16(inner.len() as u16);
            p.bytes(&inner);
        }
        p.u16(scheme);
        p.u16(counter);
        let r = send(
            &h,
            &command(
                st::SESSIONS,
                cc::ZGen_2Phase,
                &[handle],
                Some(&PASSWORD),
                &p.finish().unwrap(),
            ),
        );
        assert_eq!(r.code, rc::SUCCESS, "ZGen_2Phase -> {:08x}", r.code);
        let mut rd = Reader::new(&r.body);
        rd.u32().unwrap();
        let mut out = Vec::new();
        for _ in 0..2 {
            let n = rd.u16().unwrap() as usize;
            let inner = rd.take(n).unwrap().to_vec();
            let mut ir = Reader::new(&inner);
            let xn = ir.u16().unwrap() as usize;
            let x = ir.take(xn).unwrap().to_vec();
            let yn = ir.u16().unwrap() as usize;
            let y = ir.take(yn).unwrap().to_vec();
            out.push((x, y));
        }
        out
    };

    let mqv = two_phase(alg::ECMQV);
    assert!(!mqv[0].0.is_empty(), "outZ1 should be a point");
    assert!(
        mqv[1].0.is_empty(),
        "Full MQV produces one value, so outZ2 is the point at infinity"
    );
    assert!(
        ecc::Point::from_coordinates(&group, &mqv[0].0, &mqv[0].1).is_ok(),
        "outZ1 is not on the curve"
    );

    // The two schemes cannot give the same answer, or one of them is wrong.
    let unified = two_phase(alg::ECDH);
    assert_ne!(mqv[0].0, unified[0].0);
    assert_ne!(mqv[0].0, unified[1].0);
}

#[test]
fn the_version_185_signing_commands_take_the_commit_counter() {
    // Part 3 clause 17.5.1: "If the scheme of keyHandle uses a counter value
    // (e.g., TPM_ALG_ECDAA), then context shall contain the counter value from
    // TPM2_Commit() to use for the signature." Part 2 Table 220 makes that a
    // UINT16 for ECDAA.
    let h = harness("v185");
    let (handle, _) = primary(&h, 0x001A, Some(0));

    let take_counter = || {
        let r = commit(&h, handle, &empty_commit_params());
        assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
        commit_response(&r.body).1
    };

    // TPM2_SignDigest with the counter in its context.
    let sign_digest = |counter: Option<u16>| {
        let mut p = Writer::new();
        match counter {
            Some(c) => {
                p.u16(2);
                p.u16(c);
            }
            None => p.u16(0),
        }
        p.u16(32);
        p.bytes(&[0x11u8; 32]);
        p.u16(st::HASHCHECK);
        p.u32(rh::NULL);
        p.u16(0);
        send(
            &h,
            &command(
                st::SESSIONS,
                cc::SignDigest,
                &[handle],
                Some(&PASSWORD),
                &p.finish().unwrap(),
            ),
        )
    };

    let counter = take_counter();
    let r = sign_digest(Some(counter));
    assert_eq!(r.code, rc::SUCCESS, "SignDigest with a counter -> {:08x}", r.code);

    // The commit is spent, so the same counter cannot be used again.
    assert_ne!(sign_digest(Some(counter)).code, rc::SUCCESS);

    // An ECDAA key with no counter at all has nothing to complete.
    assert_ne!(sign_digest(None).code, rc::SUCCESS, "a missing counter was accepted");

    // TPM2_SignSequenceStart takes it too, and the sequence carries it to the
    // completion.
    let counter = take_counter();
    let mut p = Writer::new();
    p.u16(0); // auth
    p.u16(2); // context
    p.u16(counter);
    let r = send(
        &h,
        &command(
            st::NO_SESSIONS,
            cc::SignSequenceStart,
            &[handle],
            None,
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "SignSequenceStart -> {:08x}", r.code);
    let sequence = u32::from_be_bytes([r.body[0], r.body[1], r.body[2], r.body[3]]);

    let mut p = Writer::new();
    p.u16(5);
    p.bytes(b"hello");
    let auth2 = [PASSWORD.as_slice(), PASSWORD.as_slice()].concat();
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::SignSequenceComplete,
            &[sequence, handle],
            Some(&auth2),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "SignSequenceComplete with a carried counter -> {:08x}",
        r.code
    );
    let mut rd = Reader::new(&r.body);
    rd.u32().unwrap();
    assert_eq!(rd.u16().unwrap(), 0x001A, "the signature is an ECDAA one");
}

#[test]
fn a_commit_survives_a_new_tpm_built_from_the_state_file() {
    // Part 1 clause 34.4.4 saves the commit values to NV on Shutdown(STATE).
    // The in process resume keeps them in memory, so this one throws the TPM
    // away and builds another from the file, which is what a restarted daemon
    // does.
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "swtrust-split-file-{}-{}",
        std::process::id(),
        swtrust::util::time::unix_millis_now()
    ));
    let logger = Arc::new(Logger::new(dir.join("logs"), false).unwrap());
    let state_dir = dir.join("state");

    let counter = {
        // Not a Harness, because that removes the directory when it is
        // dropped and the second TPM needs the file that is in it.
        let tpm = Tpm::new(&state_dir, logger.clone()).unwrap();
        tpm.power_on();
        let r = send_to(&tpm, &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0, 0]));
        assert_eq!(r.code, rc::SUCCESS);
        let template = ecdaa_template();
        let (handle, _) = create_primary(&tpm, &template);
        let r = send_to(
            &tpm,
            &command(
                st::SESSIONS,
                cc::Commit,
                &[handle],
                Some(&PASSWORD),
                &empty_commit_params(),
            ),
        );
        assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
        let (_, counter) = commit_response(&r.body);

        // Shutdown(STATE) is what puts them in the file.
        let r = send_to(
            &tpm,
            &command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]),
        );
        assert_eq!(r.code, rc::SUCCESS);
        tpm.persist();
        counter
    };

    // A second TPM over the same file, as a restarted daemon would build.
    let tpm = Tpm::new(&state_dir, logger).unwrap();
    tpm.power_on();
    let h = Harness { tpm, dir };
    let r = send(&h, &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS, "Startup(STATE) -> {:08x}", r.code);

    let (handle, _) = primary(&h, 0x001A, Some(0));
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0x5au8; 32]);
    p.u16(0x001A);
    p.u16(alg::SHA256);
    p.u16(counter);
    p.u16(st::HASHCHECK);
    p.u32(rh::NULL);
    p.u16(0);
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::Sign,
            &[handle],
            Some(&PASSWORD),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a commit did not survive the state file -> {:08x}",
        r.code
    );
    // The Harness removes the directory when it goes.
}

#[test]
fn an_ecdaa_attestation_hides_the_signer() {
    // Part 1 clause 21.5: with an anonymous scheme the qualifiedSigner of the
    // attestation is an Empty Buffer, and for TPM2_Certify the qualifiedName
    // of the certified key is emptied too. Without that the signature would
    // name exactly the key it was meant to hide.
    let h = harness("anon");
    // A restricted ECDAA signing key, which is what an attestation needs.
    let (signer, _) = primary_with(&h, SIGNING | 0x0001_0000, 0x001A, Some(0));
    let (subject, _) = primary_with(&h, SIGNING, 0x0018, None);

    let r = commit(&h, signer, &empty_commit_params());
    assert_eq!(r.code, rc::SUCCESS, "Commit -> {:08x}", r.code);
    let (_, counter) = commit_response(&r.body);

    let mut p = Writer::new();
    p.u16(0); // qualifyingData
    p.u16(0x001A); // ECDAA
    p.u16(alg::SHA256);
    p.u16(counter);
    let auth2 = [PASSWORD.as_slice(), PASSWORD.as_slice()].concat();
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::Certify,
            &[subject, signer],
            Some(&auth2),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "Certify with ECDAA -> {:08x}", r.code);

    // Read the attestation back and check what it does not say.
    let mut rd = Reader::new(&r.body);
    rd.u32().unwrap(); // parameterSize
    let n = rd.u16().unwrap() as usize;
    let attest = rd.take(n).unwrap().to_vec();
    let mut ar = Reader::new(&attest);
    assert_eq!(ar.u32().unwrap(), 0xff54_4347, "TPM_GENERATED");
    ar.u16().unwrap(); // type
    let signer_len = ar.u16().unwrap() as usize;
    assert_eq!(signer_len, 0, "the qualifiedSigner names the key that signed");
    let extra = ar.u16().unwrap() as usize;
    ar.take(extra).unwrap();
    // clockInfo is a clock, resetCount, restartCount and safe.
    ar.u64().unwrap();
    ar.u32().unwrap();
    ar.u32().unwrap();
    ar.u8().unwrap();
    ar.u64().unwrap(); // firmwareVersion
    let name_len = ar.u16().unwrap() as usize;
    ar.take(name_len).unwrap();
    let qualified_len = ar.u16().unwrap() as usize;
    assert_eq!(
        qualified_len, 0,
        "the qualifiedName of the certified key names its parentage"
    );

    // The same certification with an ordinary scheme does name the signer.
    let (plain, _) = primary_with(&h, SIGNING | 0x0001_0000, 0x0018, None);
    let mut p = Writer::new();
    p.u16(0);
    p.u16(0x0010); // scheme NULL, so the key's own is used
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::Certify,
            &[subject, plain],
            Some(&auth2),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "Certify with ECDSA -> {:08x}", r.code);
    let mut rd = Reader::new(&r.body);
    rd.u32().unwrap();
    let n = rd.u16().unwrap() as usize;
    let attest = rd.take(n).unwrap().to_vec();
    let mut ar = Reader::new(&attest);
    ar.u32().unwrap();
    ar.u16().unwrap();
    assert_ne!(
        ar.u16().unwrap(),
        0,
        "an ordinary attestation should name its signer"
    );
}

#[test]
fn a_bad_counter_names_the_parameter_that_carried_it() {
    // Part 2 clause 6.6.2 adds TPM_RC_P and the parameter number when an error
    // belongs to a parameter. The counter arrives in a different parameter of
    // each command, so each one says which of its own.
    let h = harness("qualify");
    let (handle, _) = primary(&h, 0x001A, Some(0));

    // TPM2_Sign carries it in inScheme, which is parameter 2.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0x5au8; 32]);
    p.u16(0x001A);
    p.u16(alg::SHA256);
    p.u16(4242); // never committed
    p.u16(st::HASHCHECK);
    p.u32(rh::NULL);
    p.u16(0);
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::Sign,
            &[handle],
            Some(&PASSWORD),
            &p.finish().unwrap(),
        ),
    );
    assert_ne!(r.code, rc::SUCCESS);
    assert_eq!(r.code & 0x040, 0x040, "TPM_RC_P is not set: {:08x}", r.code);
    assert_eq!((r.code >> 8) & 0xf, 2, "wrong parameter: {:08x}", r.code);

    // TPM2_SignDigest carries it in context, which is parameter 1.
    let mut p = Writer::new();
    p.u16(2);
    p.u16(4242);
    p.u16(32);
    p.bytes(&[0x11u8; 32]);
    p.u16(st::HASHCHECK);
    p.u32(rh::NULL);
    p.u16(0);
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::SignDigest,
            &[handle],
            Some(&PASSWORD),
            &p.finish().unwrap(),
        ),
    );
    assert_ne!(r.code, rc::SUCCESS);
    assert_eq!(r.code & 0x040, 0x040, "TPM_RC_P is not set: {:08x}", r.code);
    assert_eq!((r.code >> 8) & 0xf, 1, "wrong parameter: {:08x}", r.code);
}

#[test]
fn two_phase_needs_an_unrestricted_decryption_key() {
    // Part 3 Table 54 names keyA "handle of an unrestricted ECC decryption
    // key". A signing key or a restricted one used as a key agreement scalar
    // would be doing something its attributes do not allow.
    let h = harness("keya");

    let two_phase = |handle: u32| {
        let mut p = Writer::new();
        p.u16(curve::NIST_P256);
        let r = send(
            &h,
            &command(st::NO_SESSIONS, cc::EC_Ephemeral, &[], None, &p.finish().unwrap()),
        );
        assert_eq!(r.code, rc::SUCCESS);
        let mut rd = Reader::new(&r.body);
        let n = rd.u16().unwrap() as usize;
        rd.take(n).unwrap();
        let counter = rd.u16().unwrap();

        let mut rng = swtrust::tpm::crypto::rand::Drbg::new(&[0x91u8; 48], b"peer").unwrap();
        let mut p = Writer::new();
        for _ in 0..2 {
            let k = ecc::generate(curve::NIST_P256, &mut rng).unwrap();
            let mut inner = Writer::new();
            inner.u16(k.public_x.len() as u16);
            inner.bytes(&k.public_x);
            inner.u16(k.public_y.len() as u16);
            inner.bytes(&k.public_y);
            let inner = inner.finish().unwrap();
            p.u16(inner.len() as u16);
            p.bytes(&inner);
        }
        p.u16(alg::ECDH);
        p.u16(counter);
        send(
            &h,
            &command(
                st::SESSIONS,
                cc::ZGen_2Phase,
                &[handle],
                Some(&PASSWORD),
                &p.finish().unwrap(),
            ),
        )
    };

    // A signing key is refused.
    let (signing, _) = primary_with(&h, SIGNING, 0x0010, None);
    assert_ne!(two_phase(signing).code, rc::SUCCESS, "a signing key was accepted");

    // So is a restricted decryption key, which is a storage key.
    let (restricted, _) = primary_with(&h, DECRYPTING | 0x0001_0000, 0x0010, None);
    assert_ne!(
        two_phase(restricted).code,
        rc::SUCCESS,
        "a restricted key was accepted"
    );

    // An unrestricted decryption key is what the command is for.
    let (good, _) = primary_with(&h, DECRYPTING, 0x0010, None);
    assert_eq!(two_phase(good).code, rc::SUCCESS);
}

#[test]
fn a_commit_survives_a_resume_and_a_restart_but_not_a_reset() {
    // Part 1 Table 41 puts the commit values in the state reset data, and
    // clause 34.4.4 saves that on any Shutdown(STATE) and restores it on the
    // next Startup of any type, initializing it only on a TPM Reset.
    let h = harness("resume");
    let (handle, _) = primary(&h, 0x001A, Some(0));

    let r = commit(&h, handle, &empty_commit_params());
    assert_eq!(r.code, rc::SUCCESS);
    let (_, counter) = commit_response(&r.body);

    // Shutdown(STATE), a power cycle, then Startup(STATE) is a TPM Resume.
    // Part 3 clause 9.3.1: "TPM2_Startup() is always preceded by _TPM_Init".
    let r = send(&h, &command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS, "Shutdown -> {:08x}", r.code);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = send(&h, &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x01]));
    assert_eq!(r.code, rc::SUCCESS, "Startup(STATE) -> {:08x}", r.code);

    // The key is gone with the resume, but it is a primary, so it comes back
    // the same and with the same Name the commit was derived under.
    let (handle, _) = primary(&h, 0x001A, Some(0));

    // The commit made before the shutdown is still good.
    let mut p = Writer::new();
    p.u16(32);
    p.bytes(&[0x5au8; 32]);
    p.u16(0x001A);
    p.u16(alg::SHA256);
    p.u16(counter);
    p.u16(st::HASHCHECK);
    p.u32(rh::NULL);
    p.u16(0);
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::Sign,
            &[handle],
            Some(&PASSWORD),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(
        r.code,
        rc::SUCCESS,
        "a commit did not survive a resume -> {:08x}",
        r.code
    );

    // A TPM Reset is Shutdown(CLEAR), a power cycle, then Startup(CLEAR), and
    // that does initialize them, so a new commit starts the counter again.
    let r = send(&h, &command(st::NO_SESSIONS, cc::Shutdown, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS);
    h.tpm.power_off();
    h.tpm.power_on();
    let r = send(&h, &command(st::NO_SESSIONS, cc::Startup, &[], None, &[0x00, 0x00]));
    assert_eq!(r.code, rc::SUCCESS, "Startup(CLEAR) -> {:08x}", r.code);
    let (handle, _) = primary(&h, 0x001A, Some(0));
    let r = commit(&h, handle, &empty_commit_params());
    assert_eq!(r.code, rc::SUCCESS);
    let (_, after) = commit_response(&r.body);
    assert_eq!(after, 0, "a TPM Reset starts the counter again");
}

#[test]
fn an_ephemeral_key_completes_a_two_phase_exchange() {
    // Part 1 clause 44.8.4.2, the Full Unified Model: outZ1 is [ds]QsB and
    // outZ2 is [de]QeB, where de is the value the counter names.
    let h = harness("twophase");
    let (handle, public) = primary_with(&h, DECRYPTING, 0x0010, None);
    let group = ecc::Curve::new(curve::NIST_P256).unwrap();

    // The TPM's ephemeral public key, and the counter that names its private.
    let mut p = Writer::new();
    p.u16(curve::NIST_P256);
    let r = send(
        &h,
        &command(st::NO_SESSIONS, cc::EC_Ephemeral, &[], None, &p.finish().unwrap()),
    );
    assert_eq!(r.code, rc::SUCCESS, "EC_Ephemeral -> {:08x}", r.code);
    let mut rd = Reader::new(&r.body);
    let n = rd.u16().unwrap() as usize;
    let point = rd.take(n).unwrap().to_vec();
    let counter = rd.u16().unwrap();
    let mut pr = Reader::new(&point);
    let xn = pr.u16().unwrap() as usize;
    let qe_a_x = pr.take(xn).unwrap().to_vec();
    let yn = pr.u16().unwrap() as usize;
    let qe_a_y = pr.take(yn).unwrap().to_vec();
    assert!(ecc::Point::from_coordinates(&group, &qe_a_x, &qe_a_y).is_ok());

    // The other party's two key pairs, generated here so the results can be
    // checked from outside.
    let mut rng = swtrust::tpm::crypto::rand::Drbg::new(&[0x31u8; 48], b"peer").unwrap();
    let qs_b = ecc::generate(curve::NIST_P256, &mut rng).unwrap();
    let qe_b = ecc::generate(curve::NIST_P256, &mut rng).unwrap();

    let mut p = Writer::new();
    for k in [&qs_b, &qe_b] {
        let mut inner = Writer::new();
        inner.u16(k.public_x.len() as u16);
        inner.bytes(&k.public_x);
        inner.u16(k.public_y.len() as u16);
        inner.bytes(&k.public_y);
        let inner = inner.finish().unwrap();
        p.u16(inner.len() as u16);
        p.bytes(&inner);
    }
    p.u16(alg::ECDH);
    p.u16(counter);
    let r = send(
        &h,
        &command(
            st::SESSIONS,
            cc::ZGen_2Phase,
            &[handle],
            Some(&PASSWORD),
            &p.finish().unwrap(),
        ),
    );
    assert_eq!(r.code, rc::SUCCESS, "ZGen_2Phase -> {:08x}", r.code);
    let mut rd = Reader::new(&r.body);
    rd.u32().unwrap();
    let mut got = Vec::new();
    for _ in 0..2 {
        let n = rd.u16().unwrap() as usize;
        let inner = rd.take(n).unwrap().to_vec();
        let mut ir = Reader::new(&inner);
        let xn = ir.u16().unwrap() as usize;
        let x = ir.take(xn).unwrap().to_vec();
        let yn = ir.u16().unwrap() as usize;
        ir.take(yn).unwrap();
        got.push(x);
    }

    // outZ1 must be the shared value the other party computes with its static
    // private key and the TPM's static public key.
    let (tpm_x, tpm_y) = public_point(&public);
    let (z1, _) = ecc::ecdh(&group, &qs_b.private, &tpm_x, &tpm_y).unwrap();
    assert_eq!(got[0], z1, "outZ1 is not the static shared value");

    // outZ2 must be the value from the other party's ephemeral key and the
    // TPM's ephemeral public key, which proves the TPM used the committed
    // ephemeral private and not its static one.
    let (z2, _) = ecc::ecdh(&group, &qe_b.private, &qe_a_x, &qe_a_y).unwrap();
    assert_eq!(got[1], z2, "outZ2 is not the ephemeral shared value");
    assert_ne!(got[0], got[1]);
}
