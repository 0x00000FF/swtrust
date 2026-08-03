//! The exchange a virtual machine monitor performs, replayed against a real TPM.
//!
//! These tests are not a paraphrase of the transport. They send the same
//! requests, in the same order, with the same payload lengths, that QEMU sends
//! when it attaches an external TPM, and they read the replies the way QEMU
//! reads them: the result word first, and the rest of the reply only when that
//! word is zero. A transport that framed a reply differently would be caught
//! here even though it looked correct on its own terms.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use swtrust::cli::{Config, Interface};
use swtrust::logging::Logger;
use swtrust::server::qemu::{self, cap, request, CAPABILITIES, MAX_BUFFER_SIZE, MIN_BUFFER_SIZE};
use swtrust::tpm::constants::{cap as tpm_cap, cc, pt, rc, rh, st};
use swtrust::tpm::device::Tpm;

/// A running transport with a real TPM behind it.
struct Server {
    control: TcpStream,
    data: TcpStream,
    joined: Option<thread::JoinHandle<std::io::Result<()>>>,
    dir: std::path::PathBuf,
}

/// Lowest port the search considers.
const SEARCH_BASE: u32 = 20000;
/// How many ports the search may walk.
const SEARCH_SPAN: u32 = 40000;

/// Find a port such that it and the next one are both free.
///
/// Asking the system for any free port and then hoping the one after it is
/// free as well fails often enough to matter, because the port it hands back
/// comes from a range it is busy handing out. Instead a wide range is walked
/// two at a time, from a starting point that depends on the process and the
/// clock so that two runs at once do not walk the same ground in step.
fn free_port_pair() -> u16 {
    let spread = std::process::id() as u32 ^ swtrust::util::time::unix_millis_now() as u32;
    let start = spread % SEARCH_SPAN;
    for step in 0..SEARCH_SPAN / 2 {
        let port = SEARCH_BASE + (start + step * 2) % SEARCH_SPAN;
        if port + 1 > u16::MAX as u32 {
            continue;
        }
        let port = port as u16;
        let Ok(a) = TcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        let Ok(b) = TcpListener::bind(("127.0.0.1", port + 1)) else {
            continue;
        };
        drop(a);
        drop(b);
        return port;
    }
    panic!("no free port pair in {SEARCH_BASE}..{}", SEARCH_BASE + SEARCH_SPAN);
}

/// Connect within a budget, or report that nothing came up in time.
fn connect_within(port: u16, budget: Duration) -> Option<TcpStream> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            return Some(s);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Wait for a thread to finish, without waiting for ever.
fn finished_within(j: &thread::JoinHandle<std::io::Result<()>>, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if j.is_finished() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    j.is_finished()
}

/// Stop a transport that never became usable, without blocking the test run.
fn abandon(joined: thread::JoinHandle<std::io::Result<()>>, port: u16) {
    if !joined.is_finished() {
        if let Some(mut control) = connect_within(port + 1, Duration::from_millis(200)) {
            let _ = control.write_all(&request::SHUTDOWN.to_be_bytes());
            let mut word = [0u8; 4];
            let _ = control.read_exact(&mut word);
        }
        finished_within(&joined, Duration::from_secs(2));
    }
    // The handle is dropped rather than joined, so a transport that will not
    // come down cannot wedge the whole run.
    drop(joined);
}

impl Server {
    fn start(tag: &str) -> Server {
        // A port pair is chosen by binding it and letting it go again, so
        // another test can take it in between. That is retried rather than
        // reported, because it says nothing about the transport.
        for attempt in 0..8 {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "swtrust-qemu-{tag}-{}-{}-{attempt}",
                std::process::id(),
                swtrust::util::time::unix_millis_now()
            ));
            let port = free_port_pair();
            let config = Config {
                interface: Interface::Qemu,
                port,
                state_dir: dir.join("state"),
                log_dir: dir.join("logs"),
                ..Default::default()
            };
            let logger = Arc::new(Logger::new(config.log_dir.clone(), false).unwrap());
            let tpm = Arc::new(Tpm::new(&config.state_dir, logger.clone()).unwrap());
            let joined = thread::spawn(move || qemu::serve(&config, tpm, logger));

            // The data channel is the command port and the control channel the
            // one after it, which is the pairing the caller is configured with.
            let opened = connect_within(port, Duration::from_secs(2)).and_then(|data| {
                connect_within(port + 1, Duration::from_secs(2)).map(|control| (data, control))
            });
            match opened {
                Some((data, control)) => {
                    return Server {
                        control,
                        data,
                        joined: Some(joined),
                        dir,
                    }
                }
                None => {
                    abandon(joined, port);
                    std::fs::remove_dir_all(&dir).ok();
                }
            }
        }
        panic!("no port pair stayed free long enough to start the transport");
    }

    /// Send a control request and read the result word.
    fn result(&mut self, number: u32, payload: &[u8]) -> u32 {
        let mut req = number.to_be_bytes().to_vec();
        req.extend_from_slice(payload);
        self.control.write_all(&req).unwrap();
        let mut word = [0u8; 4];
        self.control.read_exact(&mut word).unwrap();
        u32::from_be_bytes(word)
    }

    /// Read `n` further octets of a reply whose result was zero.
    fn rest(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.control.read_exact(&mut buf).unwrap();
        buf
    }

    /// Send a command buffer on the data channel and read the response the way
    /// the caller does: the header first, then as much again as its size says.
    fn command(&mut self, buf: &[u8]) -> Vec<u8> {
        self.data.write_all(buf).unwrap();
        let mut header = [0u8; 10];
        self.data.read_exact(&mut header).unwrap();
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        assert!(size >= 10, "response size {size} is below a header");
        let mut out = header.to_vec();
        out.resize(size, 0);
        self.data.read_exact(&mut out[10..]).unwrap();
        out
    }

    /// Bring the TPM up the way the caller does, and start it.
    fn attach(&mut self) {
        assert_eq!(self.result(request::INIT, &0u32.to_be_bytes()), 0);
        let out = self.command(&command_with(cc::Startup, &[0x00, 0x00]));
        assert_eq!(response_code(&out), rc::SUCCESS, "startup failed");
    }

    /// Ask the transport to shut down and wait for it to return.
    fn finish(mut self) {
        assert_eq!(self.result(request::SHUTDOWN, &[]), 0);
        if let Some(j) = self.joined.take() {
            assert!(
                finished_within(&j, Duration::from_secs(10)),
                "serve did not return after shutdown"
            );
            j.join().unwrap().unwrap();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // A test that failed before it finished leaves the transport running.
        // Nothing here may panic, because a panic while the thread is already
        // unwinding takes the whole test binary down, and nothing here may wait
        // without a bound, because that would turn one failure into a run that
        // never ends.
        if let Some(j) = self.joined.take() {
            let _ = self.control.write_all(&request::SHUTDOWN.to_be_bytes());
            let mut word = [0u8; 4];
            let _ = self.control.read_exact(&mut word);
            finished_within(&j, Duration::from_secs(2));
            drop(j);
        }
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// A command buffer with no parameters.
fn bare_command(code: u32) -> Vec<u8> {
    command_with(code, &[])
}

fn command_with(code: u32, body: &[u8]) -> Vec<u8> {
    let mut v = st::NO_SESSIONS.to_be_bytes().to_vec();
    v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&code.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// TPM2_PCR_Reset for `index`, authorized with a password session.
fn pcr_reset(index: u32) -> Vec<u8> {
    let mut auth = rh::RS_PW.to_be_bytes().to_vec();
    auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
    auth.push(0); // session attributes
    auth.extend_from_slice(&0u16.to_be_bytes()); // password

    let mut body = index.to_be_bytes().to_vec();
    body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth);

    let mut v = st::SESSIONS.to_be_bytes().to_vec();
    v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&cc::PCR_Reset.to_be_bytes());
    v.extend_from_slice(&body);
    v
}

fn response_code(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]])
}

/// The manufacturer property, which proves a command ran end to end.
fn manufacturer_query() -> Vec<u8> {
    let mut body = tpm_cap::TPM_PROPERTIES.to_be_bytes().to_vec();
    body.extend_from_slice(&pt::MANUFACTURER.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    command_with(cc::GetCapability, &body)
}

/// The version probe the caller sends before anything else.
///
/// It goes out on the data channel while the TPM has not been powered, and the
/// caller accepts an error as long as the response carries a TPM 2.0 tag. That
/// tag is what identifies the device as a TPM 2.0 rather than a 1.2, so a
/// transport that refused to answer before initialisation would never attach.
#[test]
fn the_version_probe_is_answered_with_a_tpm_2_tag_before_the_tpm_is_powered() {
    let mut s = Server::start("probe");
    let out = s.command(&bare_command(cc::ReadClock));
    assert_eq!(out.len(), 10);
    assert_eq!(
        u16::from_be_bytes([out[0], out[1]]),
        st::NO_SESSIONS,
        "the probe must come back with a TPM 2.0 tag"
    );
    assert_eq!(
        response_code(&out),
        rc::INITIALIZE,
        "a TPM that has not been powered reports that it is not initialised"
    );
    s.finish();
}

/// The whole attach sequence, in order, followed by real work.
#[test]
fn a_full_attach_brings_the_tpm_up_and_reports_the_manufacturer() {
    let mut s = Server::start("attach");

    // 1. Probe the version on the data channel.
    let out = s.command(&bare_command(cc::ReadClock));
    assert_eq!(u16::from_be_bytes([out[0], out[1]]), st::NO_SESSIONS);

    // 2. Ask what the transport supports.
    assert_eq!(s.result(request::GET_CAPABILITY, &[]), 0);
    let caps = u32::from_be_bytes(s.rest(4).try_into().unwrap());
    assert_eq!(caps, CAPABILITIES);
    for bit in [
        cap::INIT,
        cap::SHUTDOWN,
        cap::GET_ESTABLISHED,
        cap::SET_LOCALITY,
        cap::RESET_ESTABLISHED,
        cap::STOP,
        cap::SET_BUFFERSIZE,
    ] {
        assert_eq!(caps & bit, bit, "missing capability {bit:#x}");
    }

    // 3. Read the buffer size, which is preceded by a stop.
    assert_eq!(s.result(request::STOP, &[]), 0);
    assert_eq!(s.result(request::SET_BUFFERSIZE, &0u32.to_be_bytes()), 0);
    let reply = s.rest(12);
    let in_use = u32::from_be_bytes(reply[0..4].try_into().unwrap());
    let smallest = u32::from_be_bytes(reply[4..8].try_into().unwrap());
    let largest = u32::from_be_bytes(reply[8..12].try_into().unwrap());
    assert_eq!(in_use, MAX_BUFFER_SIZE);
    assert_eq!(smallest, MIN_BUFFER_SIZE);
    assert_eq!(largest, MAX_BUFFER_SIZE);

    // 4. Agree the size the device model wants, again preceded by a stop. The
    //    caller refuses to continue unless it gets back exactly what it asked
    //    for, so that is checked the same way here.
    assert_eq!(s.result(request::STOP, &[]), 0);
    assert_eq!(s.result(request::SET_BUFFERSIZE, &in_use.to_be_bytes()), 0);
    let reply = s.rest(12);
    assert_eq!(
        u32::from_be_bytes(reply[0..4].try_into().unwrap()),
        in_use,
        "the agreed size must match the request exactly"
    );

    // 5. Initialise.
    assert_eq!(s.result(request::INIT, &0u32.to_be_bytes()), 0);

    // 6. Read the establishment flag. This reply is always eight octets.
    assert_eq!(s.result(request::GET_ESTABLISHED, &[]), 0);
    assert_eq!(s.rest(4), vec![0, 0, 0, 0]);

    // 7. The guest now starts the TPM and asks who made it.
    let out = s.command(&command_with(cc::Startup, &[0x00, 0x00]));
    assert_eq!(response_code(&out), rc::SUCCESS, "startup failed");

    let out = s.command(&manufacturer_query());
    assert_eq!(response_code(&out), rc::SUCCESS);
    assert!(
        out.windows(3).any(|w| w == b"SWT"),
        "the manufacturer must reach the caller: {out:02x?}"
    );

    s.finish();
}

/// A command runs at the locality chosen on the control channel.
///
/// PCR 21 is a TCB register, which the PC Client profile lets localities two
/// and three reset and no other. Sending the same command buffer at locality
/// zero and at locality two and getting different answers is proof that the
/// locality crossed from the control channel to the data channel.
#[test]
fn the_locality_chosen_on_the_control_channel_reaches_the_command() {
    let mut s = Server::start("locality");
    s.attach();
    let reset = pcr_reset(21);

    // The payload is four octets with the locality in the first.
    assert_eq!(s.result(request::SET_LOCALITY, &[0, 0, 0, 0]), 0);
    let at_zero = response_code(&s.command(&reset));

    assert_eq!(s.result(request::SET_LOCALITY, &[2, 0, 0, 0]), 0);
    let at_two = response_code(&s.command(&reset));

    assert_eq!(at_zero, rc::LOCALITY, "locality zero may not reset a TCB register");
    assert_eq!(at_two, rc::SUCCESS, "locality two may reset a TCB register");
    s.finish();
}

/// A locality the specification does not define is refused, and the refusal
/// leaves the channel usable.
#[test]
fn a_locality_above_four_is_refused_without_breaking_the_channel() {
    let mut s = Server::start("badlocality");
    assert_eq!(s.result(request::SET_LOCALITY, &[5, 0, 0, 0]), rc::LOCALITY);
    // The next reply must still line up, which is only true if the refusal
    // wrote exactly one word and nothing more.
    assert_eq!(s.result(request::GET_CAPABILITY, &[]), 0);
    assert_eq!(
        u32::from_be_bytes(s.rest(4).try_into().unwrap()),
        CAPABILITIES
    );
    s.finish();
}

/// The three octets after a locality are padding the caller does not always
/// clear, so they must be ignored rather than read as part of the value.
#[test]
fn the_padding_after_a_locality_is_ignored() {
    let mut s = Server::start("padding");
    assert_eq!(s.result(request::SET_LOCALITY, &[2, 0xff, 0xff, 0xff]), 0);
    assert_eq!(s.result(request::GET_CAPABILITY, &[]), 0);
    let _ = s.rest(4);
    // The same holds for clearing the establishment flag, whose payload the
    // caller builds without clearing it first.
    assert_eq!(
        s.result(request::RESET_ESTABLISHED, &[0, 0xde, 0xad, 0xbe]),
        0
    );
    assert_eq!(s.result(request::GET_CAPABILITY, &[]), 0);
    let _ = s.rest(4);
    s.finish();
}

/// Stopping and initialising again is what a guest reset looks like.
#[test]
fn the_tpm_can_be_stopped_and_brought_up_again() {
    let mut s = Server::start("restart");
    s.attach();

    assert_eq!(s.result(request::STOP, &[]), 0);
    // With power removed the TPM reports that it is not initialised.
    let out = s.command(&bare_command(cc::ReadClock));
    assert_eq!(response_code(&out), rc::INITIALIZE);

    s.attach();
    let out = s.command(&bare_command(cc::ReadClock));
    assert_eq!(response_code(&out), rc::SUCCESS);
    s.finish();
}

/// What the TPM reports about itself is the same after a stop and a fresh
/// initialise, so the state file is being reloaded rather than remade.
#[test]
fn state_survives_a_stop_and_initialise() {
    let mut s = Server::start("persist");
    s.attach();
    let before = s.command(&manufacturer_query());
    assert_eq!(response_code(&before), rc::SUCCESS);

    assert_eq!(s.result(request::STOP, &[]), 0);
    s.attach();
    let after = s.command(&manufacturer_query());
    assert_eq!(before, after);
    s.finish();
}

/// Shutting down on the control channel makes the whole transport return.
#[test]
fn shutdown_returns_from_serve() {
    Server::start("shutdown").finish();
}
