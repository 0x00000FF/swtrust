//! Transport for a virtual machine monitor that drives an external TPM.
//!
//! QEMU talks to an external TPM over two stream connections rather than one.
//! A control channel carries the platform requests that have no command form:
//! initialise, stop, set the locality, read and clear the establishment flag,
//! and agree a buffer size. A data channel carries bare TPM command and
//! response buffers, exactly as the named pipe interface does.
//!
//! The data channel is the command port and the control channel is the command
//! port plus one, which is the pairing the published examples for this protocol
//! use, and which matches the convention the socket interface already follows.
//!
//! Every control request is a UINT32 request number followed by a payload whose
//! length is fixed for that request. Every reply begins with a UINT32 result.
//! All integers are big endian.
//!
//! A reply carries its remaining fields **only when the result is zero**. The
//! caller reads the result first and stops there when it is not zero, so any
//! further octets would be read as the beginning of the next reply and the
//! channel would lose its framing. Each arm below is written to respect that.

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use crate::cli::Config;
use crate::logging::Logger;
use crate::server::simulator as sim;
use crate::server::socket::{Shutdown, MAX_CONNECTIONS};
use crate::server::Device;
use crate::tpm::config;
use crate::tpm::constants::rc;
use crate::tpm::device::HEADER_SIZE;

/// Control request numbers.
pub mod request {
    pub const GET_CAPABILITY: u32 = 1;
    pub const INIT: u32 = 2;
    pub const SHUTDOWN: u32 = 3;
    pub const GET_ESTABLISHED: u32 = 4;
    pub const SET_LOCALITY: u32 = 5;
    pub const HASH_START: u32 = 6;
    pub const HASH_DATA: u32 = 7;
    pub const HASH_END: u32 = 8;
    pub const CANCEL: u32 = 9;
    pub const STORE_VOLATILE: u32 = 10;
    pub const RESET_ESTABLISHED: u32 = 11;
    pub const GET_STATEBLOB: u32 = 12;
    pub const SET_STATEBLOB: u32 = 13;
    pub const STOP: u32 = 14;
    pub const GET_CONFIG: u32 = 15;
    pub const SET_DATAFD: u32 = 16;
    pub const SET_BUFFERSIZE: u32 = 17;
    pub const GET_INFO: u32 = 18;
    pub const LOCK_STORAGE: u32 = 19;
}

/// Bits reported by the capability request.
pub mod cap {
    pub const INIT: u32 = 1;
    pub const SHUTDOWN: u32 = 1 << 1;
    pub const GET_ESTABLISHED: u32 = 1 << 2;
    pub const SET_LOCALITY: u32 = 1 << 3;
    pub const HASHING: u32 = 1 << 4;
    pub const CANCEL: u32 = 1 << 5;
    pub const STORE_VOLATILE: u32 = 1 << 6;
    pub const RESET_ESTABLISHED: u32 = 1 << 7;
    pub const GET_STATEBLOB: u32 = 1 << 8;
    pub const SET_STATEBLOB: u32 = 1 << 9;
    pub const STOP: u32 = 1 << 10;
    pub const GET_CONFIG: u32 = 1 << 11;
    pub const SET_DATAFD: u32 = 1 << 12;
    pub const SET_BUFFERSIZE: u32 = 1 << 13;
    pub const GET_INFO: u32 = 1 << 14;
    pub const SEND_COMMAND_HEADER: u32 = 1 << 15;
    pub const LOCK_STORAGE: u32 = 1 << 16;
}

/// What this transport answers to a capability request.
///
/// Only what is actually done is claimed. Two omissions are deliberate:
///
/// * The request that passes an already connected data channel as a descriptor
///   is not offered. This transport is given its data channel directly, so
///   there is no descriptor to pass and nothing for that request to do.
/// * Cancelling a running command is not offered. A command here runs to
///   completion while holding the TPM lock and nothing samples a cancel signal
///   part way through, so claiming the capability would promise an effect that
///   would never happen.
///
/// The state blob requests are likewise absent, which is how a caller is told
/// that the virtual machine cannot be migrated while this TPM is attached.
pub const CAPABILITIES: u32 = cap::INIT
    | cap::SHUTDOWN
    | cap::GET_ESTABLISHED
    | cap::SET_LOCALITY
    | cap::HASHING
    | cap::RESET_ESTABLISHED
    | cap::STOP
    | cap::SET_BUFFERSIZE;

/// Smallest command and response buffer that will be agreed.
pub const MIN_BUFFER_SIZE: u32 = 1024;
/// Largest command and response buffer that will be agreed.
pub const MAX_BUFFER_SIZE: u32 = config::MAX_RESPONSE_SIZE;

/// Highest locality a platform may select, Part 1 clause 11.4.6.
const MAX_LOCALITY: u8 = 4;

/// State the two channels share.
///
/// The locality is chosen on the control channel and applies to every command
/// that arrives on the data channel until it is chosen again.
#[derive(Debug)]
pub struct Link {
    locality: AtomicU8,
    buffer_size: AtomicU32,
}

impl Default for Link {
    fn default() -> Self {
        Link {
            locality: AtomicU8::new(0),
            buffer_size: AtomicU32::new(MAX_BUFFER_SIZE),
        }
    }
}

impl Link {
    pub fn locality(&self) -> u8 {
        self.locality.load(Ordering::SeqCst)
    }

    pub fn buffer_size(&self) -> u32 {
        self.buffer_size.load(Ordering::SeqCst)
    }

    /// Agree a buffer size. A request of zero asks what is in use without
    /// changing it; anything else is held to the supported range.
    ///
    /// The caller compares what it asked for against what is returned and
    /// refuses to continue if they differ, so a request outside the range is
    /// answered honestly with the nearest supported size rather than accepted.
    pub fn agree_buffer_size(&self, wanted: u32) -> u32 {
        if wanted == 0 {
            return self.buffer_size();
        }
        let size = wanted.clamp(MIN_BUFFER_SIZE, MAX_BUFFER_SIZE);
        self.buffer_size.store(size, Ordering::SeqCst);
        size
    }
}

/// Serve both channels until the caller asks the TPM to shut down.
pub fn serve<D: Device + 'static>(
    config: &Config,
    device: Arc<D>,
    logger: Arc<Logger>,
) -> io::Result<()> {
    let data_addr = format!("{}:{}", config.address, config.port);
    let control_addr = format!("{}:{}", config.address, config.port + 1);

    let data = TcpListener::bind(&data_addr)?;
    let control = TcpListener::bind(&control_addr)?;
    let data_local = data.local_addr()?;
    let control_local = control.local_addr()?;

    logger.line(&format!(
        "listening data={data_local} control={control_local}"
    ));

    let shutdown = Arc::new(Shutdown::default());
    shutdown.register(data_local);
    shutdown.register(control_local);

    let link = Arc::new(Link::default());
    let connections = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));

    let control_thread = {
        let device = device.clone();
        let logger = logger.clone();
        let shutdown = shutdown.clone();
        let link = link.clone();
        let connections = connections.clone();
        let active = active.clone();
        thread::spawn(move || {
            accept_loop(
                control,
                device,
                link,
                logger,
                shutdown,
                connections,
                active,
                Channel::Control,
            );
        })
    };

    accept_loop(
        data,
        device,
        link,
        logger.clone(),
        shutdown,
        connections,
        active,
        Channel::Data,
    );

    let _ = control_thread.join();
    logger.line("stopped");
    Ok(())
}

/// Which of the two channels a connection belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    Control,
    Data,
}

impl Channel {
    fn name(self) -> &'static str {
        match self {
            Channel::Control => "control",
            Channel::Data => "data",
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_loop<D: Device + 'static>(
    listener: TcpListener,
    device: Arc<D>,
    link: Arc<Link>,
    logger: Arc<Logger>,
    shutdown: Arc<Shutdown>,
    connections: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    channel: Channel,
) {
    for stream in listener.incoming() {
        if shutdown.requested() {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                logger.line(&format!("accept failed: {e}"));
                continue;
            }
        };
        // Reserve a slot, and give it straight back if the TPM is already
        // serving as many connections as it will.
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            logger.line(&format!(
                "refused connection, {MAX_CONNECTIONS} already active"
            ));
            drop(stream);
            continue;
        }
        let id = connections.fetch_add(1, Ordering::SeqCst) + 1;
        let device = device.clone();
        let link = link.clone();
        let connection_logger = logger.clone();
        let connection_shutdown = shutdown.clone();
        let connection_active = active.clone();
        let spawned = thread::Builder::new()
            .name(format!("swtrust-qemu-{id}"))
            .spawn(move || {
                let logger = connection_logger;
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                logger.line(&format!("conn={id} open {} peer={peer}", channel.name()));
                let served = match channel {
                    Channel::Control => serve_control(
                        stream,
                        &*device,
                        &link,
                        &logger,
                        &connection_shutdown,
                        id,
                    ),
                    Channel::Data => serve_data(stream, &*device, &link, &logger, id),
                };
                if let Err(e) = served {
                    if e.kind() != io::ErrorKind::UnexpectedEof
                        && e.kind() != io::ErrorKind::ConnectionReset
                        && e.kind() != io::ErrorKind::ConnectionAborted
                    {
                        logger.line(&format!("conn={id} error: {e}"));
                    }
                }
                logger.line(&format!("conn={id} closed"));
                connection_active.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            active.fetch_sub(1, Ordering::SeqCst);
            logger.line(&format!("conn={id} cannot start a thread: {e}"));
        }
        if shutdown.requested() {
            break;
        }
    }
}

/// Take the locality out of a four octet payload.
///
/// The locality is the first octet on the wire. The three that follow are
/// padding to the width of a result and are not always cleared by the caller,
/// so they are ignored rather than checked.
fn locality_of(payload: u32) -> u8 {
    (payload >> 24) as u8
}

/// Handle the control channel.
fn serve_control<D: Device + ?Sized>(
    stream: TcpStream,
    device: &D,
    link: &Link,
    logger: &Logger,
    shutdown: &Shutdown,
    id: u64,
) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    loop {
        let request = match sim::read_u32_opt(&mut reader)? {
            Some(v) => v,
            None => return Ok(()),
        };
        match request {
            request::GET_CAPABILITY => {
                sim::write_u32(&mut writer, rc::SUCCESS)?;
                sim::write_u32(&mut writer, CAPABILITIES)?;
            }
            request::INIT => {
                // The payload is a flag word asking for the volatile state file
                // to be dropped after it is read. This TPM keeps one state file
                // and reloads it when it starts, so there is nothing to drop.
                let _flags = sim::read_u32(&mut reader)?;
                device.power_on();
                device.nv_on();
                logger.line(&format!("conn={id} init"));
                sim::write_u32(&mut writer, rc::SUCCESS)?;
            }
            request::STOP => {
                device.power_off();
                logger.line(&format!("conn={id} stop"));
                sim::write_u32(&mut writer, rc::SUCCESS)?;
            }
            request::SHUTDOWN => {
                device.power_off();
                logger.line(&format!("conn={id} shutdown"));
                sim::write_u32(&mut writer, rc::SUCCESS)?;
                writer.flush()?;
                shutdown.request();
                return Ok(());
            }
            request::GET_ESTABLISHED => {
                // The caller reads this reply in one go, so both fields are
                // always written whatever the result is.
                sim::write_u32(&mut writer, rc::SUCCESS)?;
                writer.write_all(&[u8::from(device.established()), 0, 0, 0])?;
            }
            request::RESET_ESTABLISHED => {
                let locality = locality_of(sim::read_u32(&mut reader)?);
                if locality > MAX_LOCALITY {
                    sim::write_u32(&mut writer, rc::LOCALITY)?;
                } else {
                    device.reset_established(locality);
                    sim::write_u32(&mut writer, rc::SUCCESS)?;
                }
            }
            request::SET_LOCALITY => {
                let locality = locality_of(sim::read_u32(&mut reader)?);
                if locality > MAX_LOCALITY {
                    sim::write_u32(&mut writer, rc::LOCALITY)?;
                } else {
                    link.locality.store(locality, Ordering::SeqCst);
                    sim::write_u32(&mut writer, rc::SUCCESS)?;
                }
            }
            request::SET_BUFFERSIZE => {
                let wanted = sim::read_u32(&mut reader)?;
                let size = link.agree_buffer_size(wanted);
                sim::write_u32(&mut writer, rc::SUCCESS)?;
                sim::write_u32(&mut writer, size)?;
                sim::write_u32(&mut writer, MIN_BUFFER_SIZE)?;
                sim::write_u32(&mut writer, MAX_BUFFER_SIZE)?;
            }
            request::HASH_START => {
                device.hash_start();
                sim::write_u32(&mut writer, rc::SUCCESS)?;
            }
            request::HASH_DATA => {
                let data = sim::read_blob(&mut reader)?;
                device.hash_data(&data);
                sim::write_u32(&mut writer, rc::SUCCESS)?;
            }
            request::HASH_END => {
                device.hash_end();
                sim::write_u32(&mut writer, rc::SUCCESS)?;
            }
            // A request whose payload length is not known cannot be skipped
            // without losing the framing of everything after it, so the channel
            // is closed instead. Nothing that is not claimed in CAPABILITIES is
            // expected to arrive here.
            other => {
                logger.line(&format!("conn={id} unknown control request {other}"));
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown control request {other}"),
                ));
            }
        }
        writer.flush()?;
    }
}

/// Fill `buf`, reporting a clean end of stream before the first octet.
fn read_exact_opt<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated command header",
                ))
            }
            n => filled += n,
        }
    }
    Ok(true)
}

/// Handle the data channel, which carries bare command and response buffers.
fn serve_data<D: Device + ?Sized>(
    stream: TcpStream,
    device: &D,
    link: &Link,
    logger: &Logger,
    id: u64,
) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    loop {
        let mut header = [0u8; HEADER_SIZE];
        if !read_exact_opt(&mut reader, &mut header)? {
            return Ok(());
        }
        // The size in the header says how much more to read. It is checked here
        // only so far as is needed to read the rest of the buffer; whether it is
        // a size this TPM will accept is for the TPM itself to answer.
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
        if (size as usize) < HEADER_SIZE || size > sim::MAX_TRANSFER {
            logger.line(&format!("conn={id} command size {size} is not usable"));
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("command size {size} is not usable"),
            ));
        }
        let mut command = vec![0u8; size as usize];
        command[..HEADER_SIZE].copy_from_slice(&header);
        reader.read_exact(&mut command[HEADER_SIZE..])?;

        let locality = link.locality();
        logger.command(id, locality, &command);
        let response = device.execute(locality, &command);
        logger.response(id, &response);

        // The caller refuses a response larger than the size it agreed and
        // drops the connection, so a response that would do that is worth a
        // line in the log to explain what happened.
        let agreed = link.buffer_size() as usize;
        if response.len() > agreed {
            logger.line(&format!(
                "conn={id} response of {} octets is above the agreed buffer of {agreed}",
                response.len()
            ));
        }

        writer.write_all(&response)?;
        writer.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeDevice {
        powered: AtomicBool,
        established: AtomicBool,
        events: Mutex<Vec<String>>,
    }

    impl FakeDevice {
        fn log(&self, s: &str) {
            self.events.lock().unwrap().push(s.to_string());
        }
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    impl Device for FakeDevice {
        fn execute(&self, locality: u8, command: &[u8]) -> Vec<u8> {
            self.log(&format!("execute loc={locality} len={}", command.len()));
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        }
        fn power_on(&self) {
            self.powered.store(true, Ordering::SeqCst);
            self.log("power_on");
        }
        fn power_off(&self) {
            self.powered.store(false, Ordering::SeqCst);
            self.log("power_off");
        }
        fn is_powered_on(&self) -> bool {
            self.powered.load(Ordering::SeqCst)
        }
        fn nv_on(&self) {
            self.log("nv_on");
        }
        fn nv_off(&self) {
            self.log("nv_off");
        }
        fn physical_presence(&self, asserted: bool) {
            self.log(&format!("pp={asserted}"));
        }
        fn cancel(&self, asserted: bool) {
            self.log(&format!("cancel={asserted}"));
        }
        fn hash_start(&self) {
            self.established.store(true, Ordering::SeqCst);
            self.log("hash_start");
        }
        fn hash_data(&self, data: &[u8]) {
            self.log(&format!("hash_data len={}", data.len()));
        }
        fn hash_end(&self) {
            self.log("hash_end");
        }
        fn established(&self) -> bool {
            self.established.load(Ordering::SeqCst)
        }
        fn reset_established(&self, locality: u8) {
            self.established.store(false, Ordering::SeqCst);
            self.log(&format!("reset_established loc={locality}"));
        }
        fn act_get_signaled(&self, act: u32) -> bool {
            act == 0
        }
    }

    fn logger() -> Logger {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "swtrust-qemu-{}-{}",
            std::process::id(),
            crate::util::time::unix_millis_now()
        ));
        Logger::new(dir, false).unwrap()
    }

    /// Drive one of the channel handlers over a loopback connection.
    fn exchange(request: &[u8], device: &FakeDevice, link: &Link, channel: Channel) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let request = request.to_vec();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&request).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            out
        });
        let (server, _) = listener.accept().unwrap();
        let log = logger();
        let shutdown = Shutdown::default();
        match channel {
            Channel::Control => {
                serve_control(server, device, link, &log, &shutdown, 1).unwrap();
            }
            Channel::Data => {
                serve_data(server, device, link, &log, 1).unwrap();
            }
        }
        client.join().unwrap()
    }

    fn control(request: &[u8], device: &FakeDevice, link: &Link) -> Vec<u8> {
        exchange(request, device, link, Channel::Control)
    }

    /// A control request with no payload.
    fn bare(number: u32) -> Vec<u8> {
        number.to_be_bytes().to_vec()
    }

    /// A control request whose payload is a single word.
    fn with_word(number: u32, word: u32) -> Vec<u8> {
        let mut v = number.to_be_bytes().to_vec();
        v.extend_from_slice(&word.to_be_bytes());
        v
    }

    #[test]
    fn capabilities_claim_only_what_is_done() {
        let device = FakeDevice::default();
        let out = control(&bare(request::GET_CAPABILITY), &device, &Link::default());
        assert_eq!(out.len(), 8);
        assert_eq!(&out[0..4], &0u32.to_be_bytes());
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), CAPABILITIES);
    }

    #[test]
    fn the_required_capabilities_for_a_tpm_2_are_claimed() {
        // A caller refuses to attach unless all of these are present. The one
        // it also asks for, passing the data channel as a descriptor, is
        // meaningless when the data channel is given directly.
        for bit in [
            cap::INIT,
            cap::SHUTDOWN,
            cap::GET_ESTABLISHED,
            cap::SET_LOCALITY,
            cap::RESET_ESTABLISHED,
            cap::STOP,
            cap::SET_BUFFERSIZE,
        ] {
            assert_eq!(CAPABILITIES & bit, bit, "missing capability {bit:#x}");
        }
        assert_eq!(CAPABILITIES & cap::SET_DATAFD, 0);
        // Nothing is claimed about migration, which is how a caller learns it
        // must block migration rather than attempt it.
        assert_eq!(CAPABILITIES & cap::GET_STATEBLOB, 0);
        assert_eq!(CAPABILITIES & cap::SET_STATEBLOB, 0);
        // A command runs to completion, so cancelling is not claimed either.
        assert_eq!(CAPABILITIES & cap::CANCEL, 0);
    }

    #[test]
    fn init_powers_the_tpm_and_makes_storage_available() {
        let device = FakeDevice::default();
        let out = control(&with_word(request::INIT, 0), &device, &Link::default());
        assert_eq!(out, vec![0, 0, 0, 0]);
        assert_eq!(device.events(), vec!["power_on", "nv_on"]);
        assert!(device.is_powered_on());
    }

    #[test]
    fn stop_removes_power_without_ending_the_connection() {
        let device = FakeDevice::default();
        let mut req = with_word(request::INIT, 0);
        req.extend_from_slice(&bare(request::STOP));
        req.extend_from_slice(&bare(request::GET_CAPABILITY));
        let out = control(&req, &device, &Link::default());
        // Init, stop, then a capability reply that proves the channel is still
        // framed correctly after the stop.
        assert_eq!(&out[0..4], &0u32.to_be_bytes());
        assert_eq!(&out[4..8], &0u32.to_be_bytes());
        assert_eq!(out.len(), 16);
        assert!(!device.is_powered_on());
    }

    #[test]
    fn the_locality_chosen_on_the_control_channel_reaches_the_data_channel() {
        let device = FakeDevice::default();
        let link = Link::default();
        // The first octet of the payload is the locality; the rest is padding
        // the caller does not always clear, so it must not be looked at.
        let out = control(&with_word(request::SET_LOCALITY, 0x03_ff_ff_ff), &device, &link);
        assert_eq!(out, vec![0, 0, 0, 0]);
        assert_eq!(link.locality(), 3);

        let command = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];
        let out = exchange(&command, &device, &link, Channel::Data);
        assert_eq!(out, vec![0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0, 0]);
        assert!(device.events().contains(&"execute loc=3 len=12".to_string()));
    }

    #[test]
    fn a_locality_above_four_is_refused() {
        let device = FakeDevice::default();
        let link = Link::default();
        let out = control(&with_word(request::SET_LOCALITY, 0x05_00_00_00), &device, &link);
        assert_eq!(out, rc::LOCALITY.to_be_bytes().to_vec());
        // The refusal leaves the locality alone.
        assert_eq!(link.locality(), 0);
    }

    #[test]
    fn the_establishment_flag_is_reported_and_cleared() {
        let device = FakeDevice::default();
        let link = Link::default();

        let out = control(&bare(request::GET_ESTABLISHED), &device, &link);
        assert_eq!(out, vec![0, 0, 0, 0, 0, 0, 0, 0]);

        // Beginning an H-CRTM sequence sets it.
        let out = control(&bare(request::HASH_START), &device, &link);
        assert_eq!(out, vec![0, 0, 0, 0]);
        let out = control(&bare(request::GET_ESTABLISHED), &device, &link);
        assert_eq!(out, vec![0, 0, 0, 0, 1, 0, 0, 0]);

        // The reply is always eight octets, so the padding must be there.
        let out = control(&with_word(request::RESET_ESTABLISHED, 0x03_00_00_00), &device, &link);
        assert_eq!(out, vec![0, 0, 0, 0]);
        let out = control(&bare(request::GET_ESTABLISHED), &device, &link);
        assert_eq!(out, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_buffer_size_request_of_zero_asks_without_changing() {
        let device = FakeDevice::default();
        let link = Link::default();
        let out = control(&with_word(request::SET_BUFFERSIZE, 0), &device, &link);
        assert_eq!(out.len(), 16);
        assert_eq!(&out[0..4], &0u32.to_be_bytes());
        assert_eq!(&out[4..8], &MAX_BUFFER_SIZE.to_be_bytes());
        assert_eq!(&out[8..12], &MIN_BUFFER_SIZE.to_be_bytes());
        assert_eq!(&out[12..16], &MAX_BUFFER_SIZE.to_be_bytes());
        assert_eq!(link.buffer_size(), MAX_BUFFER_SIZE);
    }

    #[test]
    fn a_buffer_size_inside_the_range_is_agreed_exactly() {
        // A caller refuses to continue when what it asked for and what it is
        // given differ, so a supported size must come back unchanged.
        let device = FakeDevice::default();
        let link = Link::default();
        let out = control(&with_word(request::SET_BUFFERSIZE, 3968), &device, &link);
        assert_eq!(&out[4..8], &3968u32.to_be_bytes());
        assert_eq!(link.buffer_size(), 3968);
    }

    #[test]
    fn a_buffer_size_outside_the_range_is_answered_with_the_nearest() {
        let device = FakeDevice::default();
        let link = Link::default();
        let out = control(&with_word(request::SET_BUFFERSIZE, 65536), &device, &link);
        assert_eq!(&out[4..8], &MAX_BUFFER_SIZE.to_be_bytes());
        let out = control(&with_word(request::SET_BUFFERSIZE, 16), &device, &link);
        assert_eq!(&out[4..8], &MIN_BUFFER_SIZE.to_be_bytes());
    }

    #[test]
    fn hash_data_carries_a_counted_blob() {
        let device = FakeDevice::default();
        let mut req = bare(request::HASH_DATA);
        sim::write_blob(&mut req, &[1, 2, 3, 4]).unwrap();
        let out = control(&req, &device, &Link::default());
        assert_eq!(out, vec![0, 0, 0, 0]);
        assert_eq!(device.events(), vec!["hash_data len=4"]);
    }

    #[test]
    fn shutdown_sets_the_shutdown_flag() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&bare(request::SHUTDOWN)).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            out
        });
        let (server, _) = listener.accept().unwrap();
        let device = FakeDevice::default();
        let log = logger();
        let shutdown = Shutdown::default();
        serve_control(server, &device, &Link::default(), &log, &shutdown, 1).unwrap();
        assert!(shutdown.requested());
        assert_eq!(client.join().unwrap(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn an_unknown_control_request_closes_the_channel() {
        // Its payload length is unknown, so carrying on would lose the framing.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&bare(4242)).unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
        });
        let (server, _) = listener.accept().unwrap();
        let device = FakeDevice::default();
        let log = logger();
        let shutdown = Shutdown::default();
        let e = serve_control(server, &device, &Link::default(), &log, &shutdown, 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        client.join().unwrap();
    }

    #[test]
    fn several_commands_run_back_to_back_on_one_data_connection() {
        let device = FakeDevice::default();
        let link = Link::default();
        let command = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];
        let mut req = Vec::new();
        req.extend_from_slice(&command);
        req.extend_from_slice(&command);
        let out = exchange(&req, &device, &link, Channel::Data);
        assert_eq!(out.len(), 20);
        assert_eq!(&out[0..10], &out[10..20]);
    }

    #[test]
    fn a_command_size_below_a_header_is_refused() {
        let device = FakeDevice::default();
        let link = Link::default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let bad = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x44];
            s.write_all(&bad).unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
        });
        let (server, _) = listener.accept().unwrap();
        let log = logger();
        let e = serve_data(server, &device, &link, &log, 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        client.join().unwrap();
    }

    #[test]
    fn an_oversized_command_is_refused_without_allocating_for_it() {
        let device = FakeDevice::default();
        let link = Link::default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let mut bad = vec![0x80u8, 0x01];
            bad.extend_from_slice(&u32::MAX.to_be_bytes());
            bad.extend_from_slice(&[0x00, 0x00, 0x01, 0x44]);
            s.write_all(&bad).unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
        });
        let (server, _) = listener.accept().unwrap();
        let log = logger();
        let e = serve_data(server, &device, &link, &log, 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        client.join().unwrap();
    }

    #[test]
    fn a_clean_end_of_stream_on_the_data_channel_is_not_an_error() {
        let device = FakeDevice::default();
        let link = Link::default();
        let out = exchange(&[], &device, &link, Channel::Data);
        assert!(out.is_empty());
    }
}
