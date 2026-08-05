//! TCP transport.
//!
//! Two listeners are opened: the command port carries TPM command buffers and
//! the platform port, always the command port plus one, carries the platform
//! signals. Each connection is served on its own thread.

use std::io::{self, BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::cli::Config;
use crate::logging::Logger;
use crate::server::simulator::{self as sim, op};
use crate::server::Device;

/// Largest number of connections served at once, across both ports.
///
/// A client that connects and then stalls holds a thread and its buffers, so
/// the count is capped and further connections are closed immediately.
pub const MAX_CONNECTIONS: usize = 64;

/// How long to wait when waking a blocked listener.
const WAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// Shared shutdown flag set by the TPM_STOP request.
///
/// Setting the flag is not enough on its own: both accept loops are blocked
/// inside `accept`, so requesting a shutdown also opens a throwaway connection
/// to every listener to wake it.
#[derive(Debug, Default)]
pub struct Shutdown {
    flag: AtomicBool,
    listeners: Mutex<Vec<SocketAddr>>,
}

impl Shutdown {
    /// Record a listener that must be woken when a shutdown is requested.
    pub fn register(&self, addr: SocketAddr) {
        if let Ok(mut l) = self.listeners.lock() {
            l.push(addr);
        }
    }

    pub fn requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Set the flag and wake every registered listener.
    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let addrs = match self.listeners.lock() {
            Ok(l) => l.clone(),
            Err(p) => p.into_inner().clone(),
        };
        for addr in addrs {
            let _ = TcpStream::connect_timeout(&addr, WAKE_TIMEOUT);
        }
    }
}

/// Serve both ports until a client sends TPM_STOP.
pub fn serve<D: Device + 'static>(
    config: &Config,
    device: Arc<D>,
    logger: Arc<Logger>,
) -> io::Result<()> {
    let command_addr = format!("{}:{}", config.address, config.port);
    let platform_addr = format!("{}:{}", config.address, config.port + 1);

    let command = TcpListener::bind(&command_addr)?;
    let platform = TcpListener::bind(&platform_addr)?;
    let command_local = command.local_addr()?;
    let platform_local = platform.local_addr()?;

    logger.line(&format!(
        "listening command={command_local} platform={platform_local}"
    ));

    let shutdown = Arc::new(Shutdown::default());
    shutdown.register(command_local);
    shutdown.register(platform_local);

    let connections = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));

    let platform_thread = {
        let device = device.clone();
        let logger = logger.clone();
        let shutdown = shutdown.clone();
        let connections = connections.clone();
        let active = active.clone();
        thread::spawn(move || {
            accept_loop(platform, device, logger, shutdown, connections, active, false);
        })
    };

    accept_loop(
        command,
        device,
        logger.clone(),
        shutdown.clone(),
        connections,
        active,
        true,
    );

    let _ = platform_thread.join();
    logger.line("stopped");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accept_loop<D: Device + 'static>(
    listener: TcpListener,
    device: Arc<D>,
    logger: Arc<Logger>,
    shutdown: Arc<Shutdown>,
    connections: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    is_command_port: bool,
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
        let connection_logger = logger.clone();
        let connection_shutdown = shutdown.clone();
        let connection_active = active.clone();
        let spawned = thread::Builder::new()
            .name(format!("swtrust-conn-{id}"))
            .spawn(move || {
                let logger = connection_logger;
                let shutdown = connection_shutdown;
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                logger.line(&format!(
                    "conn={id} open {} peer={peer}",
                    if is_command_port { "command" } else { "platform" }
                ));
                if let Err(e) = serve_connection(stream, &*device, &logger, &shutdown, id) {
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

/// Handle one connection. Both ports accept the same opcode set, matching the
/// reference simulator, so a single loop serves either.
fn serve_connection<D: Device + ?Sized>(
    stream: TcpStream,
    device: &D,
    logger: &Logger,
    shutdown: &Shutdown,
    id: u64,
) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    loop {
        let opcode = match sim::read_u32_opt(&mut reader)? {
            Some(v) => v,
            None => return Ok(()),
        };
        match opcode {
            op::SEND_COMMAND => {
                let locality = sim::read_u8(&mut reader)?;
                let command = sim::read_blob(&mut reader)?;
                logger.command(id, locality, &command);
                let response = device.execute(locality, &command);
                logger.response(id, &response);
                sim::write_blob(&mut writer, &response)?;
                sim::write_ack(&mut writer)?;
            }
            op::REMOTE_HANDSHAKE => {
                let _client_version = sim::read_u32(&mut reader)?;
                sim::write_u32(&mut writer, sim::SERVER_VERSION)?;
                sim::write_u32(&mut writer, sim::ENDPOINT_INFO)?;
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_POWER_ON => {
                device.power_on();
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_POWER_OFF => {
                device.power_off();
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_RESET | op::SIGNAL_RESTART => {
                device.power_off();
                device.power_on();
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_NV_ON => {
                device.nv_on();
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_NV_OFF => {
                device.nv_off();
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_PHYS_PRES_ON => {
                device.physical_presence(true);
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_PHYS_PRES_OFF => {
                device.physical_presence(false);
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_CANCEL_ON => {
                device.cancel(true);
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_CANCEL_OFF => {
                device.cancel(false);
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_HASH_START => {
                device.hash_start();
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_HASH_DATA => {
                let data = sim::read_blob(&mut reader)?;
                device.hash_data(&data);
                sim::write_ack(&mut writer)?;
            }
            op::SIGNAL_HASH_END => {
                device.hash_end();
                sim::write_ack(&mut writer)?;
            }
            op::ACT_GET_SIGNALED => {
                let act = sim::read_u32(&mut reader)?;
                sim::write_u32(&mut writer, u32::from(device.act_get_signaled(act)))?;
                sim::write_ack(&mut writer)?;
            }
            // Key caching and alternative results exist in the reference
            // simulator for test scaffolding. They are accepted and ignored.
            op::SIGNAL_KEY_CACHE_ON | op::SIGNAL_KEY_CACHE_OFF => {
                sim::write_ack(&mut writer)?;
            }
            op::SET_ALTERNATIVE_RESULT => {
                let _result = sim::read_u32(&mut reader)?;
                sim::write_ack(&mut writer)?;
            }
            op::TEST_FAILURE_MODE => {
                sim::write_ack(&mut writer)?;
            }
            op::GET_COMMAND_RESPONSE_SIZES => {
                // Reported as zero, matching a simulator built without the
                // command and response size instrumentation.
                sim::write_u32(&mut writer, 0)?;
                sim::write_u32(&mut writer, 0)?;
                sim::write_ack(&mut writer)?;
            }
            op::SESSION_END => {
                writer.flush()?;
                return Ok(());
            }
            op::STOP => {
                shutdown.request();
                sim::write_ack(&mut writer)?;
                writer.flush()?;
                return Ok(());
            }
            other => {
                logger.line(&format!("conn={id} unknown opcode {other}"));
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown opcode {other}"),
                ));
            }
        }
        writer.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeDevice {
        powered: AtomicBool,
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
            // A well formed success response with no parameters.
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
            self.log("hash_start");
        }
        fn hash_data(&self, data: &[u8]) {
            self.log(&format!("hash_data len={}", data.len()));
        }
        fn hash_end(&self) {
            self.log("hash_end");
        }
        fn established(&self) -> bool {
            false
        }
        fn reset_established(&self, locality: u8) {
            self.log(&format!("reset_established loc={locality}"));
        }
        fn act_get_signaled(&self, act: u32) -> bool {
            act == 0
        }
    }

    fn logger() -> Logger {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "swtrust-sock-{}-{}",
            std::process::id(),
            crate::util::time::unix_millis_now()
        ));
        Logger::new(dir, false).unwrap()
    }

    /// Drive `serve_connection` over a loopback socket pair.
    fn exchange(request: &[u8], device: &FakeDevice) -> Vec<u8> {
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
        serve_connection(server, device, &log, &shutdown, 1).unwrap();
        client.join().unwrap()
    }

    #[test]
    fn handshake_reports_version_and_endpoint_info() {
        let device = FakeDevice::default();
        let mut req = Vec::new();
        sim::write_u32(&mut req, op::REMOTE_HANDSHAKE).unwrap();
        sim::write_u32(&mut req, 1).unwrap();
        let out = exchange(&req, &device);
        assert_eq!(out.len(), 12);
        assert_eq!(&out[0..4], &sim::SERVER_VERSION.to_be_bytes());
        assert_eq!(&out[4..8], &sim::ENDPOINT_INFO.to_be_bytes());
        assert_eq!(&out[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn send_command_returns_response_then_ack() {
        let device = FakeDevice::default();
        let command = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];
        let mut req = Vec::new();
        sim::write_u32(&mut req, op::SEND_COMMAND).unwrap();
        req.push(3); // locality
        sim::write_blob(&mut req, &command).unwrap();
        let out = exchange(&req, &device);
        assert_eq!(&out[0..4], &10u32.to_be_bytes());
        assert_eq!(&out[4..14], &[0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0, 0]);
        assert_eq!(&out[14..18], &[0, 0, 0, 0]);
        assert_eq!(device.events(), vec!["execute loc=3 len=12"]);
    }

    #[test]
    fn platform_signals_are_acknowledged() {
        let device = FakeDevice::default();
        let mut req = Vec::new();
        for opcode in [
            op::SIGNAL_POWER_ON,
            op::SIGNAL_NV_ON,
            op::SIGNAL_PHYS_PRES_ON,
            op::SIGNAL_PHYS_PRES_OFF,
            op::SIGNAL_CANCEL_ON,
            op::SIGNAL_CANCEL_OFF,
            op::SIGNAL_HASH_START,
            op::SIGNAL_HASH_END,
            op::SIGNAL_NV_OFF,
            op::SIGNAL_POWER_OFF,
        ] {
            sim::write_u32(&mut req, opcode).unwrap();
        }
        let out = exchange(&req, &device);
        assert_eq!(out.len(), 40);
        assert!(out.iter().all(|b| *b == 0));
        assert_eq!(
            device.events(),
            vec![
                "power_on",
                "nv_on",
                "pp=true",
                "pp=false",
                "cancel=true",
                "cancel=false",
                "hash_start",
                "hash_end",
                "nv_off",
                "power_off",
            ]
        );
    }

    #[test]
    fn hash_data_carries_a_blob() {
        let device = FakeDevice::default();
        let mut req = Vec::new();
        sim::write_u32(&mut req, op::SIGNAL_HASH_DATA).unwrap();
        sim::write_blob(&mut req, &[1, 2, 3, 4]).unwrap();
        let out = exchange(&req, &device);
        assert_eq!(out, vec![0, 0, 0, 0]);
        assert_eq!(device.events(), vec!["hash_data len=4"]);
    }

    #[test]
    fn act_signaled_is_reported() {
        let device = FakeDevice::default();
        let mut req = Vec::new();
        sim::write_u32(&mut req, op::ACT_GET_SIGNALED).unwrap();
        sim::write_u32(&mut req, 0).unwrap();
        sim::write_u32(&mut req, op::ACT_GET_SIGNALED).unwrap();
        sim::write_u32(&mut req, 1).unwrap();
        let out = exchange(&req, &device);
        assert_eq!(&out[0..4], &1u32.to_be_bytes());
        assert_eq!(&out[4..8], &[0, 0, 0, 0]);
        assert_eq!(&out[8..12], &0u32.to_be_bytes());
        assert_eq!(&out[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn stop_sets_the_shutdown_flag() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let mut req = Vec::new();
            sim::write_u32(&mut req, op::STOP).unwrap();
            s.write_all(&req).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            out
        });
        let (server, _) = listener.accept().unwrap();
        let device = FakeDevice::default();
        let log = logger();
        let shutdown = Shutdown::default();
        serve_connection(server, &device, &log, &shutdown, 1).unwrap();
        assert!(shutdown.requested());
        assert_eq!(client.join().unwrap(), vec![0, 0, 0, 0]);
    }

    /// Find a port such that it and the next one are both free.
    fn free_port_pair() -> u16 {
        for _ in 0..64 {
            let Ok(a) = TcpListener::bind("127.0.0.1:0") else {
                continue;
            };
            let port = a.local_addr().unwrap().port();
            if port == u16::MAX {
                continue;
            }
            let Ok(b) = TcpListener::bind(("127.0.0.1", port + 1)) else {
                continue;
            };
            drop(a);
            drop(b);
            return port;
        }
        panic!("no free port pair");
    }

    #[test]
    fn stop_makes_serve_return() {
        let port = free_port_pair();
        let mut config = crate::cli::Config {
            port,
            ..Default::default()
        };
        let mut log_dir = std::env::temp_dir();
        log_dir.push(format!(
            "swtrust-serve-{}-{}",
            std::process::id(),
            crate::util::time::unix_millis_now()
        ));
        config.log_dir = log_dir.clone();

        let device = Arc::new(FakeDevice::default());
        let logger = Arc::new(Logger::new(&log_dir, false).unwrap());
        let served = {
            let device = device.clone();
            thread::spawn(move || serve(&config, device, logger))
        };

        // Wait for both listeners to come up, then ask the TPM to stop.
        // Two seconds is not always enough on a loaded machine, and the point
        // of the test is what serve() does once the listener is up.
        let mut client = None;
        for _ in 0..3000 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                client = Some(s);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut client = client.expect("command port never accepted a connection");
        let mut req = Vec::new();
        sim::write_u32(&mut req, op::STOP).unwrap();
        client.write_all(&req).unwrap();
        let mut ack = [0u8; 4];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [0, 0, 0, 0]);
        drop(client);

        // serve() must return rather than stay blocked in accept().
        for _ in 0..500 {
            if served.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(served.is_finished(), "serve did not return after TPM_STOP");
        served.join().unwrap().unwrap();
        std::fs::remove_dir_all(&log_dir).ok();
    }

    #[test]
    fn unknown_opcode_closes_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let mut req = Vec::new();
            sim::write_u32(&mut req, 999).unwrap();
            s.write_all(&req).unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
        });
        let (server, _) = listener.accept().unwrap();
        let device = FakeDevice::default();
        let log = logger();
        let shutdown = Shutdown::default();
        let e = serve_connection(server, &device, &log, &shutdown, 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        client.join().unwrap();
    }
}
