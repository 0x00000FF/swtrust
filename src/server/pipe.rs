//! Windows named pipe transport.
//!
//! The pipe carries bare TPM command and response buffers. A command is framed
//! by its own header: octets 2 through 5 hold `commandSize`, which covers the
//! whole command including the header. The response is written back the same
//! way, framed by the `responseSize` field.

use std::io;
use std::sync::Arc;

use crate::cli::Config;
use crate::logging::Logger;
use crate::server::Device;

/// Smallest well formed command: tag, commandSize and commandCode.
pub const HEADER_SIZE: usize = 10;
/// Octets needed before `commandSize` can be read.
pub const SIZE_FIELD_END: usize = 6;

/// Largest command accepted from a client.
///
/// The TPM itself rejects anything above `config::MAX_COMMAND_SIZE`. This
/// larger bound is what the transport is willing to read into memory before
/// handing the buffer over, so a bad length cannot cause a large allocation.
pub const MAX_COMMAND: u32 = 64 * 1024;

/// Largest number of pipe clients served at once.
pub const MAX_CONNECTIONS: usize = 64;

/// Read the `commandSize` field out of a partial header.
pub fn command_size(prefix: &[u8]) -> io::Result<u32> {
    if prefix.len() < SIZE_FIELD_END {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "command header is too short",
        ));
    }
    let size = u32::from_be_bytes([prefix[2], prefix[3], prefix[4], prefix[5]]);
    if (size as usize) < HEADER_SIZE || size > MAX_COMMAND {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("commandSize {size} is out of range"),
        ));
    }
    Ok(size)
}

/// Read one complete command buffer from `r`.
///
/// Returns `None` when the peer closed the connection before sending anything.
pub fn read_command<R: io::Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; SIZE_FIELD_END];
    let mut filled = 0;
    while filled < SIZE_FIELD_END {
        match r.read(&mut head[filled..])? {
            0 if filled == 0 => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated command header",
                ))
            }
            n => filled += n,
        }
    }
    let size = command_size(&head)? as usize;
    let mut buf = Vec::with_capacity(size);
    buf.extend_from_slice(&head);
    buf.resize(size, 0);
    r.read_exact(&mut buf[SIZE_FIELD_END..])?;
    Ok(Some(buf))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    const BUFFER_SIZE: u32 = 64 * 1024;

    /// An accepted named pipe connection.
    pub struct PipeStream {
        handle: HANDLE,
    }

    // The handle is owned exclusively by this value and every use goes through
    // a blocking call, so it is safe to move between threads.
    unsafe impl Send for PipeStream {}

    impl PipeStream {
        fn new(handle: HANDLE) -> PipeStream {
            PipeStream { handle }
        }
    }

    impl io::Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut read: u32 = 0;
            let len = buf.len().min(u32::MAX as usize) as u32;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr(),
                    len,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let code = unsafe { GetLastError() };
                // A closing client shows up as a broken pipe, which is a clean
                // end of stream for us.
                const ERROR_BROKEN_PIPE: u32 = 109;
                if code == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            Ok(read as usize)
        }
    }

    impl io::Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut written: u32 = 0;
            let len = buf.len().min(u32::MAX as usize) as u32;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr(),
                    len,
                    &mut written,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
            }
            Ok(written as usize)
        }

        /// Nothing is buffered on this side, so there is nothing to flush.
        ///
        /// `FlushFileBuffers` on a pipe server blocks until the client has read
        /// everything already written, which lets a client that stops reading
        /// stall the TPM. `WriteFile` has already handed the octets to the
        /// pipe, so the flush would buy nothing.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for PipeStream {
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.handle);
                CloseHandle(self.handle);
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// Create one pipe instance and wait for a client.
    fn accept(name: &str) -> io::Result<PipeStream> {
        let wide_name = wide(name);
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
        }
        let stream = PipeStream::new(handle);
        let connected = unsafe { ConnectNamedPipe(handle, ptr::null_mut()) };
        if connected == 0 {
            let code = unsafe { GetLastError() };
            // A client that connected between CreateNamedPipeW and
            // ConnectNamedPipe is already attached.
            if code != ERROR_PIPE_CONNECTED {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        Ok(stream)
    }

    pub fn serve<D: Device + 'static>(
        config: &Config,
        device: Arc<D>,
        logger: Arc<Logger>,
    ) -> io::Result<()> {
        logger.line(&format!("listening pipe={}", config.pipe_name));
        // The pipe carries no platform signals, so power is applied as soon as
        // the daemon starts.
        device.power_on();

        let connections = AtomicU64::new(0);
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let stream = accept(&config.pipe_name)?;
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                logger.line(&format!(
                    "refused pipe client, {MAX_CONNECTIONS} already active"
                ));
                drop(stream);
                continue;
            }
            let id = connections.fetch_add(1, Ordering::SeqCst) + 1;
            let device = device.clone();
            let connection_logger = logger.clone();
            let connection_active = active.clone();
            let spawned = thread::Builder::new()
                .name(format!("swtrust-pipe-{id}"))
                .spawn(move || {
                    let logger = connection_logger;
                    logger.line(&format!("conn={id} open pipe"));
                    if let Err(e) = super::serve_connection(stream, &*device, &logger, id) {
                        if e.kind() != io::ErrorKind::UnexpectedEof {
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
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn serve<D: Device + 'static>(
        _config: &Config,
        _device: Arc<D>,
        _logger: Arc<Logger>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the named pipe interface is only available on Windows",
        ))
    }
}

pub use imp::serve;

/// Serve one connection: read commands, execute them, write responses.
///
/// The locality of a pipe client is always zero because the transport carries
/// no locality field.
pub fn serve_connection<S, D>(stream: S, device: &D, logger: &Logger, id: u64) -> io::Result<()>
where
    S: io::Read + io::Write,
    D: Device + ?Sized,
{
    let mut stream = stream;
    loop {
        let command = match read_command(&mut stream)? {
            Some(c) => c,
            None => return Ok(()),
        };
        logger.command(id, 0, &command);
        let response = device.execute(0, &command);
        logger.response(id, &response);
        stream.write_all(&response)?;
        stream.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_size_is_read_from_the_header() {
        let head = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c];
        assert_eq!(command_size(&head).unwrap(), 12);
    }

    #[test]
    fn command_size_rejects_short_and_huge_values() {
        assert_eq!(
            command_size(&[0x80, 0x01, 0x00, 0x00, 0x00, 0x09])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            command_size(&[0x80, 0x01, 0xff, 0xff, 0xff, 0xff])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            command_size(&[0x80, 0x01]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn reads_a_framed_command() {
        let command = [
            0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let mut cur = io::Cursor::new(command.to_vec());
        let got = read_command(&mut cur).unwrap().unwrap();
        assert_eq!(got, command);
        assert_eq!(read_command(&mut cur).unwrap(), None);
    }

    #[test]
    fn reads_back_to_back_commands() {
        let one = [
            0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let two = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7b];
        let mut data = one.to_vec();
        data.extend_from_slice(&two);
        let mut cur = io::Cursor::new(data);
        assert_eq!(read_command(&mut cur).unwrap().unwrap(), one);
        assert_eq!(read_command(&mut cur).unwrap().unwrap(), two);
        assert_eq!(read_command(&mut cur).unwrap(), None);
    }

    #[test]
    fn truncated_body_is_an_error() {
        let data = vec![0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00];
        let mut cur = io::Cursor::new(data);
        assert_eq!(
            read_command(&mut cur).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn truncated_header_is_an_error() {
        let mut cur = io::Cursor::new(vec![0x80u8, 0x01]);
        assert_eq!(
            read_command(&mut cur).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
