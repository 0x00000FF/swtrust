//! Command logging.
//!
//! Every command and response pair is appended to `<log-dir>/YYYY-MM-DD.log`.
//! The file rolls over when the UTC date changes. With `--verbose` the same
//! records are also written to stdout.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::util::hex;
use crate::util::time;

/// Appends records to a date stamped file and optionally to stdout.
pub struct Logger {
    inner: Mutex<Inner>,
    verbose: bool,
}

struct Inner {
    dir: PathBuf,
    /// Date string of the currently open file, empty when nothing is open.
    date: String,
    file: Option<File>,
}

impl Logger {
    /// Create a logger writing into `dir`. The directory is created if needed.
    pub fn new(dir: impl AsRef<Path>, verbose: bool) -> io::Result<Logger> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Logger {
            inner: Mutex::new(Inner {
                dir,
                date: String::new(),
                file: None,
            }),
            verbose,
        })
    }

    /// Path of the file that records for `date` are written to.
    pub fn path_for(dir: &Path, date: &str) -> PathBuf {
        dir.join(format!("{date}.log"))
    }

    /// Write a single line, prefixed with a timestamp.
    pub fn line(&self, message: &str) {
        let now = time::now();
        let record = format!("{} {}\n", now.timestamp_string(), message);
        if self.verbose {
            print!("{record}");
            let _ = io::stdout().flush();
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let date = now.date_string();
        if inner.file.is_none() || inner.date != date {
            let path = Self::path_for(&inner.dir, &date);
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => {
                    inner.file = Some(f);
                    inner.date = date;
                }
                Err(e) => {
                    // Logging must never take the TPM down. Report once per line
                    // on stderr and keep serving commands.
                    eprintln!("swtrust: cannot open log file {}: {e}", path.display());
                    inner.file = None;
                    inner.date.clear();
                    return;
                }
            }
        }
        if let Some(f) = inner.file.as_mut() {
            if let Err(e) = f.write_all(record.as_bytes()) {
                eprintln!("swtrust: cannot write log: {e}");
            }
        }
    }

    /// Log a received command buffer.
    pub fn command(&self, connection: u64, locality: u8, command: &[u8]) {
        self.line(&format!(
            "conn={connection} locality={locality} {} cmd  {}",
            describe(command),
            hex::encode(command)
        ));
    }

    /// Log the response buffer produced for a command.
    pub fn response(&self, connection: u64, response: &[u8]) {
        self.line(&format!(
            "conn={connection} {} rsp  {}",
            describe_response(response),
            hex::encode(response)
        ));
    }
}

/// Short human readable header summary for a command buffer.
fn describe(buf: &[u8]) -> String {
    if buf.len() < 10 {
        return "short".to_string();
    }
    let tag = u16::from_be_bytes([buf[0], buf[1]]);
    let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    let cc = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
    let name = crate::tpm::constants::cc_name(cc).unwrap_or("Unknown");
    format!("tag=0x{tag:04x} size={size} cc=0x{cc:08x}({name})")
}

/// Short human readable header summary for a response buffer.
fn describe_response(buf: &[u8]) -> String {
    if buf.len() < 10 {
        return "short".to_string();
    }
    let tag = u16::from_be_bytes([buf[0], buf[1]]);
    let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    let rc = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
    format!("tag=0x{tag:04x} size={size} rc=0x{rc:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "swtrust-log-{tag}-{}-{}",
            std::process::id(),
            time::unix_millis_now()
        ));
        p
    }

    #[test]
    fn writes_dated_file() {
        let dir = temp_dir("dated");
        let logger = Logger::new(&dir, false).unwrap();
        logger.line("hello");
        let date = time::now().date_string();
        let path = Logger::path_for(&dir, &date);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("hello"));
        assert!(text.starts_with(&date));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn logs_command_and_response() {
        let dir = temp_dir("cmdrsp");
        let logger = Logger::new(&dir, false).unwrap();
        // TPM2_Startup(TPM_SU_CLEAR)
        let cmd = [
            0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let rsp = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00];
        logger.command(1, 0, &cmd);
        logger.response(1, &rsp);
        let path = Logger::path_for(&dir, &time::now().date_string());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("cc=0x00000144(TPM2_Startup)"), "{text}");
        assert!(text.contains(&hex::encode(&cmd)), "{text}");
        assert!(text.contains("rc=0x00000000"), "{text}");
        assert!(text.contains(&hex::encode(&rsp)), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncated_buffers_do_not_panic() {
        let dir = temp_dir("short");
        let logger = Logger::new(&dir, false).unwrap();
        logger.command(1, 0, &[0x80]);
        logger.response(1, &[]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
