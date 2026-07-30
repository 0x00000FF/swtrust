//! Storage of the TPM non-volatile state as a hex text file.
//!
//! The state directory holds `tpm-state.hex`. The file is plain text so the
//! contents can be inspected and copied without special tooling. Writes go to a
//! temporary file that is then renamed over the old one, so an interrupted save
//! never leaves a half written state file behind.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::util::hex;

/// Name of the state file inside the state directory.
pub const STATE_FILE: &str = "tpm-state.hex";

/// First line of the file, identifying the format.
const HEADER: &str = "# swtrust TPM state v1";

/// Number of hex characters per line in the saved file.
const LINE_WIDTH: usize = 64;

/// Largest state file accepted, in octets of text.
///
/// The state is a bounded structure, so a much larger file is either corrupt or
/// hostile and is refused rather than read into memory.
pub const MAX_STATE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Distinguishes the temporary files of concurrent saves.
static SAVE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A hex text backed store for the non-volatile state.
#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// Open the store rooted at `dir`, creating the directory if needed.
    pub fn new(dir: impl AsRef<Path>) -> io::Result<StateStore> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(StateStore { dir })
    }

    /// Path of the state file.
    pub fn path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    /// Directory holding the state file.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Read the saved state, or `None` when no state has been written yet.
    ///
    /// The file must start with the format header, must not exceed
    /// [`MAX_STATE_FILE_BYTES`], and must decode as hex.
    pub fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let path = self.path();
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if meta.len() > MAX_STATE_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: state file is {} octets, the limit is {}",
                    path.display(),
                    meta.len(),
                    MAX_STATE_FILE_BYTES
                ),
            ));
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut lines = text.lines();
        match lines.next() {
            Some(first) if first.trim_end() == HEADER => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: missing the '{HEADER}' header", path.display()),
                ))
            }
        }
        let mut body = String::with_capacity(text.len());
        for line in lines {
            if line.trim_start().starts_with('#') {
                continue;
            }
            body.push_str(line);
        }
        match hex::decode(&body) {
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )),
        }
    }

    /// Write `data` as hex text, replacing any existing state.
    ///
    /// The new contents are written to a temporary file that is then renamed
    /// over the old one. `fs::rename` maps to MoveFileEx with
    /// MOVEFILE_REPLACE_EXISTING on Windows, so the previous state stays intact
    /// until the replacement is complete. The temporary name carries the
    /// process id and a counter so concurrent saves never share one.
    pub fn save(&self, data: &[u8]) -> io::Result<()> {
        let path = self.path();
        let serial = SAVE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!("{STATE_FILE}.{}.{serial}.tmp", std::process::id()));
        let mut text = String::with_capacity(HEADER.len() + data.len() * 2 + data.len() / 32 + 8);
        text.push_str(HEADER);
        text.push('\n');
        text.push_str(&hex::encode_wrapped(data, LINE_WIDTH));
        text.push('\n');
        if let Err(e) = fs::write(&tmp, text.as_bytes()) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Remove the state file, which returns the TPM to a manufactured state on
    /// the next start.
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(self.path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::time;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "swtrust-state-{tag}-{}-{}",
            std::process::id(),
            time::unix_millis_now()
        ));
        p
    }

    #[test]
    fn creates_directory_and_reports_no_state() {
        let dir = temp_dir("create");
        assert!(!dir.exists());
        let store = StateStore::new(&dir).unwrap();
        assert!(dir.exists());
        assert!(store.load().unwrap().is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn round_trip_is_hex_text() {
        let dir = temp_dir("roundtrip");
        let store = StateStore::new(&dir).unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        store.save(&data).unwrap();

        let text = fs::read_to_string(store.path()).unwrap();
        assert!(text.starts_with("# swtrust TPM state v1"));
        assert!(text.is_ascii());
        for line in text.lines().skip(1) {
            assert!(line.len() <= LINE_WIDTH);
            assert!(line.chars().all(|c| c.is_ascii_hexdigit()));
        }

        assert_eq!(store.load().unwrap().unwrap(), data);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_replaces_previous_state() {
        let dir = temp_dir("replace");
        let store = StateStore::new(&dir).unwrap();
        store.save(&[1, 2, 3]).unwrap();
        store.save(&[9]).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), vec![9]);
        // No temporary file is left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_saves_do_not_share_a_temporary_file() {
        let dir = temp_dir("concurrent");
        let store = StateStore::new(&dir).unwrap();
        let handles: Vec<_> = (0u8..8)
            .map(|i| {
                let store = store.clone();
                std::thread::spawn(move || store.save(&[i; 64]).unwrap())
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // Whichever save landed last, the file decodes and holds one of the
        // written values rather than a mixture.
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.len(), 64);
        assert!(loaded.iter().all(|b| *b == loaded[0]));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_header_is_rejected() {
        let dir = temp_dir("noheader");
        let store = StateStore::new(&dir).unwrap();
        fs::write(store.path(), "aabb\n").unwrap();
        let e = store.load().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("header"), "{e}");

        fs::write(store.path(), "# some other file\naabb\n").unwrap();
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_oversized_state_file_is_refused() {
        let dir = temp_dir("huge");
        let store = StateStore::new(&dir).unwrap();
        let mut text = String::from(HEADER);
        text.push('\n');
        text.push_str(&"ab".repeat((MAX_STATE_FILE_BYTES as usize / 2) + 8));
        fs::write(store.path(), text).unwrap();
        let e = store.load().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("limit"), "{e}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn comment_lines_after_the_header_are_ignored() {
        let dir = temp_dir("comments");
        let store = StateStore::new(&dir).unwrap();
        fs::write(
            store.path(),
            format!("{HEADER}\n# a note\ndead\n# another\nbeef\n"),
        )
        .unwrap();
        assert_eq!(
            store.load().unwrap().unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_state_round_trips() {
        let dir = temp_dir("empty");
        let store = StateStore::new(&dir).unwrap();
        store.save(&[]).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), Vec::<u8>::new());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_removes_state() {
        let dir = temp_dir("clear");
        let store = StateStore::new(&dir).unwrap();
        store.save(&[7, 7]).unwrap();
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        // Clearing twice is not an error.
        store.clear().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_state_is_reported() {
        let dir = temp_dir("corrupt");
        let store = StateStore::new(&dir).unwrap();
        fs::write(store.path(), format!("{HEADER}\nnothex\n")).unwrap();
        let e = store.load().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).ok();
    }
}
