//! Storage of the TPM non-volatile state as a hex text file.
//!
//! The state directory holds `tpm-state.hex`. The file is plain text so the
//! contents can be inspected and copied without special tooling. Writes go to a
//! temporary file that is then renamed over the old one, so an interrupted save
//! never leaves a half written state file behind.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::util::hex;

/// Name of the state file inside the state directory.
pub const STATE_FILE: &str = "tpm-state.hex";

/// First line of the file, identifying the format.
const HEADER: &str = "# swtrust TPM state v1";

/// Number of hex characters per line in the saved file.
const LINE_WIDTH: usize = 64;

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
    pub fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let path = self.path();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let body: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("");
        match hex::decode(&body) {
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )),
        }
    }

    /// Write `data` as hex text, replacing any existing state.
    pub fn save(&self, data: &[u8]) -> io::Result<()> {
        let path = self.path();
        let tmp = self.dir.join(format!("{STATE_FILE}.tmp"));
        let mut text = String::with_capacity(HEADER.len() + data.len() * 2 + data.len() / 32 + 8);
        text.push_str(HEADER);
        text.push('\n');
        text.push_str(&hex::encode_wrapped(data, LINE_WIDTH));
        text.push('\n');
        fs::write(&tmp, text.as_bytes())?;
        // Windows rename fails when the destination exists, so remove it first.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        fs::rename(&tmp, &path)
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
        // The temporary file is not left behind.
        assert!(!dir.join(format!("{STATE_FILE}.tmp")).exists());
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
        fs::write(store.path(), "# swtrust TPM state v1\nnothex\n").unwrap();
        let e = store.load().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).ok();
    }
}
