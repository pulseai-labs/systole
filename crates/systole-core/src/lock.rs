//! The single-writer lock (ADR-0001, ADR-0007): `.systole/write.lock` inside
//! the project root, held with `std::fs::File::try_lock` (stable since Rust
//! 1.89 — no locking crate; this settles ADR-0007's unverified `fs2` claim by
//! not needing it), with the holder's pid written into the file. `.systole/**`
//! is outside the hash domain, so the lock file is invisible to the IR.
//!
//! Taken for `commit`, `rollback` and doctor's recovery/`--absorb`; never for
//! reads. The guard releases the OS lock on drop.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const LOCK_DIR: &str = ".systole";
const LOCK_FILE_NAME: &str = "write.lock";

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("project is locked by pid {pid}")]
    Held { pid: u32 },
    #[error("io error on the write lock: {0}")]
    Io(#[from] std::io::Error),
}

/// A held write lock. Dropping it releases the OS lock.
#[derive(Debug)]
pub struct WriteLock {
    file: File,
    _path: PathBuf,
}

impl WriteLock {
    /// Acquire the project's write lock, or fail with [`LockError::Held`]
    /// naming the holder's pid.
    pub fn acquire(root: &Path) -> Result<WriteLock, LockError> {
        let dir = root.join(LOCK_DIR);
        fs::create_dir_all(&dir)?;
        let path = dir.join(LOCK_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        match file.try_lock() {
            Ok(()) => {}
            Err(e) => {
                let e = std::io::Error::from(e);
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ResourceBusy | std::io::ErrorKind::WouldBlock
                ) {
                    let pid = read_pid(&path).unwrap_or(0);
                    return Err(LockError::Held { pid });
                }
                return Err(LockError::Io(e));
            }
        }

        let mut file = file;
        file.set_len(0)?;
        file.write_all(std::process::id().to_string().as_bytes())?;
        file.flush()?;
        Ok(WriteLock { file, _path: path })
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        // Explicit unlock; closing the descriptor would release it anyway.
        let _ = self.file.unlock();
    }
}

fn read_pid(path: &Path) -> Option<u32> {
    let mut buf = String::new();
    File::open(path).ok()?.read_to_string(&mut buf).ok()?;
    buf.trim().parse().ok()
}
