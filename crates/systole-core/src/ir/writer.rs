//! Atomic file writes: temp file in the target's directory, then rename, so a
//! crash never leaves a half-written IR file behind. The temp is fsynced
//! before the rename and the containing directory after it — a crash can
//! neither lose the bytes nor the link.

use std::fs;
use std::io::Write;
use std::path::Path;

/// fsync a directory so a rename/create/unlink inside it survives a crash.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Write `bytes` to `path` via a temp file in the same directory and an atomic
/// rename over the destination.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".systole-tmp-")
        .tempfile_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    sync_dir(parent)?;
    Ok(())
}
