//! Atomic file writes: temp file in the target's directory, then rename, so a
//! crash never leaves a half-written IR file behind.

use std::io::Write;
use std::path::Path;

/// Write `bytes` to `path` via a temp file in the same directory and an atomic
/// rename over the destination.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".systole-tmp-")
        .tempfile_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
