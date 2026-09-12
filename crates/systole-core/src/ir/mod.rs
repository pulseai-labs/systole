//! The Project IR on disk: manifest, lock, the loaded project, the canonical
//! format, and the atomic writer.

pub mod format;
pub mod lock;
pub mod manifest;
pub mod project;
pub mod writer;

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A project-relative POSIX path (`regions/region_00001/region.json`). Ordering
/// is byte order of the path string, which is the hash's sorted-path order.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RelPath(String);

impl RelPath {
    pub fn new(path: impl Into<String>) -> Self {
        RelPath(path.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The file name of the project manifest inside a project root.
pub const MANIFEST_FILE: &str = "project.systole.json";
/// The file name of the lock inside a project root.
pub const LOCK_FILE: &str = "systole.lock.json";
