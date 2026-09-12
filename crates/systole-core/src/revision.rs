//! The project hash and the load-time integrity check (ADR-0006, ADR-0010).
//!
//! `project_hash` is sha256 over, in sorted relative-path order, the path
//! bytes, a NUL, the file's canonical bytes, a NUL — for the manifest (with
//! `project_hash`, `project_revision` and `audit_head` blanked), the lock, and
//! every `*.json` under `regions/**` and `entities/**`. `audit/**`, `plans/**`
//! and `.systole/**` are excluded. The manifest's `files` table carries the
//! per-file sha256 of the same canonical bytes for exact changed-file
//! reporting; `project_hash` and the table are updated together on every
//! write.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::ir::format::format_value;
use crate::ir::manifest::Manifest;
use crate::ir::project::Project;
use crate::ir::{RelPath, LOCK_FILE, MANIFEST_FILE};

/// The refusal a loading command returns when the project on disk no longer
/// matches its recorded hash. `expected` is the recorded hash, `actual` the
/// recomputed one, `changed` the files whose digests differ from the manifest's
/// table (or that exist only on one side of it).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IntegrityError {
    pub expected: String,
    pub actual: String,
    pub changed: Vec<RelPath>,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "project files changed outside a transaction ({})",
            self.changed
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for IntegrityError {}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A digest as stored in the manifest: `sha256:<hex>`.
pub fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The manifest with `project_hash`, `project_revision` and `audit_head`
/// replaced by null — the form that enters the project hash.
pub fn blanked_manifest_value(manifest: &Manifest) -> serde_json::Value {
    let mut value =
        serde_json::to_value(manifest).expect("serializing a manifest cannot fail");
    let object = value
        .as_object_mut()
        .expect("a manifest serializes to an object");
    object.insert("project_hash".into(), serde_json::Value::Null);
    object.insert("project_revision".into(), serde_json::Value::Null);
    object.insert("audit_head".into(), serde_json::Value::Null);
    value
}

/// sha256 over, in sorted relative-path order, the path bytes, a NUL, the
/// file's canonical bytes, a NUL. Deterministic across machines.
pub fn project_hash(entries: &BTreeMap<RelPath, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for (path, bytes) in entries {
        hasher.update(path.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Recompute the hash over a loaded project and compare it against the
/// manifest's record. On mismatch, name exactly which files changed by hashing
/// each domain file against the manifest's `files` table.
pub fn verify(project: &Project) -> Result<(), IntegrityError> {
    // Canonical bytes of every hash-domain file, keyed by relative path.
    let mut domain: BTreeMap<RelPath, Vec<u8>> = BTreeMap::new();
    domain.insert(
        RelPath::new(MANIFEST_FILE),
        format_value(&blanked_manifest_value(&project.manifest)),
    );
    domain.insert(
        RelPath::new(LOCK_FILE),
        format_value(&serde_json::to_value(&project.lock).expect("lock serializes")),
    );
    for (path, value) in &project.files {
        domain.insert(path.clone(), format_value(value));
    }

    let actual = project_hash(&domain);
    let expected = project.manifest.project_hash.clone();
    if actual == expected {
        return Ok(());
    }

    // Exact changed-file report: digest mismatch, file only on disk, or entry
    // only in the recorded table.
    let mut changed: Vec<RelPath> = Vec::new();
    let table = &project.manifest.files;
    for (path, bytes) in &domain {
        let digest = digest_of(bytes);
        if path.as_str() != MANIFEST_FILE && table.get(path) != Some(&digest) {
            changed.push(path.clone());
        }
    }
    for path in table.keys() {
        if !domain.contains_key(path) {
            changed.push(path.clone());
        }
    }
    if changed.is_empty() {
        // No domain file disagrees with the table, so the manifest itself is
        // what changed (its recorded hash no longer matches its own content).
        changed.push(RelPath::new(MANIFEST_FILE));
    }

    Err(IntegrityError {
        expected,
        actual,
        changed,
    })
}
