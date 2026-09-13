//! The two-phase, crash-recoverable commit (ADR-0007): pending marker, temp
//! files, ordered renames, audit append, marker clear.
//!
//! Order, all paths resolved absolute: compute the post-state in memory
//! (staged files, the manifest with the revision and the stable-id counter
//! advanced, the `files` table refreshed, `project_hash` recomputed over the
//! blanked manifest exactly as `revision` defines it); build the audit entry —
//! its `post_project_hash` is computable before `audit_head` because the hash
//! blanks `audit_head`; compute the entry's hash; set `manifest.audit_head`;
//! write the pending marker `audit/pending/<transaction_id>.json` at phase
//! `prepared`; write every temp file beside its target via `format_value`;
//! mark `renaming`; rename each temp into place in the marker's order (a
//! delete carries `temp_path: null`); append the entry as one canonical line;
//! mark `audited`; remove the marker. A crash at any point leaves a marker
//! `doctor` resolves.
//!
//! The manifest is always the last rename, so an interrupted commit always
//! leaves the old manifest in place until every data file has landed — a
//! recoverable-by-construction crash window.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::{self, AuditEntry, ChainBreak};
use crate::ir::format::format_value;
use crate::ir::manifest::{AuditHead, Manifest};
use crate::ir::project::Project;
use crate::ir::writer::{sync_dir, write_atomic};
use crate::ir::{RelPath, LOCK_FILE, MANIFEST_FILE};
use crate::op::FileChange;
use crate::revision::{self, digest_of, project_hash};

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot advance project revision {0:?}")]
    BadRevision(String),
    #[error("{count} pending transaction marker(s) under audit/pending — \
             run `systole project doctor` to resolve them before any further \
             transaction")]
    PendingMarkers { count: usize },
    #[error("staged path escapes the project root: {path:?}")]
    PathEscapes { path: String },
    #[error("no changes staged — nothing to commit")]
    NoChanges,
    #[error("audit chain broken: {0}")]
    Chain(#[from] ChainBreak),
}

fn io(path: &str) -> impl FnOnce(std::io::Error) -> CommitError + '_ {
    move |source| CommitError::Io {
        path: path.to_string(),
        source,
    }
}

/// Everything the audit entry needs beyond the staged changes — supplied by
/// the caller (the engine for an op commit, fixed values for the synthetic
/// `core.rollback` / `core.external_edit` entries).
pub struct CommitMeta {
    pub actor: String,
    pub op_id: String,
    pub op_version: u32,
    pub input: serde_json::Value,
    pub plan_id: Option<String>,
    pub capability: String,
    pub approval: String,
    pub rollback_of: Option<String>,
    pub output: serde_json::Value,
}

/// One row of the pending marker's `files` list (ADR-0007): the target, the
/// temp file holding its post-state bytes, and the digest those bytes must
/// hash to. A delete carries `temp_path: null` and a null post hash.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PendingFile {
    pub path: String,
    pub temp_path: Option<String>,
    pub expected_post_hash: Option<String>,
}

/// `audit/pending/<transaction_id>.json` — the crash-recovery record. All
/// paths are project-relative and resolved absolute at use.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PendingMarker {
    pub transaction_id: String,
    pub phase: String,
    pub plan_id: Option<String>,
    pub entry: AuditEntry,
    /// The pre-state manifest: rollback restores it when the manifest rename
    /// already landed but the transaction cannot be completed.
    #[serde(default)]
    pub manifest_before: Option<Manifest>,
    pub files: Vec<PendingFile>,
}

/// A commit planned but not yet on disk: the marker plus the temp-file bytes
/// each write target will receive. Splitting planning from the phase steps
/// lets the engine run the whole commit and lets tests drive partial crashes.
pub struct PreparedCommit {
    pub marker: PendingMarker,
    /// (temp relative path, target relative path, canonical bytes)
    pub temp_writes: Vec<(String, String, Vec<u8>)>,
    /// targets that are deletions (temp_path null in the marker)
    pub deletes: Vec<String>,
}

/// Compute the post-state and build the marker + entry, writing nothing.
pub fn plan_commit(
    root: &Path,
    project: &Project,
    writes: &[FileChange],
    entry_changes: &[FileChange],
    new_stable_id_counter: u64,
    meta: CommitMeta,
) -> Result<PreparedCommit, CommitError> {
    let _ = root;

    // An empty write set would still bump the revision and append an audit
    // entry — refuse before any marker exists so no-change commits leave no
    // trace.
    if writes.is_empty() {
        return Err(CommitError::NoChanges);
    }

    // Every staged or recorded path must stay inside the project — a `..`
    // or absolute target would let `root.join` below escape the root, so
    // the whole transaction is refused before any marker or temp exists.
    for change in writes.iter().chain(entry_changes) {
        if !crate::ir::is_project_relative(change.path.as_str()) {
            return Err(CommitError::PathEscapes {
                path: change.path.as_str().to_string(),
            });
        }
    }

    // 1. Post-state file map.
    let mut post_files: BTreeMap<RelPath, serde_json::Value> = project.files.clone();
    for change in writes {
        match &change.after {
            Some(value) => {
                post_files.insert(change.path.clone(), value.clone());
            }
            None => {
                post_files.remove(&change.path);
            }
        }
    }

    // 2. Post-state manifest: revision + counter advance, files table
    //    refreshed, hash recomputed over the blanked manifest.
    let mut post_manifest: Manifest = project.manifest.clone();
    post_manifest.project_revision =
        revision::bump_revision(&project.manifest.project_revision)
            .map_err(|_| CommitError::BadRevision(project.manifest.project_revision.clone()))?;
    post_manifest.stable_id_counter = new_stable_id_counter;
    post_manifest.audit_head = None;

    let lock_bytes = project.lock_bytes();
    let mut table = BTreeMap::new();
    table.insert(RelPath::new(LOCK_FILE), digest_of(&lock_bytes));
    let mut domain: BTreeMap<RelPath, Vec<u8>> = BTreeMap::new();
    domain.insert(RelPath::new(LOCK_FILE), lock_bytes);
    for (path, value) in &post_files {
        let bytes = format_value(value);
        table.insert(path.clone(), digest_of(&bytes));
        domain.insert(path.clone(), bytes);
    }
    post_manifest.files = table;
    domain.insert(
        RelPath::new(MANIFEST_FILE),
        format_value(&revision::blanked_manifest_value(&post_manifest)),
    );
    post_manifest.project_hash = project_hash(&domain);

    // 3. The audit entry. post_project_hash is the just-computed hash.
    // Audit identity comes from the VERIFIED chain, not a raw line count: a
    // torn or trailing-garbage log cannot mint a colliding audit_id, and an
    // already-broken chain is refused rather than silently re-extended.
    let entries =
        audit::verify_chain(&project.root, project.manifest.audit_head.as_ref())?;
    let audit_id = audit::next_audit_id(entries.len());
    let prev_hash = entries
        .last()
        .map(audit::entry_hash)
        .unwrap_or_else(|| audit::GENESIS_PREV_HASH.to_string());
    let transaction_id = audit::transaction_id(&audit_id, meta.plan_id.as_deref());

    let entry = AuditEntry {
        audit_id: audit_id.clone(),
        transaction_id: transaction_id.clone(),
        timestamp: audit::now_rfc3339(),
        actor: meta.actor,
        op_id: meta.op_id,
        op_version: meta.op_version,
        input_hash: audit::input_hash(&meta.input),
        plan_id: meta.plan_id.clone(),
        capability: meta.capability,
        approval: meta.approval,
        base_project_revision: project.manifest.project_revision.clone(),
        project_revision: post_manifest.project_revision.clone(),
        pre_project_hash: project.manifest.project_hash.clone(),
        post_project_hash: post_manifest.project_hash.clone(),
        changes: entry_changes.to_vec(),
        output: meta.output,
        rollback_of: meta.rollback_of,
        hash_alg: "sha256".into(),
        prev_hash,
    };

    // 4. audit_head now that the entry's own hash is known.
    post_manifest.audit_head = Some(AuditHead {
        id: audit_id,
        hash: audit::entry_hash(&entry),
    });
    let manifest_bytes = format_value(
        &serde_json::to_value(&post_manifest).expect("a manifest serializes"),
    );

    // 5. Marker file list: every staged write, then the manifest LAST.
    let mut files: Vec<PendingFile> = Vec::new();
    let mut temp_writes = Vec::new();
    let mut deletes = Vec::new();
    let mut push = |path: &str, bytes: Option<Vec<u8>>| match bytes {
        Some(bytes) => {
            let temp = temp_path_for(path, &transaction_id);
            files.push(PendingFile {
                path: path.to_string(),
                temp_path: Some(temp.clone()),
                expected_post_hash: Some(digest_of(&bytes)),
            });
            temp_writes.push((temp, path.to_string(), bytes));
        }
        None => {
            files.push(PendingFile {
                path: path.to_string(),
                temp_path: None,
                expected_post_hash: None,
            });
            deletes.push(path.to_string());
        }
    };
    for change in writes {
        match &change.after {
            Some(value) => push(change.path.as_str(), Some(format_value(value))),
            None => push(change.path.as_str(), None),
        }
    }
    push(MANIFEST_FILE, Some(manifest_bytes));

    Ok(PreparedCommit {
        marker: PendingMarker {
            transaction_id,
            phase: "prepared".into(),
            plan_id: meta.plan_id,
            entry,
            manifest_before: Some(project.manifest.clone()),
            files,
        },
        temp_writes,
        deletes,
    })
}

/// The sibling temp path for a target: a dotfile, never `*.json`, so it is
/// invisible to the loader and the hash domain even while it sits beside its
/// target inside `entities/**` or `regions/**`.
fn temp_path_for(target: &str, transaction_id: &str) -> String {
    match target.rsplit_once('/') {
        Some((dir, name)) => format!("{dir}/.{name}.systmp-{transaction_id}"),
        None => format!(".{target}.systmp-{transaction_id}"),
    }
}

pub fn marker_path(root: &Path, transaction_id: &str) -> PathBuf {
    root.join(audit::PENDING_DIR)
        .join(format!("{transaction_id}.json"))
}

/// The marker files under `audit/pending/`, in name order — the set every
/// manifest-writing path must refuse to proceed over until `doctor` resolves
/// them. A missing directory is an empty set.
pub fn pending_marker_files(root: &Path) -> Result<Vec<PathBuf>, CommitError> {
    let dir = root.join(audit::PENDING_DIR);
    let read_dir = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(audit::PENDING_DIR)(e)),
    };
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(io(audit::PENDING_DIR))?;
        if entry.file_name().to_string_lossy().ends_with(".json") {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// Write the marker at the given phase.
pub fn write_marker(
    root: &Path,
    marker: &mut PendingMarker,
    phase: &str,
) -> Result<(), CommitError> {
    marker.phase = phase.to_string();
    let path = marker_path(root, &marker.transaction_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io("audit/pending"))?;
    }
    write_atomic(
        &path,
        &format_value(&serde_json::to_value(&*marker).expect("a pending marker serializes")),
    )
    .map_err(io("audit/pending"))
}

/// Join a project-relative path onto `root`, refusing any path that would
/// escape the project — the one gateway every write path funnels through.
fn checked_join(root: &Path, rel: &str) -> Result<PathBuf, CommitError> {
    if crate::ir::is_project_relative(rel) {
        Ok(root.join(rel))
    } else {
        Err(CommitError::PathEscapes {
            path: rel.to_string(),
        })
    }
}

/// Write every temp file beside its target. Each temp is fsynced — and its
/// containing directory afterwards — so the `renaming` marker that follows is
/// never written ahead of the bytes it describes.
pub fn write_temps(root: &Path, prepared: &PreparedCommit) -> Result<(), CommitError> {
    let mut dirs = BTreeSet::new();
    for (temp, _target, bytes) in &prepared.temp_writes {
        let abs = checked_join(root, temp)?;
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).map_err(io(temp))?;
        }
        let mut file = fs::File::create(&abs).map_err(io(temp))?;
        file.write_all(bytes).map_err(io(temp))?;
        file.sync_all().map_err(io(temp))?;
        if let Some(parent) = abs.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }
    for dir in dirs {
        let label = dir.display().to_string();
        sync_dir(&dir).map_err(io(&label))?;
    }
    Ok(())
}

/// Apply the marker's order: rename each temp over its target; a `temp_path:
/// null` entry deletes its target.
pub fn apply_renames(root: &Path, prepared: &PreparedCommit) -> Result<(), CommitError> {
    for file in &prepared.marker.files {
        let target = checked_join(root, &file.path)?;
        match &file.temp_path {
            Some(temp) => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(io(&file.path))?;
                }
                fs::rename(checked_join(root, temp)?, &target).map_err(io(&file.path))?;
            }
            None => match fs::remove_file(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(&file.path)(e)),
            },
        }
    }
    // The renames are only durable once every directory they touched is
    // fsynced — an unsynced rename can vanish across a crash.
    let mut dirs = BTreeSet::new();
    for file in &prepared.marker.files {
        if let Some(parent) = checked_join(root, &file.path)?.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }
    for dir in dirs {
        let label = dir.display().to_string();
        sync_dir(&dir).map_err(io(&label))?;
    }
    Ok(())
}

/// Append the entry's canonical line to `audit/audit.jsonl`.
pub fn append_entry(root: &Path, entry: &AuditEntry) -> Result<(), CommitError> {
    audit::append_line(root, &audit::canonical_line(entry)).map_err(io(audit::LOG_FILE))
}

/// Remove the pending marker.
pub fn remove_marker(root: &Path, marker: &PendingMarker) -> Result<(), CommitError> {
    let path = marker_path(root, &marker.transaction_id);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io("audit/pending")(e)),
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent).map_err(io("audit/pending"))?;
    }
    Ok(())
}

/// Run the whole two-phase commit. Returns the appended entry.
pub fn run(
    root: &Path,
    project: &Project,
    writes: &[FileChange],
    entry_changes: &[FileChange],
    new_stable_id_counter: u64,
    meta: CommitMeta,
) -> Result<AuditEntry, CommitError> {
    // The single funnel every audit-appending write passes through: refuse
    // while a leftover crash marker exists — doctor owns that state.
    let pending = pending_marker_files(root)?;
    if !pending.is_empty() {
        return Err(CommitError::PendingMarkers {
            count: pending.len(),
        });
    }
    let prepared = plan_commit(root, project, writes, entry_changes, new_stable_id_counter, meta)?;
    let mut marker = prepared.marker.clone();
    write_marker(root, &mut marker, "prepared")?;
    write_temps(root, &prepared)?;
    write_marker(root, &mut marker, "renaming")?;
    apply_renames(root, &prepared)?;
    append_entry(root, &marker.entry)?;
    write_marker(root, &mut marker, "audited")?;
    remove_marker(root, &marker)?;
    Ok(marker.entry)
}
