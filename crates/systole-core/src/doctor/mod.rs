//! `project doctor` (ADR-0006): detect and resolve interrupted commits, then
//! check health. Order: resolve pending markers (completing or rolling back
//! each crashed transaction), verify the audit chain and `audit_head`, then
//! re-verify the load-time hash.
//!
//! `--absorb` exists because humans will edit the IR by hand: when the hash
//! fails, the doctor can commit the observed state as an `external_edit`
//! entry — the diff recorded is digests, not content (the engine never claims
//! to know what the editor wrote). Absorb also runs module validators and
//! reports their findings as warnings. There is no force-accept flag in
//! Release 0.

use std::fs;
use std::path::Path;

use serde_json::json;

use crate::audit::{self, AuditEntry, ChainBreak};
use crate::capability::Capability;
use crate::engine::is_read_only;
use crate::finding::Finding;
use crate::ir::format::format_value;
use crate::ir::manifest::Manifest;
use crate::ir::project::{Project, ProjectError};
use crate::ir::writer::{sync_dir, write_atomic};
use crate::ids::StableId;
use crate::ir::{LOCK_FILE, MANIFEST_FILE};
use crate::lock::{LockError, WriteLock};
use crate::module::Validator;
use crate::revision::{self, digest_of, IntegrityError};
use crate::tx::commit::{self, CommitError, CommitMeta, PendingMarker};

#[derive(Debug, thiserror::Error)]
pub enum DoctorError {
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error(transparent)]
    Chain(#[from] ChainBreak),
    #[error("{0}")]
    Commit(#[from] CommitError),
    #[error("{0}")]
    Io(String),
    #[error("refused: SYSTOLE_READ_ONLY=1")]
    ReadOnly,
    #[error("project is locked by pid {pid}")]
    Locked { pid: u32 },
    #[error("{0}")]
    Integrity(#[from] IntegrityError),
    #[error("pending marker rejected: {0} — left in place for manual inspection")]
    MarkerRejected(String),
}

/// How a pending transaction was resolved.
#[derive(Clone, PartialEq, Debug)]
pub enum Recovery {
    /// All files were in place or staged; the audit entry was appended (once).
    Completed { transaction_id: String },
    /// The transaction was incomplete; temps were removed and renamed files
    /// restored to their `before` images.
    RolledBack { transaction_id: String },
}

pub struct DoctorReport {
    /// `Some` iff a pending marker was resolved this run.
    pub recovered: Option<Recovery>,
    /// Audit entries in the log after recovery.
    pub entries: usize,
    /// `Some(audit_id)` iff `--absorb` committed an `external_edit` entry.
    pub absorbed: Option<String>,
    /// Findings from module validators (absorb only).
    pub findings: Vec<Finding>,
    /// Any blocking findings.
    pub blocking: bool,
}

fn lock_for(root: &Path) -> Result<WriteLock, DoctorError> {
    WriteLock::acquire(root).map_err(|e| match e {
        LockError::Held { pid } => DoctorError::Locked { pid },
        LockError::Io(e) => DoctorError::Io(e.to_string()),
    })
}

/// Where one marker file stands relative to its post-state.
enum FileState {
    /// Target already carries the post-state bytes (a delete: target absent).
    InPlace,
    /// Temp exists and carries the post-state bytes.
    Staged,
    /// Neither — the transaction is incomplete.
    Incomplete,
}

fn file_state(root: &Path, file: &commit::PendingFile) -> FileState {
    match &file.temp_path {
        Some(temp) => {
            let target = root.join(&file.path);
            let expected = file.expected_post_hash.as_deref().unwrap_or("");
            if let Ok(bytes) = fs::read(&target)
                && digest_of(&bytes) == expected
            {
                return FileState::InPlace;
            }
            if let Ok(bytes) = fs::read(root.join(temp))
                && digest_of(&bytes) == expected
            {
                return FileState::Staged;
            }
            FileState::Incomplete
        }
        // A delete: "in place" means the target is already gone.
        None => {
            if root.join(&file.path).exists() {
                FileState::Incomplete
            } else {
                FileState::InPlace
            }
        }
    }
}

/// Repair a torn final audit line before the marker it belongs to is
/// resolved. A crash mid-append leaves a non-empty log without a trailing
/// newline; the fragment must be a prefix of the marker's claimed entry —
/// anything else means the tail cannot be authenticated and is refused. A
/// matching fragment is truncated so the complete path can re-append the
/// entry canonically.
fn repair_torn_tail(root: &Path, marker: &PendingMarker) -> Result<(), DoctorError> {
    let path = root.join(audit::LOG_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(DoctorError::Io(e.to_string())),
    };
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(());
    }
    let boundary = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let fragment = &bytes[boundary..];
    let expected = audit::canonical_line(&marker.entry);
    if !expected.as_slice().starts_with(fragment) {
        return Err(DoctorError::MarkerRejected(format!(
            "{}: torn final audit line does not match the marker's entry",
            marker.transaction_id
        )));
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| DoctorError::Io(e.to_string()))?;
    file.set_len(boundary as u64)
        .map_err(|e| DoctorError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| DoctorError::Io(e.to_string()))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent).map_err(|e| DoctorError::Io(e.to_string()))?;
    }
    Ok(())
}

/// Authenticate a marker's claims against the verified log tail and the
/// on-disk manifest before executing anything it says. A marker is just a
/// file under audit/pending — anything could have written it — so:
/// - marker and entry must agree on transaction_id and plan_id;
/// - the claimed entry must either already BE the log tail (a crash between
///   append and marker-clear) or be the chain's next id with prev_hash equal
///   to the tail hash;
/// - the manifest must carry either the entry's base revision (rename still
///   pending) or its post revision (rename already landed).
///
/// Returns whether the claimed entry is already appended.
fn authenticate_marker(
    root: &Path,
    marker: &PendingMarker,
    lines: &[Vec<u8>],
) -> Result<bool, DoctorError> {
    let rejected = |reason: String| {
        DoctorError::MarkerRejected(format!("{}: {reason}", marker.transaction_id))
    };
    if marker.entry.transaction_id != marker.transaction_id {
        return Err(rejected(
            "marker/entry transaction_id mismatch".into(),
        ));
    }
    if marker.plan_id != marker.entry.plan_id {
        return Err(rejected("marker/entry plan_id mismatch".into()));
    }
    let last: Option<AuditEntry> = match lines.last() {
        Some(line) => Some(serde_json::from_slice(line).map_err(|e| {
            rejected(format!("log tail is unparseable — cannot authenticate: {e}"))
        })?),
        None => None,
    };
    if let Some(last) = &last
        && last.audit_id == marker.entry.audit_id
    {
        // Post-append crash: the appended line must be exactly the entry the
        // marker claims.
        if audit::canonical_line(last) != audit::canonical_line(&marker.entry) {
            return Err(rejected(
                "appended entry differs from the marker's claim".into(),
            ));
        }
        return Ok(true);
    }
    if marker.entry.audit_id != audit::next_audit_id(lines.len()) {
        return Err(rejected(format!(
            "entry {} is not the chain's next id",
            marker.entry.audit_id
        )));
    }
    let tail_hash = lines
        .last()
        .map(|l| digest_of(l))
        .unwrap_or_else(|| audit::GENESIS_PREV_HASH.to_string());
    if marker.entry.prev_hash != tail_hash {
        return Err(rejected(
            "entry prev_hash does not match the log tail".into(),
        ));
    }
    let manifest_bytes =
        fs::read(root.join(MANIFEST_FILE)).map_err(|e| DoctorError::Io(e.to_string()))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| DoctorError::Io(format!("unparseable manifest: {e}")))?;
    if manifest.project_revision != marker.entry.base_project_revision
        && manifest.project_revision != marker.entry.project_revision
    {
        return Err(rejected(
            "manifest revision matches neither the entry's base nor post revision"
                .into(),
        ));
    }
    Ok(false)
}

/// Resolve one pending marker (ADR-0007's rules):
/// - authenticate the marker against the log tail and manifest first;
/// - every file in place or staged → complete: rename remaining temps, append
///   the entry unless the log already carries its `audit_id`, remove marker;
/// - anything else → roll back: remove temps, restore `before` images on files
///   already renamed — the manifest included — remove marker.
fn resolve_marker(root: &Path, marker: &PendingMarker) -> Result<Recovery, DoctorError> {
    // A torn final line (crash mid-append) is repaired against the marker's
    // claim before the tail is authenticated.
    repair_torn_tail(root, marker)?;
    let lines = audit::read_lines(root).map_err(|e| DoctorError::Io(e.to_string()))?;
    let appended = authenticate_marker(root, marker, &lines)?;
    let states: Vec<FileState> = marker
        .files
        .iter()
        .map(|f| file_state(root, f))
        .collect();
    let completable = states
        .iter()
        .all(|s| matches!(s, FileState::InPlace | FileState::Staged));

    if completable {
        let mut dirs = std::collections::BTreeSet::new();
        for (file, state) in marker.files.iter().zip(&states) {
            if let (Some(temp), FileState::Staged) = (&file.temp_path, state) {
                let target = root.join(&file.path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| DoctorError::Io(e.to_string()))?;
                }
                fs::rename(root.join(temp), &target)
                    .map_err(|e| DoctorError::Io(e.to_string()))?;
                if let Some(parent) = target.parent() {
                    dirs.insert(parent.to_path_buf());
                }
            }
        }
        for dir in dirs {
            sync_dir(&dir).map_err(|e| DoctorError::Io(e.to_string()))?;
        }
        // Append exactly once: the crash may have landed after the append.
        let already = audit::read_lines(root)
            .map_err(|e| DoctorError::Io(e.to_string()))?
            .iter()
            .filter_map(|l| serde_json::from_slice::<AuditEntry>(l).ok())
            .any(|e| e.audit_id == marker.entry.audit_id);
        if !already {
            audit::append_line(root, &audit::canonical_line(&marker.entry))
                .map_err(|e| DoctorError::Io(e.to_string()))?;
        }
        let _ = commit::remove_marker(root, marker);
        Ok(Recovery::Completed {
            transaction_id: marker.transaction_id.clone(),
        })
    } else {
        if appended {
            return Err(DoctorError::MarkerRejected(format!(
                "{}: entry {} is already appended but not every post-state file \
                 is on disk — refusing to roll back a recorded transaction",
                marker.transaction_id, marker.entry.audit_id
            )));
        }
        // Roll back: drop temps, restore before-images where a rename landed.
        for file in &marker.files {
            if let Some(temp) = &file.temp_path {
                let temp_abs = root.join(temp);
                if temp_abs.exists() {
                    fs::remove_file(&temp_abs).map_err(|e| DoctorError::Io(e.to_string()))?;
                }
            }
            if matches!(file_state(root, file), FileState::InPlace)
                && let Some(change) = marker
                    .entry
                    .changes
                    .iter()
                    .find(|c| c.path.as_str() == file.path)
            {
                let target = root.join(&file.path);
                match &change.before {
                    Some(before) => {
                        write_atomic(&target, &format_value(before))
                            .map_err(|e| DoctorError::Io(e.to_string()))?;
                    }
                    None => {
                        let _ = fs::remove_file(&target);
                    }
                }
            }
        }
        // The manifest is not in entry.changes — its pre-state image travels
        // in the marker. Restore it whenever the on-disk manifest is not
        // already the pre-state bytes (a post-state manifest left in place
        // would make the project unloadable after rollback).
        let manifest_target = root.join(MANIFEST_FILE);
        let manifest_pre_bytes = marker
            .manifest_before
            .as_ref()
            .map(|m| format_value(&serde_json::to_value(m).expect("manifest serializes")));
        let manifest_in_place = marker
            .files
            .iter()
            .any(|f| f.path == MANIFEST_FILE && matches!(file_state(root, f), FileState::InPlace));
        match &manifest_pre_bytes {
            Some(pre) => {
                let current = fs::read(&manifest_target).ok();
                if current.as_deref() != Some(pre.as_slice()) {
                    write_atomic(&manifest_target, pre)
                        .map_err(|e| DoctorError::Io(e.to_string()))?;
                }
            }
            None if manifest_in_place => {
                return Err(DoctorError::MarkerRejected(format!(
                    "{}: the manifest rename landed but the marker records no \
                     pre-state image to restore",
                    marker.transaction_id
                )));
            }
            None => {}
        }
        let _ = commit::remove_marker(root, marker);
        Ok(Recovery::RolledBack {
            transaction_id: marker.transaction_id.clone(),
        })
    }
}

/// List pending markers in name order (single writer ⇒ at most one in
/// practice; the loop tolerates more).
fn pending_markers(root: &Path) -> Result<Vec<PendingMarker>, DoctorError> {
    let dir = root.join(audit::PENDING_DIR);
    let mut out = Vec::new();
    let read_dir = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(DoctorError::Io(e.to_string())),
    };
    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|e| DoctorError::Io(e.to_string()))?;
        let marker: PendingMarker = serde_json::from_slice(&bytes)
            .map_err(|e| DoctorError::Io(format!("unparseable marker {name}: {e}")))?;
        // Every recorded file target must stay inside the project: only
        // ordinary components — no absolute prefix, no parent steps.
        let inside = |t: &str| {
            !t.is_empty()
                && std::path::Path::new(t)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
        };
        if marker
            .files
            .iter()
            .any(|f| !inside(&f.path) || f.temp_path.as_deref().is_some_and(|t| !inside(t)))
        {
            return Err(DoctorError::MarkerRejected(format!(
                "{name}: records a file target outside the project root"
            )));
        }
        // The claimed id must equal the file it was read from: a forged id
        // could aim marker_path writes and removals outside audit/pending.
        let stem = name.strip_suffix(".json").unwrap_or_default();
        if marker.transaction_id != stem {
            return Err(DoctorError::MarkerRejected(format!(
                "{name}: marker claims transaction_id {:?}",
                marker.transaction_id
            )));
        }
        out.push(marker);
    }
    out.sort_by(|a, b| a.transaction_id.cmp(&b.transaction_id));
    Ok(out)
}

/// Build the `external_edit` entry that absorbs a hand edit (ADR-0006). The
/// recorded diff is digests: `before` is the digest the manifest recorded,
/// `after` the digest of the observed canonical bytes (or null when a file
/// vanished). Runs through the same two-phase commit as any transaction.
/// The highest stable-id number observed anywhere in the project — the
/// post-absorb counter derives from it so a hand-added object can never have
/// its id reissued by a later op.
fn observed_stable_id_counter(project: &Project) -> u64 {
    fn walk(value: &serde_json::Value, max: &mut u64) {
        match value {
            serde_json::Value::String(s) => {
                if let Ok(id) = StableId::try_from(s.clone()) {
                    *max = (*max).max(id.n);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, max);
                }
            }
            serde_json::Value::Object(map) => {
                for v in map.values() {
                    walk(v, max);
                }
            }
            _ => {}
        }
    }
    let mut max = project.manifest.stable_id_counter;
    for value in project.files.values() {
        walk(value, &mut max);
    }
    max
}

fn absorb_external_edit(
    project: &Project,
    integrity: &IntegrityError,
) -> Result<AuditEntry, DoctorError> {
    let mut digest_rows = Vec::new();
    for path in &integrity.changed {
        let before = project
            .manifest
            .files
            .get(path)
            .map(|s| json!(s.clone()))
            .unwrap_or(serde_json::Value::Null);
        let after = if path.as_str() == LOCK_FILE {
            // The lock lives in `project.lock`, not `project.files`: the
            // recorded digest is of the canonical bytes the commit leaves
            // on disk — the same bytes `refresh_integrity` will hash.
            json!(digest_of(&project.lock_bytes()))
        } else {
            match project.files.get(path) {
                Some(v) => json!(digest_of(&format_value(v))),
                None => {
                    // A tracked file that vanished — manifest changes show up
                    // here too; record their observed digest if readable.
                    match fs::read(project.root.join(path.as_str())) {
                        Ok(bytes) => json!(digest_of(&bytes)),
                        Err(_) => serde_json::Value::Null,
                    }
                }
            }
        };
        digest_rows.push(crate::op::FileChange {
            path: path.clone(),
            before: Some(before),
            after: Some(after),
        });
    }
    // The staged writes rewrite each changed file to its canonical bytes —
    // verification digests the raw on-disk form, so absorb must leave the
    // observed CONTENT in canonical form or the project would verify dirty
    // forever.
    let canonicalizing: Vec<crate::op::FileChange> = integrity
        .changed
        .iter()
        .map(|path| crate::op::FileChange {
            path: path.clone(),
            before: None,
            // The lock is stored on `project.lock`, not `project.files` —
            // staging `None` here would DELETE the file the committed
            // manifest's digest table still records, leaving the project
            // unloadable. Stage its canonical serialization instead, exactly
            // as `write_all` produces it.
            after: if path.as_str() == LOCK_FILE {
                Some(serde_json::to_value(&project.lock).expect("lock serializes"))
            } else {
                project.files.get(path).cloned()
            },
        })
        .collect();
    let entry = commit::run(
        &project.root,
        project,
        &canonicalizing,
        &digest_rows,
        observed_stable_id_counter(project),
        CommitMeta {
            actor: "cli_local".into(),
            op_id: "core.external_edit".into(),
            op_version: 1,
            input: json!({
                "changed": integrity.changed.iter().map(|p| p.as_str()).collect::<Vec<_>>()
            }),
            plan_id: None,
            capability: Capability::ProjectWrite.as_str().to_string(),
            approval: "allow".into(),
            rollback_of: None,
            output: serde_json::Value::Null,
        },
    )?;
    Ok(entry)
}

/// The full doctor pass. `absorb` permits the `external_edit` commit; without
/// it an integrity failure is a refusal.
pub fn run(
    root: &Path,
    absorb: bool,
    validators: &[Box<dyn Validator>],
) -> Result<DoctorReport, DoctorError> {
    if absorb && is_read_only() {
        return Err(DoctorError::ReadOnly);
    }

    // Load WITHOUT the hash check — doctor exists to look at broken state.
    let mut project = Project::load_unverified(root)?;

    // 1. Pending markers first — recovery may need the lock and is a write.
    let mut recovered = None;
    let markers = pending_markers(root)?;
    if !markers.is_empty() {
        if is_read_only() {
            return Err(DoctorError::ReadOnly);
        }
        let _lock = lock_for(root)?;
        for marker in &markers {
            recovered = Some(resolve_marker(root, marker)?);
        }
        drop(_lock);
        // Recovery may have landed a post-state manifest or restored the
        // pre-state one — the chain and integrity checks below must see the
        // state actually on disk now, not the pre-recovery snapshot.
        project = Project::load_unverified(root)?;
    }

    // 2. Audit chain + audit_head.
    let entries = audit::verify_chain(root, project.manifest.audit_head.as_ref())?;

    // 3. Load-time hash. On mismatch: refuse, or absorb under the lock.
    let mut absorbed = None;
    let mut findings = Vec::new();
    match revision::verify(&project) {
        Ok(()) => {}
        Err(integrity) => {
            if !absorb {
                return Err(DoctorError::Integrity(integrity));
            }
            if is_read_only() {
                return Err(DoctorError::ReadOnly);
            }
            let _lock = lock_for(root)?;
            let entry = absorb_external_edit(&project, &integrity)?;
            absorbed = Some(entry.audit_id.clone());
            // Module validators observe the absorbed state; findings are
            // reported as warnings and never block.
            let absorbed_project = Project::load_unverified(root)?;
            for v in validators {
                // Findings over an absorbed state are advisory — absorb
                // reports what the editor left behind; it does not gate.
                let mut run_findings = v.run(&absorbed_project);
                for f in &mut run_findings {
                    f.blocking = false;
                }
                findings.extend(run_findings);
            }
            drop(_lock);
            revision::verify(&absorbed_project).map_err(DoctorError::Integrity)?;
        }
    }

    let blocking = findings.iter().any(|f| f.blocking);
    Ok(DoctorReport {
        recovered,
        entries: entries.len() + absorbed.iter().count(),
        absorbed,
        findings,
        blocking,
    })
}
