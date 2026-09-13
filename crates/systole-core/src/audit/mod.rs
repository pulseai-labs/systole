//! The audit log (ADR-0003, ADR-0006): one canonical compact line per entry
//! in `audit/audit.jsonl`, hash-chained by `prev_hash` with the head recorded
//! in the manifest's `audit_head`. Entries are append-only; rollback is a
//! compensating entry, never an edit.
//!
//! The log is outside the IR and the hash domain; `ir::format::format_line` is
//! its only serializer. An entry's own hash is sha256 over its canonical line
//! and is stored only in the next entry's `prev_hash` and in the manifest's
//! `audit_head` — a hashed record never carries its own digest.

use std::fs;
use std::io::Write;
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ir::format::{format_line, format_value};
use crate::ir::manifest::AuditHead;
use crate::op::FileChange;
use crate::revision::{digest_of, sha256_hex};

pub const LOG_FILE: &str = "audit/audit.jsonl";
pub const PENDING_DIR: &str = "audit/pending";

/// The `prev_hash` of the first entry: `sha256:` over 64 zeros.
pub const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// One audit entry — every committed transaction's record (ADR-0006). The
/// `changes` list is the diff; each change's `before` is the inverse data a
/// rollback restores. `rollback_of` is absent unless the entry is itself a
/// rollback. `hash_alg` is recorded per entry so the algorithm stays
/// replaceable (ADR-0007).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AuditEntry {
    pub audit_id: String,
    pub transaction_id: String,
    pub timestamp: String,
    pub actor: String,
    pub op_id: String,
    pub op_version: u32,
    pub input_hash: String,
    pub plan_id: Option<String>,
    pub capability: String,
    pub approval: String,
    pub base_project_revision: String,
    pub project_revision: String,
    pub pre_project_hash: String,
    pub post_project_hash: String,
    pub changes: Vec<FileChange>,
    pub output: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_of: Option<String>,
    pub hash_alg: String,
    pub prev_hash: String,
}

/// The entry's canonical line: `format_line` over its serialized value.
pub fn canonical_line(entry: &AuditEntry) -> Vec<u8> {
    format_line(&serde_json::to_value(entry).expect("an audit entry serializes"))
}

/// The entry's own hash — `sha256:<hex>` over the canonical line.
pub fn entry_hash(entry: &AuditEntry) -> String {
    digest_of(&canonical_line(entry))
}

/// `aud_NNNNN`, N = entries so far + 1 — the first commit is `aud_00001`.
pub fn next_audit_id(entries_so_far: usize) -> String {
    format!("aud_{:05}", entries_so_far + 1)
}

/// `tx_` + 16 hex of sha256 over the audit id and plan id — deterministic,
/// so the same commit always names the same transaction.
pub fn transaction_id(audit_id: &str, plan_id: Option<&str>) -> String {
    let mut domain = audit_id.as_bytes().to_vec();
    domain.extend_from_slice(plan_id.unwrap_or("").as_bytes());
    format!("tx_{}", &sha256_hex(&domain)[..16])
}

/// `sha256:` over the canonical bytes of a request's `input`.
pub fn input_hash(input: &serde_json::Value) -> String {
    digest_of(&format_value(input))
}

/// Every raw line of the log, newline stripped. A missing log is an empty log.
pub fn read_lines(root: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let path = root.join(LOG_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.to_vec())
        .collect())
}

/// Append one canonical line (plus its newline) to the log. The append is
/// fsynced, and the containing directory after it — the commit protocol's
/// marker/temp/rename/append ordering only holds if each step is durable.
pub fn append_line(root: &Path, line: &[u8]) -> std::io::Result<()> {
    let path = root.join(LOG_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    file.write_all(line)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        crate::ir::writer::sync_dir(parent)?;
    }
    Ok(())
}

/// The point at which chain verification failed: the 0-based line index, the
/// entry's `audit_id` when it parsed, and the reason.
#[derive(Clone, PartialEq, Debug)]
pub struct ChainBreak {
    pub index: usize,
    pub audit_id: Option<String>,
    pub reason: String,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.audit_id {
            Some(id) => write!(f, "audit chain broken at {id}: {}", self.reason),
            None => write!(f, "audit chain broken at line {}: {}", self.index + 1, self.reason),
        }
    }
}

impl std::error::Error for ChainBreak {}

/// Verify the chain end to end and the manifest's `audit_head` against the
/// last line. Each line must be canonical compact form, carry `aud_{i+1:05}`,
/// and name the previous line's hash in `prev_hash` (genesis for the first).
/// Returns the parsed entries on success; the first failing line's index on a
/// break.
pub fn verify_chain(
    root: &Path,
    audit_head: Option<&AuditHead>,
) -> Result<Vec<AuditEntry>, ChainBreak> {
    let lines = read_lines(root).map_err(|e| ChainBreak {
        index: 0,
        audit_id: None,
        reason: format!("cannot read {LOG_FILE}: {e}"),
    })?;

    let mut entries = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let expected_id = next_audit_id(i);
        let entry: AuditEntry = serde_json::from_slice(line).map_err(|e| ChainBreak {
            index: i,
            audit_id: None,
            reason: format!("unparseable entry: {e}"),
        })?;
        if format_line(
            &serde_json::to_value(&entry).expect("an audit entry serializes"),
        ) != *line
        {
            return Err(ChainBreak {
                index: i,
                audit_id: Some(entry.audit_id.clone()),
                reason: "entry is not in canonical line form".into(),
            });
        }
        // Every recorded change target must stay inside the project: a forged
        // or corrupted line must not aim later renames outside the root.
        for change in &entry.changes {
            let inside = !change.path.as_str().is_empty()
                && std::path::Path::new(change.path.as_str())
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)));
            if !inside {
                return Err(ChainBreak {
                    index: i,
                    audit_id: Some(entry.audit_id.clone()),
                    reason: "entry records an out-of-project target".to_string(),
                });
            }
        }
        if entry.audit_id != expected_id {
            return Err(ChainBreak {
                index: i,
                audit_id: Some(entry.audit_id.clone()),
                reason: format!("audit_id out of sequence: expected {expected_id}"),
            });
        }
        let expected_prev = if i == 0 {
            GENESIS_PREV_HASH.to_string()
        } else {
            digest_of(&lines[i - 1])
        };
        if entry.prev_hash != expected_prev {
            return Err(ChainBreak {
                index: i,
                audit_id: Some(entry.audit_id.clone()),
                reason: format!(
                    "prev_hash mismatch: entry records {}, previous line hashes to {}",
                    entry.prev_hash, expected_prev
                ),
            });
        }
        entries.push(entry);
    }

    // The manifest's audit_head must name exactly the last line.
    match (audit_head, entries.last()) {
        (None, None) => Ok(entries),
        (Some(head), Some(last)) => {
            let last_hash = digest_of(&lines[lines.len() - 1]);
            if head.id == last.audit_id && head.hash == last_hash {
                Ok(entries)
            } else {
                Err(ChainBreak {
                    index: lines.len() - 1,
                    audit_id: Some(last.audit_id.clone()),
                    reason: format!(
                        "audit_head {} / {} does not match last entry {} / {}",
                        head.id, head.hash, last.audit_id, last_hash
                    ),
                })
            }
        }
        (Some(head), None) => Err(ChainBreak {
            index: 0,
            audit_id: Some(head.id.clone()),
            reason: "audit_head is set but the log is empty".into(),
        }),
        (None, Some(last)) => Err(ChainBreak {
            index: lines.len() - 1,
            audit_id: Some(last.audit_id.clone()),
            reason: "entries exist but audit_head is null".into(),
        }),
    }
}

/// The current time as RFC 3339 UTC — the only timestamp anywhere in the
/// project, and only ever inside an audit entry (ADR-0010).
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    rfc3339_from_unix(secs)
}

/// Convert seconds since the Unix epoch to `YYYY-MM-DDTHH:MM:SSZ`.
/// Howard Hinnant's days-from-civil algorithm; no dependency.
pub fn rfc3339_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let (hour, min, sec) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}
