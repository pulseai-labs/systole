//! The seven `rpg.*` operations (ADR-0012's final Release-0 set): six writes
//! and one read, all version 1, `Stability::Experimental`.

pub mod create_region;
pub mod mark_warp;
pub mod paint_area;
pub mod paint_path;
pub mod place_npc;
pub mod query_region;
pub mod set_collision;

use std::collections::BTreeSet;

use serde_json::Value;
use systole_core::finding::{finding_id, Finding, Location, Severity};
use systole_core::ids::{IdKind, StableId};
use systole_core::ir::project::Project;
use systole_core::ir::RelPath;
use systole_core::op::{Diff, FileChange, OpError, PlanRequest};
use systole_core::tx::Transaction;

use crate::schema;

/// Request-error codes (`OpError::InvalidRequest`, exit 2 at the CLI) and
/// finding codes this module can emit (ADR-0004).
pub(crate) mod codes {
    pub const REGION_NOT_FOUND: &str = "rpg.region.not_found";
    pub const REGION_INVALID_ID: &str = "rpg.region.invalid_id";
    pub const ENTITY_INVALID_ID: &str = "rpg.entity.invalid_id";
    pub const RECT_OUT_OF_BOUNDS: &str = "spatial.rect_out_of_bounds";
    pub const POINT_OUT_OF_BOUNDS: &str = "spatial.point_out_of_bounds";
    pub const UNKNOWN_TERRAIN: &str = "rpg.terrain.unknown_kind";

    pub const REGION_DUPLICATE_ID: &str = "rpg.region.duplicate_id";
    pub const ENTITY_DUPLICATE_ID: &str = "rpg.entity.duplicate_id";
    pub const PLACEMENT_ON_SOLID: &str = "rpg.placement.on_solid_tile";
    pub const WARP_DANGLING_TARGET: &str = "rpg.warp.dangling_target";
    pub const WARP_DUPLICATE_TILE: &str = "rpg.warp.duplicate_tile";
}

/// A request error carrying its machine-readable code: `"<code>: <message>"`.
pub(crate) fn invalid(code: &str, message: impl std::fmt::Display) -> OpError {
    OpError::InvalidRequest(format!("{code}: {message}"))
}

/// A suggested fix is a PlanRequest for a kernel op (ADR-0004). The actor is
/// the module id until the engine's `plan --from-finding` rewrites it to the
/// invoking actor (w4 note).
pub(crate) fn fix_request(op_id: &str, input: Value) -> PlanRequest {
    PlanRequest {
        op_id: op_id.to_string(),
        op_version: 1,
        input,
        actor: "systole.rpg".to_string(),
    }
}

/// Build a finding whose `finding_id` is deterministic (ADR-0010): the first
/// 16 hex of sha256 over the canonical bytes of `{code, location, evidence}` —
/// the shared `systole_core::finding::finding_id` formula.
pub(crate) fn make_finding(
    code: &str,
    severity: Severity,
    blocking: bool,
    stable_id: Option<String>,
    path: Option<RelPath>,
    evidence: Value,
    suggested_fixes: Vec<PlanRequest>,
) -> Finding {
    let location = Location { stable_id, path };
    let id = finding_id(code, &location, &evidence);
    Finding {
        finding_id: id,
        code: code.to_string(),
        severity,
        location,
        evidence,
        suggested_fixes,
        blocking,
    }
}

/// Findings ordered by `finding_id` so output diffs cleanly (ADR-0010).
pub(crate) fn ordered(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    findings
}

/// The stable id the next `Transaction::alloc_id` will issue for `kind` —
/// the shared counter only advances at commit, and a plan is bound to its
/// base revision, so `counter + 1` is a sound prediction for `diff`.
pub(crate) fn predicted_id(project: &Project, kind: IdKind) -> String {
    StableId::new(kind, project.manifest.stable_id_counter + 1).to_string()
}

/// Assemble a `Diff` from the `(path, after)` writes an apply will stage;
/// `before` is the project's current value at each path. No-op writes —
/// where the after-image equals the value already on disk — are filtered
/// out: `stage_if_changed` stages nothing for them, so emitting them here
/// would make the preview claim changes the commit never makes.
pub(crate) fn diff_of(project: &Project, writes: Vec<(RelPath, Value)>) -> Diff {
    Diff {
        changes: writes
            .into_iter()
            .filter_map(|(path, after)| {
                let before = project.files.get(&path).cloned();
                (before.as_ref() != Some(&after)).then_some(FileChange {
                    before,
                    path,
                    after: Some(after),
                })
            })
            .collect(),
    }
}

/// Resolve a region handle to `(stable_id, region value)`, or the
/// `rpg.region.not_found` request error.
pub(crate) fn require_region<'p>(
    project: &'p Project,
    handle: &str,
) -> Result<(String, &'p Value), OpError> {
    schema::find_region(project, handle).ok_or_else(|| {
        invalid(
            codes::REGION_NOT_FOUND,
            format!("no region with id {handle:?}"),
        )
    })
}

/// Stage `after` at `path` only when it differs from the transaction's
/// current view — a no-op apply stages nothing.
pub(crate) fn stage_if_changed(tx: &mut Transaction, path: RelPath, after: Value) {
    if tx.read(&path) != Some(&after) {
        tx.write(path, after);
    }
}

/// Compute the writes of a terrain paint: the terrain file with `tiles` set
/// to `kind`'s glyph, and the collision file recomputed over them. `read`
/// views the pre-apply state — `Project::files.get` in diff,
/// `Transaction::read` in apply — so both phases compute the same
/// after-images. Returns the writes and the count of tiles whose glyph
/// actually changed.
pub(crate) fn paint_writes<'a>(
    read: impl Fn(&RelPath) -> Option<&'a Value>,
    region_stable_id: &str,
    tiles: &BTreeSet<(u32, u32)>,
    kind: schema::Terrain,
    mk_err: fn(String) -> OpError,
) -> Result<(Vec<(RelPath, Value)>, u64), OpError> {
    let terrain_path = schema::terrain_path(region_stable_id);
    let collision_path = schema::collision_path(region_stable_id);
    let mut terrain = read(&terrain_path).cloned().ok_or_else(|| {
        mk_err(format!("region {region_stable_id} lacks {terrain_path}"))
    })?;
    let mut collision = read(&collision_path).cloned().ok_or_else(|| {
        mk_err(format!("region {region_stable_id} lacks {collision_path}"))
    })?;
    let changed = schema::paint_terrain(&mut terrain, tiles, kind);
    schema::recompute_collision(&mut collision, &terrain, tiles);
    Ok((vec![(terrain_path, terrain), (collision_path, collision)], changed))
}
