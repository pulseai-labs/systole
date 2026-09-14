//! `rpg.reachability` — per region, a 4-neighbour BFS from the spawn tile over
//! the collision layer's walkable tiles (ADR-0012, ADR-0004): every placed NPC
//! and every warp tile must be reached, and a warp's destination region must
//! exist. Blocking findings carry `rpg.set_collision` fixes that are
//! pre-verified in memory (the fix contract): emitted only when applying the
//! request makes the finding disappear.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{json, Value};
use systole_core::finding::{finding_id, Finding, Location, Severity};
use systole_core::ir::project::Project;
use systole_core::ir::RelPath;
use systole_core::module::Validator;
use systole_core::op::PlanRequest;
use systole_core::registry::Registry;
use systole_core::validators::staged_apply;

use crate::ops::{fix_request, ordered};
use crate::schema;

pub const CODE_SPAWN_BLOCKED: &str = "rpg.reachability.spawn_blocked";
pub const CODE_UNREACHABLE_NPC: &str = "rpg.reachability.unreachable_npc";
pub const CODE_UNREACHABLE_WARP: &str = "rpg.reachability.unreachable_warp";
pub const CODE_ON_SOLID_TILE: &str = "rpg.placement.on_solid_tile";
pub const CODE_DANGLING_TARGET: &str = "rpg.warp.dangling_target";
/// A warp's explicit destination is inside a region that exists but cannot be
/// reached there — out-of-bounds or walled off from that region's spawn.
pub const CODE_UNREACHABLE_DESTINATION: &str = "rpg.warp.unreachable_destination";
/// A region declaring dimensions outside the module's bounds — refused
/// before any width-by-height grid is allocated.
pub const CODE_INVALID_DIMENSIONS: &str = "rpg.region.invalid_dimensions";

/// The validator carries the registry that materializes and applies its
/// suggested fixes — the fix contract needs the real dispatch path, not a
/// reimplementation.
pub struct Reachability {
    registry: Registry,
}

impl Reachability {
    pub fn new(registry: Registry) -> Self {
        Reachability { registry }
    }
}

/// One addressable object the walkable graph must reach: a region placement
/// or a warp tile.
struct Target {
    /// `placements[i]` or `warps[i]` — which array produced the target.
    is_warp: bool,
    /// The entity's / warp's own stable id.
    stable_id: String,
    at: (u32, u32),
    /// The entity's `id` handle (placements only).
    entity_id: Option<String>,
}

/// A region's walkable view: the collision layer's effective rows plus the
/// region body's spawn and targets.
/// One warp on a region: stable id, source tile, target handle, and the
/// optional landing point inside the target region.
type WarpView = (String, (u32, u32), String, Option<(u32, u32)>);

struct RegionView {
    stable_id: String,
    handle: String,
    path: RelPath,
    width: u32,
    height: u32,
    spawn: (u32, u32),
    solid: Vec<Vec<bool>>,
    targets: Vec<Target>,
    /// `(warp stable_id, at, to.region_id, to.at)` rows — the dangling check
    /// uses the region handle, the destination check the optional point.
    warps: Vec<WarpView>,
}

impl Validator for Reachability {
    fn id(&self) -> &'static str {
        "rpg.reachability"
    }

    fn run(&self, project: &Project) -> Vec<Finding> {
        self.run_inner(project, 0)
    }
}

impl Reachability {
    // The validator walk. depth bounds verified_fixes recursion: a
    // fix-check re-run produces findings only, keeping validate linear.
    fn run_inner(&self, project: &Project, depth: u32) -> Vec<Finding> {
        let (views, mut findings) = regions(project);
        let mut dest_reach: std::collections::BTreeMap<String, BTreeSet<(u32, u32)>> =
            std::collections::BTreeMap::new();
        for view in &views {
            let reached = bfs_reached(view);
            if solid_at(view, view.spawn) {
                let location = Location {
                    stable_id: Some(view.stable_id.clone()),
                    path: Some(view.path.clone()),
                };
                let evidence = json!({ "spawn": [view.spawn.0, view.spawn.1] });
                let fixes = self.verified_fixes(
                    project,
                    vec![collision_fix(&view.handle, view.spawn, 1, 1)],
                    CODE_SPAWN_BLOCKED,
                    &location,
                    &evidence,
                    depth,
                );
                findings.push(make(
                    CODE_SPAWN_BLOCKED,
                    true,
                    location,
                    with_message(evidence, fixes.is_empty()),
                    fixes,
                ));
            }
            for target in &view.targets {
                if inside(view, target.at)
                    && view.solid[target.at.1 as usize][target.at.0 as usize]
                {
                    let code = CODE_ON_SOLID_TILE;
                    let location = Location {
                        stable_id: Some(view.stable_id.clone()),
                        path: Some(view.path.clone()),
                    };
                    let evidence = target_evidence(target, view);
                    let fixes = self.verified_fixes(
                        project,
                        vec![collision_fix(&view.handle, target.at, 1, 1)],
                        code,
                        &location,
                        &evidence,
                        depth,
                    );
                    findings.push(make(
                        code,
                        false,
                        location,
                        with_message(evidence, fixes.is_empty()),
                        fixes,
                    ));
                }
                if !reached.contains(&target.at) {
                    let code = if target.is_warp {
                        CODE_UNREACHABLE_WARP
                    } else {
                        CODE_UNREACHABLE_NPC
                    };
                    let location = Location {
                        stable_id: Some(view.stable_id.clone()),
                        path: Some(view.path.clone()),
                    };
                    let evidence = reach_evidence(target, view, reached.len());
                    let candidates = repair_candidates(view, &reached, target.at);
                    let fixes =
                        self.verified_fixes(project, candidates, code, &location, &evidence, depth);
                    findings.push(make(
                        code,
                        true,
                        location,
                        with_message(evidence, fixes.is_empty()),
                        fixes,
                    ));
                }
            }
            for (warp_stable_id, at, target_region_id, dest_at) in &view.warps {
                // W4-A1: dangling iff no region carries the `to.region_id`
                // handle. The stored `to.region_stable_id` stays null after a
                // `create_region` fix (no Release 0 op rewrites a warp), so the
                // check is on the handle, not the stored id.
                if schema::find_region(project, target_region_id).is_none() {
                    let location = Location {
                        stable_id: Some(view.stable_id.clone()),
                        path: Some(view.path.clone()),
                    };
                    let evidence = json!({
                        "warp_stable_id": warp_stable_id,
                        "at": [at.0, at.1],
                        "target_region_id": target_region_id,
                    });
                    let fixes = self.verified_fixes(
                        project,
                        vec![fix_request(
                            "rpg.create_region",
                            json!({
                                "id": target_region_id,
                                "width": view.width,
                                "height": view.height,
                                "spawn": [view.spawn.0, view.spawn.1],
                            }),
                        )],
                        CODE_DANGLING_TARGET,
                        &location,
                        &evidence,
                        depth,
                    );
                    findings.push(make(
                        CODE_DANGLING_TARGET,
                        false,
                        location,
                        with_message(evidence, fixes.is_empty()),
                        fixes,
                    ));
                } else if let Some(dest) = dest_at {
                    // The destination must be a reachable landing inside the
                    // resolved region — out-of-bounds or walled off from that
                    // region's spawn. Advisory: no Release 0 op rewrites a warp.
                    if let Some(dest_view) = views.iter().find(|v| v.handle == *target_region_id)
                    {
                        let dest_reached = dest_reach
                            .entry(target_region_id.clone())
                            .or_insert_with(|| bfs_reached(dest_view));
                        if !dest_reached.contains(dest) {
                            let location = Location {
                                stable_id: Some(view.stable_id.clone()),
                                path: Some(view.path.clone()),
                            };
                            findings.push(make(
                                CODE_UNREACHABLE_DESTINATION,
                                false,
                                location,
                                with_message(
                                    json!({
                                        "warp_stable_id": warp_stable_id,
                                        "at": [at.0, at.1],
                                        "target_region_id": target_region_id,
                                        "destination_at": [dest.0, dest.1],
                                    }),
                                    true,
                                ),
                                Vec::new(),
                            ));
                        }
                    }
                }
            }
        }
        ordered(findings)
    }
}

impl Reachability {
    /// The fix contract: keep only the candidates whose staged application
    /// makes this finding absent on re-run, preserving candidate order.
    /// Identity ignores `reached`/`message` — they vary with the state the
    /// validator observes, not with the condition being flagged.
    fn verified_fixes(
        &self,
        project: &Project,
        candidates: Vec<PlanRequest>,
        code: &str,
        location: &Location,
        evidence: &Value,
        depth: u32,
    ) -> Vec<PlanRequest> {
        if depth != 0 {
            return Vec::new();
        }
        let target = identity(code, location, evidence);
        candidates
            .into_iter()
            .filter(|req| {
                staged_apply(project, &self.registry, req)
                    .map(|staged| {
                        !self
                            .run_inner(&staged, depth + 1)
                            .iter()
                            .any(|f| identity(&f.code, &f.location, &f.evidence) == target)
                    })
                    .unwrap_or(false)
            })
            .collect()
    }
}

/// What makes a finding "the same condition" across project states: code,
/// location, and evidence minus the state-dependent keys.
fn identity(code: &str, location: &Location, evidence: &Value) -> Value {
    let mut e = evidence.clone();
    if let Some(map) = e.as_object_mut() {
        map.remove("reached");
        map.remove("message");
    }
    json!([
        code,
        serde_json::to_value(location).unwrap_or(Value::Null),
        e
    ])
}

/// `rpg.set_collision` on a rectangle — the only collision fix the kernel
/// surface can propose.
fn collision_fix(handle: &str, at: (u32, u32), w: u32, h: u32) -> PlanRequest {
    fix_request(
        "rpg.set_collision",
        json!({
            "region": handle,
            "x": at.0,
            "y": at.1,
            "w": w,
            "h": h,
            "solid": false,
        }),
    )
}

fn make(
    code: &str,
    blocking: bool,
    location: Location,
    evidence: Value,
    suggested_fixes: Vec<PlanRequest>,
) -> Finding {
    Finding {
        finding_id: finding_id(code, &location, &evidence),
        code: code.to_string(),
        severity: if blocking {
            Severity::Error
        } else {
            Severity::Warning
        },
        location,
        evidence,
        suggested_fixes,
        blocking,
    }
}

/// When no candidate verifies, the fix contract requires a `message` in
/// evidence saying the kernel cannot repair this state (reachable only
/// through out-of-band edits).
fn with_message(mut evidence: Value, unfixable: bool) -> Value {
    if unfixable
        && let Some(map) = evidence.as_object_mut()
    {
        map.insert(
            "message".to_string(),
            json!(
                "no suggested fix verified: this state cannot be repaired by a \
                 single Release 0 operation — repair by hand or via `systole project doctor`"
            ),
        );
    }
    evidence
}

fn target_evidence(target: &Target, view: &RegionView) -> Value {
    let mut evidence = json!({
        "stable_id": target.stable_id,
        "at": [target.at.0, target.at.1],
        "spawn": [view.spawn.0, view.spawn.1],
    });
    if let Some(id) = &target.entity_id {
        evidence["entity_id"] = json!(id);
    }
    if target.is_warp {
        evidence["warp_stable_id"] = evidence["stable_id"].take();
    }
    evidence
}

fn reach_evidence(target: &Target, view: &RegionView, reached: usize) -> Value {
    let mut evidence = target_evidence(target, view);
    evidence["reached"] = json!(reached);
    evidence
}

/// Every `regions/<sid>/region.json` whose `kind` is `region`, in path order
/// (the project's BTreeMap keeps the walk deterministic).
fn regions(project: &Project) -> (Vec<RegionView>, Vec<Finding>) {
    let mut out = Vec::new();
    let mut invalid = Vec::new();
    for (path, value) in &project.files {
        let segs: Vec<&str> = path.as_str().split('/').collect();
        let ["regions", sid, "region.json"] = segs.as_slice() else {
            continue;
        };
        if value.get("kind").and_then(Value::as_str) != Some("region") {
            continue;
        }
        let (width, height) = schema::region_size(value);
        // A hand-edited or imported region can declare dimensions far past
        // MAX_REGION_DIMENSION — refuse it with a blocking finding rather
        // than allocating a width-by-height grid (memory exhaustion).
        if width == 0
            || height == 0
            || width > schema::MAX_REGION_DIMENSION
            || height > schema::MAX_REGION_DIMENSION
        {
            invalid.push(make(
                CODE_INVALID_DIMENSIONS,
                true,
                Location {
                    stable_id: Some(sid.to_string()),
                    path: Some(path.clone()),
                },
                with_message(
                    json!({
                        "width": width,
                        "height": height,
                        "max": schema::MAX_REGION_DIMENSION,
                    }),
                    true,
                ),
                Vec::new(),
            ));
            continue;
        }
        let spawn = point(value.get("spawn")).unwrap_or((0, 0));
        let collision = project
            .files
            .get(&schema::collision_path(sid))
            .cloned()
            .unwrap_or(Value::Null);
        let rows: Vec<Vec<bool>> = collision["rows"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|r| {
                        r.as_str()
                            .unwrap_or_default()
                            .chars()
                            .map(|c| c == '#')
                            .collect()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut solid = vec![vec![true; width as usize]; height as usize];
        for (y, row) in rows.iter().enumerate().take(height as usize) {
            for (x, s) in row.iter().enumerate().take(width as usize) {
                solid[y][x] = *s;
            }
        }
        let mut targets = Vec::new();
        if let Some(placements) = value.get("placements").and_then(Value::as_array) {
            for placement in placements {
                let Some(at) = point(placement.get("at")) else {
                    continue;
                };
                let stable_id = placement
                    .get("stable_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let entity_id = schema::find_entity_by_stable_id(project, &stable_id)
                    .and_then(|e| e.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                targets.push(Target {
                    is_warp: false,
                    stable_id,
                    at,
                    entity_id,
                });
            }
        }
        let mut warps = Vec::new();
        if let Some(entries) = value.get("warps").and_then(Value::as_array) {
            for warp in entries {
                let Some(at) = point(warp.get("at")) else {
                    continue;
                };
                let stable_id = warp
                    .get("stable_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if let Some(target_region_id) = warp
                    .get("to")
                    .and_then(|to| to.get("region_id"))
                    .and_then(Value::as_str)
                {
                    let dest_at = warp
                        .get("to")
                        .and_then(|to| to.get("at"))
                        .and_then(|v| point(Some(v)));
                    warps.push((stable_id.clone(), at, target_region_id.to_string(), dest_at));
                }
                targets.push(Target {
                    is_warp: true,
                    stable_id,
                    at,
                    entity_id: None,
                });
            }
        }
        out.push(RegionView {
            stable_id: sid.to_string(),
            handle: value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            path: path.clone(),
            width,
            height,
            spawn,
            solid,
            targets,
            warps,
        });
    }
    (out, invalid)
}

fn point(value: Option<&Value>) -> Option<(u32, u32)> {
    let a = value?.as_array()?;
    Some((
        a.first()?.as_u64()? as u32,
        a.get(1)?.as_u64()? as u32,
    ))
}

fn inside(view: &RegionView, tile: (u32, u32)) -> bool {
    tile.0 < view.width && tile.1 < view.height
}

fn solid_at(view: &RegionView, tile: (u32, u32)) -> bool {
    !inside(view, tile) || view.solid[tile.1 as usize][tile.0 as usize]
}

/// The tiles a 4-neighbour flood from the spawn reaches over walkable tiles;
/// empty when the spawn tile is solid or out of bounds.
fn bfs_reached(view: &RegionView) -> BTreeSet<(u32, u32)> {
    let mut reached = BTreeSet::new();
    if solid_at(view, view.spawn) {
        return reached;
    }
    let mut queue = VecDeque::from([view.spawn]);
    reached.insert(view.spawn);
    while let Some(tile) = queue.pop_front() {
        for next in neighbours(view, tile) {
            if !view.solid[next.1 as usize][next.0 as usize] && reached.insert(next) {
                queue.push_back(next);
            }
        }
    }
    reached
}

fn neighbours(view: &RegionView, tile: (u32, u32)) -> Vec<(u32, u32)> {
    let mut out = Vec::with_capacity(4);
    if tile.0 > 0 {
        out.push((tile.0 - 1, tile.1));
    }
    if tile.1 > 0 {
        out.push((tile.0, tile.1 - 1));
    }
    if tile.0 + 1 < view.width {
        out.push((tile.0 + 1, tile.1));
    }
    if tile.1 + 1 < view.height {
        out.push((tile.0, tile.1 + 1));
    }
    out
}

/// The repair corridor candidates for an unreachable target, most specific
/// first (W4-A2): the **door** — the first solid tile of a minimal-cost path
/// that is adjacent to the reached set (or the target tile itself when the
/// target is solid) — then the **breach** — the bounding rectangle of the
/// path's solid tiles — only when it differs from the door. Pre-verification
/// in `verified_fixes` drops whichever does not clear the finding.
fn repair_candidates(
    view: &RegionView,
    reached: &BTreeSet<(u32, u32)>,
    target: (u32, u32),
) -> Vec<PlanRequest> {
    if reached.is_empty() || !inside(view, target) {
        return Vec::new();
    }
    let Some(path) = minimal_path(view, reached, target) else {
        return Vec::new();
    };
    let solids: Vec<(u32, u32)> = path
        .iter()
        .copied()
        .filter(|t| view.solid[t.1 as usize][t.0 as usize])
        .collect();
    let mut requests = Vec::new();

    // (1) The door.
    let door = if view.solid[target.1 as usize][target.0 as usize] {
        Some(target)
    } else {
        path.iter().copied().find(|t| {
            view.solid[t.1 as usize][t.0 as usize]
                && neighbours(view, *t).iter().any(|n| reached.contains(n))
        })
    };
    if let Some(tile) = door {
        requests.push(collision_fix(&view.handle, tile, 1, 1));
    }

    // (2) The breach — only when it differs from the door.
    if !solids.is_empty() {
        let min_x = solids.iter().map(|t| t.0).min().unwrap_or(0);
        let max_x = solids.iter().map(|t| t.0).max().unwrap_or(0);
        let min_y = solids.iter().map(|t| t.1).min().unwrap_or(0);
        let max_y = solids.iter().map(|t| t.1).max().unwrap_or(0);
        let breach = collision_fix(
            &view.handle,
            (min_x, min_y),
            max_x - min_x + 1,
            max_y - min_y + 1,
        );
        if requests.first().map(|d| d.input != breach.input).unwrap_or(true) {
            requests.push(breach);
        }
    }
    requests
}

/// A minimal-cost path from the reached set to `target`, as the list of tiles
/// strictly outside the reached set ending at `target`. 0-1 BFS: entering a
/// solid tile costs 1, a walkable one 0, so the path crosses as few walls as
/// possible. Deterministic: reached seeds and neighbours are visited in
/// sorted order and the first minimal parent wins.
fn minimal_path(
    view: &RegionView,
    reached: &BTreeSet<(u32, u32)>,
    target: (u32, u32),
) -> Option<Vec<(u32, u32)>> {
    let mut dist: BTreeMap<(u32, u32), u64> = BTreeMap::new();
    let mut parent: BTreeMap<(u32, u32), (u32, u32)> = BTreeMap::new();
    let mut deque = VecDeque::new();
    for &seed in reached {
        dist.insert(seed, 0);
        deque.push_back(seed);
    }
    while let Some(tile) = deque.pop_front() {
        let base = dist[&tile];
        for next in neighbours(view, tile) {
            let cost = base + u64::from(view.solid[next.1 as usize][next.0 as usize]);
            if dist.get(&next).is_none_or(|d| cost < *d) {
                dist.insert(next, cost);
                parent.insert(next, tile);
                if view.solid[next.1 as usize][next.0 as usize] {
                    deque.push_back(next);
                } else {
                    deque.push_front(next);
                }
            }
        }
    }
    if reached.contains(&target) || !dist.contains_key(&target) {
        return None;
    }
    let mut path = Vec::new();
    let mut cur = target;
    while !reached.contains(&cur) {
        path.push(cur);
        cur = *parent.get(&cur)?;
    }
    path.reverse();
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use systole_core::ir::lock::Lock;
    use systole_core::ir::manifest::{Engine, Manifest, ModuleEntry};
    use systole_core::module::Module;
    use systole_core::validators::staged_apply;
    use crate::RpgModule;

    fn validator() -> Reachability {
        let mut registry = Registry::new();
        RpgModule.register(&mut registry);
        Reachability::new(registry)
    }

    fn project(files: Vec<(String, Value)>) -> Project {
        let engine = Engine {
            name: "systole".into(),
            version: "0.1.0".into(),
        };
        Project {
            root: PathBuf::new(),
            manifest: Manifest {
                engine: engine.clone(),
                project_schema: 1,
                modules: BTreeMap::from([(
                    "systole.rpg".to_string(),
                    ModuleEntry {
                        version: "0.1.0".into(),
                        schema: 1,
                    },
                )]),
                stable_id_counter: 3,
                project_revision: "rev_00000".into(),
                project_hash: "sha256:test".into(),
                audit_head: None,
                files: BTreeMap::new(),
            },
            lock: Lock {
                engine,
                modules: BTreeMap::new(),
            },
            files: files
                .into_iter()
                .map(|(p, v)| (RelPath::new(p), v))
                .collect(),
        }
    }

    /// The outline tiles of the `[x, x+w) × [y, y+h)` rect.
    fn ring(x: u32, y: u32, w: u32, h: u32) -> BTreeSet<(u32, u32)> {
        schema::rect_tiles(x, y, w, 1)
            .union(&schema::rect_tiles(x, y + h - 1, w, 1))
            .copied()
            .collect::<BTreeSet<_>>()
            .union(&schema::rect_tiles(x, y + 1, 1, h - 2))
            .copied()
            .collect::<BTreeSet<_>>()
            .union(&schema::rect_tiles(x + w - 1, y + 1, 1, h - 2))
            .copied()
            .collect()
    }

    /// A 16×16 grass `town` (region_00001, spawn (1,1)) whose collision layer
    /// carries `solid` overrides on `walls`. `npc_at` places `elder`
    /// (ent_00002); `warp` adds `warp_00003` → `to_region` at `warp_at`.
    fn town(
        walls: &BTreeSet<(u32, u32)>,
        npc_at: Option<(u32, u32)>,
        warp: Option<((u32, u32), &str)>,
    ) -> Project {
        let terrain = schema::terrain_file(16, 16, schema::Terrain::Grass);
        let mut collision = schema::collision_file(16, 16, &terrain);
        for &(x, y) in walls {
            schema::apply_collision_override(&mut collision, x, y, 1, 1, true).unwrap();
        }
        let mut region = schema::region_file("town", "region_00001", 16, 16, [1, 1]);
        if let Some(at) = npc_at {
            region["placements"]
                .as_array_mut()
                .unwrap()
                .push(json!({"stable_id": "ent_00002", "at": [at.0, at.1], "facing": "down"}));
        }
        if let Some((at, to_region)) = warp {
            region["warps"].as_array_mut().unwrap().push(json!({
                "stable_id": "warp_00003",
                "at": [at.0, at.1],
                "to": {"region_id": to_region, "region_stable_id": null, "at": null},
            }));
        }
        let mut files = vec![
            ("regions/region_00001/region.json".to_string(), region),
            (
                "regions/region_00001/layers/terrain.json".to_string(),
                terrain,
            ),
            (
                "regions/region_00001/layers/collision.json".to_string(),
                collision,
            ),
        ];
        if npc_at.is_some() {
            files.push((
                "entities/npc/ent_00002.json".to_string(),
                schema::npc_file(
                    "elder",
                    "ent_00002",
                    &[],
                    "",
                    &[],
                    None,
                    schema::Facing::Down,
                ),
            ));
        }
        project(files)
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.code.as_str()).collect()
    }

    #[test]
    fn an_open_town_is_clean() {
        let findings = validator().run(&town(&BTreeSet::new(), Some((5, 5)), None));
        assert!(findings.is_empty(), "unexpected: {findings:?}");
    }

    #[test]
    fn an_npc_inside_a_closed_ring_gets_a_verified_door_fix() {
        let p = town(&ring(4, 4, 3, 3), Some((5, 5)), None);
        let v = validator();
        let findings = v.run(&p);
        assert_eq!(codes(&findings), vec![CODE_UNREACHABLE_NPC]);
        let f = &findings[0];
        assert!(f.blocking);
        assert_eq!(f.suggested_fixes.len(), 1);
        let fix = &f.suggested_fixes[0];
        assert_eq!(fix.op_id, "rpg.set_collision");
        assert_eq!(fix.input["w"], 1);
        assert_eq!(fix.input["h"], 1);
        assert_eq!(fix.input["solid"], false);
        // The emitted fix was pre-verified; applying it in memory clears the
        // finding.
        let staged = staged_apply(&p, &v.registry, fix).unwrap();
        assert!(!v
            .run(&staged)
            .iter()
            .any(|g| g.code == CODE_UNREACHABLE_NPC));
    }

    #[test]
    fn a_two_thick_wall_yields_the_breach_fix() {
        // A solid 5×5 block with only the centre tile open — the ring around
        // it is two tiles thick on every side.
        let walls: BTreeSet<(u32, u32)> = schema::rect_tiles(4, 4, 5, 5)
            .difference(&schema::rect_tiles(6, 6, 1, 1))
            .copied()
            .collect();
        let p = town(&walls, Some((6, 6)), None);
        let v = validator();
        let findings = v.run(&p);
        assert_eq!(codes(&findings), vec![CODE_UNREACHABLE_NPC]);
        let fixes = &findings[0].suggested_fixes;
        // A one-tile door cannot cross two tiles of wall; the breach rect
        // covers the minimal path's solid span (1×2 or 2×1).
        assert_eq!(fixes.len(), 1);
        let fix = &fixes[0];
        let (w, h) = (
            fix.input["w"].as_u64().unwrap(),
            fix.input["h"].as_u64().unwrap(),
        );
        assert!(w == 2 || h == 2, "breach must span two solid tiles: {fix:?}");
        let staged = staged_apply(&p, &v.registry, fix).unwrap();
        assert!(!v
            .run(&staged)
            .iter()
            .any(|g| g.code == CODE_UNREACHABLE_NPC));
    }

    #[test]
    fn a_warp_destination_point_is_checked_for_reachability() {
        // route_1 (region_00002, 4x4 grass) with a single solid tile at (3,3);
        // town's warp lands exactly there.
        let terrain = schema::terrain_file(4, 4, schema::Terrain::Grass);
        let mut collision = schema::collision_file(4, 4, &terrain);
        schema::apply_collision_override(&mut collision, 3, 3, 1, 1, true).unwrap();
        let mut p = town(&BTreeSet::new(), None, None);
        p.files.insert(
            RelPath::new("regions/region_00002/region.json"),
            schema::region_file("route_1", "region_00002", 4, 4, [1, 1]),
        );
        p.files.insert(
            RelPath::new("regions/region_00002/layers/terrain.json"),
            terrain,
        );
        p.files.insert(
            RelPath::new("regions/region_00002/layers/collision.json"),
            collision,
        );
        p.files
            .get_mut(&RelPath::new("regions/region_00001/region.json"))
            .unwrap()["warps"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "stable_id": "warp_00003",
                "at": [15, 8],
                "to": {"region_id": "route_1", "region_stable_id": "region_00002", "at": [3, 3]}
            }));
        let findings = validator().run(&p);
        assert_eq!(codes(&findings), vec![CODE_UNREACHABLE_DESTINATION]);
        assert!(
            !findings[0].blocking,
            "an unreachable destination stays advisory"
        );
    }

    #[test]
    fn a_spawn_on_a_wall_is_blocking_with_a_one_tile_fix() {
        let p = town(&BTreeSet::from([(1, 1)]), Some((5, 5)), None);
        let findings = validator().run(&p);
        let spawn = findings
            .iter()
            .find(|f| f.code == CODE_SPAWN_BLOCKED)
            .expect("spawn_blocked");
        assert!(spawn.blocking);
        assert_eq!(spawn.suggested_fixes.len(), 1);
        assert_eq!(spawn.suggested_fixes[0].input["x"], 1);
        assert_eq!(spawn.suggested_fixes[0].input["y"], 1);
    }

    #[test]
    fn a_warp_behind_a_wall_is_unreachable() {
        let p = town(&ring(4, 4, 3, 3), None, Some(((5, 5), "route_1")));
        let findings = validator().run(&p);
        let warp = findings
            .iter()
            .find(|f| f.code == CODE_UNREACHABLE_WARP)
            .expect("unreachable_warp");
        assert!(warp.blocking);
        assert!(!warp.suggested_fixes.is_empty());
    }

    #[test]
    fn a_dangling_warp_target_is_non_blocking_with_a_create_region_fix() {
        let p = town(&BTreeSet::new(), None, Some(((15, 8), "route_1")));
        let findings = validator().run(&p);
        assert_eq!(codes(&findings), vec![CODE_DANGLING_TARGET]);
        let f = &findings[0];
        assert!(!f.blocking);
        let fix = &f.suggested_fixes[0];
        assert_eq!(fix.op_id, "rpg.create_region");
        assert_eq!(fix.input["id"], "route_1");
        // The fix carries the source region's dimensions and spawn.
        assert_eq!(fix.input["width"], 16);
        assert_eq!(fix.input["height"], 16);
        assert_eq!(fix.input["spawn"], json!([1, 1]));
        let staged = staged_apply(&p, &validator().registry, fix).unwrap();
        assert!(validator().run(&staged).is_empty());
    }

    #[test]
    fn findings_are_sorted_by_finding_id() {
        // A walled NPC plus a dangling warp produce several findings at once.
        let p = town(&ring(4, 4, 3, 3), Some((5, 5)), Some(((15, 8), "route_1")));
        let findings = validator().run(&p);
        let ids: Vec<&str> = findings.iter().map(|f| f.finding_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
        let unique: BTreeSet<&&str> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "finding ids are unique");
        assert!(codes(&findings).contains(&CODE_UNREACHABLE_NPC));
        assert!(codes(&findings).contains(&CODE_DANGLING_TARGET));
    }

    #[test]
    fn every_emitted_fix_clears_its_own_finding() {
        // Property: across a family of generated rings, every suggested fix
        // is pre-verified — staged-apply it and its finding is gone.
        for (x, y, w, h) in [(4, 4, 3, 3), (2, 2, 4, 4), (8, 8, 5, 3)] {
            let p = town(&ring(x, y, w, h), Some((x + 1, y + 1)), None);
            let v = validator();
            for f in v.run(&p) {
                for fix in &f.suggested_fixes {
                    let staged = staged_apply(&p, &v.registry, fix)
                        .expect("a suggested fix always materializes and applies");
                    let id = identity(&f.code, &f.location, &f.evidence);
                    assert!(
                        !v.run(&staged)
                            .iter()
                            .any(|g| identity(&g.code, &g.location, &g.evidence) == id),
                        "fix did not clear {} on ring {x},{y} {w}x{h}",
                        f.code
                    );
                }
            }
        }
    }
}
