//! `rpg.mark_warp` — mark a warp tile on a region; the destination region may
//! not exist yet (towns are built incrementally).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use systole_core::capability::Capability;
use systole_core::finding::{Finding, Severity};
use systole_core::ids::IdKind;
use systole_core::ir::project::Project;
use systole_core::op::{Diff, Mutability, Operation, OperationDescription, OpError, Stability};
use systole_core::tx::Transaction;

use super::{
    codes, diff_of, fix_request, invalid, make_finding, ordered, predicted_id, require_region,
};
use crate::schema;

#[derive(Default)]
pub struct MarkWarp;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct WarpTarget {
    /// The destination region's handle.
    pub region: String,
    #[serde(default)]
    pub at: Option<[u32; 2]>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MarkWarpRequest {
    pub region: String,
    pub at: [u32; 2],
    pub to: WarpTarget,
}

/// The replayable plan: both handles resolved — `to.region` to its stable id
/// when a region with that handle exists, `null` when it does not.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MarkWarpPlan {
    pub region: String,
    pub region_stable_id: String,
    pub at: [u32; 2],
    pub to: ResolvedWarpTarget,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ResolvedWarpTarget {
    pub region_id: String,
    pub region_stable_id: Option<String>,
    pub at: Option<[u32; 2]>,
}

#[derive(Serialize, JsonSchema)]
pub struct MarkWarpOutput {
    pub stable_id: String,
}

impl Operation for MarkWarp {
    type Request = MarkWarpRequest;
    type Plan = MarkWarpPlan;
    type Output = MarkWarpOutput;

    const ID: &'static str = "rpg.mark_warp";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Experimental;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "mark a warp tile on a region pointing at a destination region".into(),
            input_schema: schemars::schema_for!(MarkWarpRequest),
            example: json!({"region": "town", "at": [15, 8], "to": {"region": "route_1", "at": [1, 8]}}),
            avoid_when: vec!["a warp already sits on that tile — remove or move it instead".into()],
        }
    }

    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError> {
        if !schema::valid_handle(&req.to.region) {
            return Err(invalid(
                codes::REGION_INVALID_ID,
                format!("target region id {:?} must match [a-z][a-z0-9_]*", req.to.region),
            ));
        }
        Ok(())
    }

    fn materialize(&self, project: &Project, req: Self::Request) -> Result<Self::Plan, OpError> {
        let (stable_id, region) = require_region(project, &req.region)?;
        let (width, height) = schema::region_size(region);
        if !schema::point_inside(req.at[0], req.at[1], width, height) {
            return Err(invalid(
                codes::POINT_OUT_OF_BOUNDS,
                format!(
                    "point ({},{}) is outside region {:?} bounds {}x{}",
                    req.at[0], req.at[1], req.region, width, height
                ),
            ));
        }
        let target_stable_id = schema::find_region(project, &req.to.region).map(|(sid, _)| sid);
        Ok(MarkWarpPlan {
            region: req.region,
            region_stable_id: stable_id,
            at: req.at,
            to: ResolvedWarpTarget {
                region_id: req.to.region,
                region_stable_id: target_stable_id,
                at: req.to.at,
            },
        })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let warp_stable_id = predicted_id(project, IdKind::Warp);
        let region_path = schema::region_path(&plan.region_stable_id);
        let mut region = project.files.get(&region_path).cloned().ok_or_else(|| {
            OpError::Diff(format!("region {} lacks {region_path}", plan.region_stable_id))
        })?;
        push_warp(&mut region, &warp_stable_id, plan, OpError::Diff)?;
        Ok(diff_of(project, vec![(region_path, region)]))
    }

    fn validate(&self, project: &Project, plan: &Self::Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        let region_path = schema::region_path(&plan.region_stable_id);
        if let Some(region) = project.files.get(&region_path) {
            if let Some(warps) = region["warps"].as_array() {
                for warp in warps {
                    let same_tile = warp["at"]
                        .as_array()
                        .and_then(|a| {
                            Some((
                                a.first()?.as_u64()? as u32,
                                a.get(1)?.as_u64()? as u32,
                            ))
                        })
                        == Some((plan.at[0], plan.at[1]));
                    if same_tile {
                        findings.push(make_finding(
                            codes::WARP_DUPLICATE_TILE,
                            Severity::Error,
                            true,
                            warp["stable_id"].as_str().map(str::to_string),
                            Some(region_path.clone()),
                            json!({ "at": plan.at, "existing_warp": warp["stable_id"] }),
                            Vec::new(),
                        ));
                    }
                }
            }
        }
        if plan.to.region_stable_id.is_none() {
            // The suggested fix must replay as-is: `rpg.create_region`
            // requires width and height, so it proposes the source region's
            // dimensions as the starting size for the unbuilt destination.
            let (w, h) = project
                .files
                .get(&region_path)
                .map(schema::region_size)
                .unwrap_or((16, 16));
            findings.push(make_finding(
                codes::WARP_DANGLING_TARGET,
                Severity::Warning,
                false,
                Some(plan.region_stable_id.clone()),
                Some(region_path),
                json!({ "at": plan.at, "target_region_id": plan.to.region_id }),
                vec![fix_request(
                    "rpg.create_region",
                    json!({ "id": plan.to.region_id, "width": w, "height": h }),
                )],
            ));
        }
        ordered(findings)
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let warp_stable_id = tx.alloc_id(IdKind::Warp).to_string();
        let region_path = schema::region_path(&plan.region_stable_id);
        let mut region = tx.read(&region_path).cloned().ok_or_else(|| {
            OpError::Apply(format!("region {} lacks {region_path}", plan.region_stable_id))
        })?;
        push_warp(&mut region, &warp_stable_id, &plan, OpError::Apply)?;
        tx.write(region_path, region);
        Ok(MarkWarpOutput {
            stable_id: warp_stable_id,
        })
    }
}

/// Append `{stable_id, at, to}` to the region's `warps`. `to` carries the
/// target handle and its resolved stable id (`null` while the target is
/// unbuilt — the finding tracks the gap).
fn push_warp(
    region: &mut Value,
    warp_stable_id: &str,
    plan: &MarkWarpPlan,
    mk_err: fn(String) -> OpError,
) -> Result<(), OpError> {
    let warps = region["warps"]
        .as_array_mut()
        .ok_or_else(|| mk_err("region warps is not an array".into()))?;
    warps.push(json!({
        "stable_id": warp_stable_id,
        "at": plan.at,
        "to": {
            "region_id": plan.to.region_id,
            "region_stable_id": plan.to.region_stable_id,
            "at": plan.to.at,
        },
    }));
    Ok(())
}
