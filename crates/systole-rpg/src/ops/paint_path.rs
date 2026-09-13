//! `rpg.paint_path` — paint an L-shaped path: horizontal at `from.y` to
//! `to.x`, then vertical at `to.x` to `to.y` (the spike's shape).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use systole_core::capability::Capability;
use systole_core::finding::Finding;
use systole_core::ir::project::Project;
use systole_core::op::{Diff, Mutability, Operation, OperationDescription, OpError, Stability};
use systole_core::tx::Transaction;

use super::{codes, diff_of, invalid, paint_writes, require_region, stage_if_changed};
use crate::schema;

#[derive(Default)]
pub struct PaintPath;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PaintPathRequest {
    pub region: String,
    pub from: [u32; 2],
    pub to: [u32; 2],
    #[serde(default)]
    pub terrain: Option<String>,
}

/// The replayable plan: the region handle resolved to its stable id and the
/// terrain default applied.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PaintPathPlan {
    pub region_stable_id: String,
    pub from: [u32; 2],
    pub to: [u32; 2],
    pub terrain: String,
}

#[derive(Serialize, JsonSchema)]
pub struct PaintPathOutput {
    pub tiles_changed: u64,
}

impl Operation for PaintPath {
    type Request = PaintPathRequest;
    type Plan = PaintPathPlan;
    type Output = PaintPathOutput;

    const ID: &'static str = "rpg.paint_path";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Experimental;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "paint an L-shaped path of one terrain kind between two points".into(),
            input_schema: schemars::schema_for!(PaintPathRequest),
            example: json!({"region": "town", "from": [1, 1], "to": [4, 3]}),
            avoid_when: vec!["the target is a filled rectangle — use rpg.paint_area".into()],
        }
    }

    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError> {
        if let Some(terrain) = &req.terrain {
            if schema::Terrain::from_kind(terrain).is_none() {
                return Err(invalid(
                    codes::UNKNOWN_TERRAIN,
                    format!("unknown terrain kind {terrain:?}"),
                ));
            }
        }
        Ok(())
    }

    fn materialize(&self, project: &Project, req: Self::Request) -> Result<Self::Plan, OpError> {
        let (stable_id, region) = require_region(project, &req.region)?;
        let (width, height) = schema::region_size(region);
        for point in [req.from, req.to] {
            if !schema::point_inside(point[0], point[1], width, height) {
                return Err(invalid(
                    codes::POINT_OUT_OF_BOUNDS,
                    format!(
                        "point ({},{}) is outside region {:?} bounds {}x{}",
                        point[0], point[1], req.region, width, height
                    ),
                ));
            }
        }
        Ok(PaintPathPlan {
            region_stable_id: stable_id,
            from: req.from,
            to: req.to,
            terrain: req.terrain.unwrap_or_else(|| "path".to_string()),
        })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let kind = schema::Terrain::from_kind(&plan.terrain)
            .ok_or_else(|| OpError::Diff(format!("plan carries unknown terrain {:?}", plan.terrain)))?;
        let tiles = schema::l_path_tiles(plan.from, plan.to);
        let (writes, _) = paint_writes(
            |path| project.files.get(path),
            &plan.region_stable_id,
            &tiles,
            kind,
            OpError::Diff,
        )?;
        Ok(diff_of(project, writes))
    }

    fn validate(&self, _project: &Project, _plan: &Self::Plan) -> Vec<Finding> {
        Vec::new()
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let kind = schema::Terrain::from_kind(&plan.terrain)
            .ok_or_else(|| OpError::Apply(format!("plan carries unknown terrain {:?}", plan.terrain)))?;
        let tiles = schema::l_path_tiles(plan.from, plan.to);
        let (writes, tiles_changed) = paint_writes(
            |path| tx.read(path),
            &plan.region_stable_id,
            &tiles,
            kind,
            OpError::Apply,
        )?;
        for (path, after) in writes {
            stage_if_changed(tx, path, after);
        }
        Ok(PaintPathOutput { tiles_changed })
    }
}
