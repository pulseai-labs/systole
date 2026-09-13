//! `rpg.paint_area` — paint a rectangle of terrain and recompute collision
//! for its tiles that carry no override.

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
pub struct PaintArea;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PaintAreaRequest {
    pub region: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub terrain: String,
}

/// The replayable plan: the region handle resolved to its stable id.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PaintAreaPlan {
    pub region_stable_id: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub terrain: String,
}

#[derive(Serialize, JsonSchema)]
pub struct PaintAreaOutput {
    pub tiles_changed: u64,
}

impl Operation for PaintArea {
    type Request = PaintAreaRequest;
    type Plan = PaintAreaPlan;
    type Output = PaintAreaOutput;

    const ID: &'static str = "rpg.paint_area";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Experimental;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "paint a rectangle of one terrain kind inside a region".into(),
            input_schema: schemars::schema_for!(PaintAreaRequest),
            example: json!({"region": "town", "x": 0, "y": 0, "w": 4, "h": 4, "terrain": "path"}),
            avoid_when: vec!["the stroke is a path between two points — use rpg.paint_path".into()],
        }
    }

    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError> {
        if schema::Terrain::from_kind(&req.terrain).is_none() {
            return Err(invalid(
                codes::UNKNOWN_TERRAIN,
                format!("unknown terrain kind {:?}", req.terrain),
            ));
        }
        Ok(())
    }

    fn materialize(&self, project: &Project, req: Self::Request) -> Result<Self::Plan, OpError> {
        let (stable_id, region) = require_region(project, &req.region)?;
        let (width, height) = schema::region_size(region);
        if !schema::rect_inside(req.x, req.y, req.w, req.h, width, height) {
            return Err(invalid(
                codes::RECT_OUT_OF_BOUNDS,
                format!(
                    "rect ({},{})+{}x{} exceeds region {:?} bounds {}x{}",
                    req.x, req.y, req.w, req.h, req.region, width, height
                ),
            ));
        }
        Ok(PaintAreaPlan {
            region_stable_id: stable_id,
            x: req.x,
            y: req.y,
            w: req.w,
            h: req.h,
            terrain: req.terrain,
        })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let kind = schema::Terrain::from_kind(&plan.terrain)
            .ok_or_else(|| OpError::Diff(format!("plan carries unknown terrain {:?}", plan.terrain)))?;
        let tiles = schema::rect_tiles(plan.x, plan.y, plan.w, plan.h);
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
        let tiles = schema::rect_tiles(plan.x, plan.y, plan.w, plan.h);
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
        Ok(PaintAreaOutput { tiles_changed })
    }
}
