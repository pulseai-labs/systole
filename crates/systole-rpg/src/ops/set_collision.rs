//! `rpg.set_collision` — record explicit solidity overrides for a rectangle;
//! overrides survive later terrain paints.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use systole_core::capability::Capability;
use systole_core::finding::Finding;
use systole_core::ir::project::Project;
use systole_core::op::{Diff, Mutability, Operation, OperationDescription, OpError, Stability};
use systole_core::tx::Transaction;

use super::{codes, diff_of, invalid, require_region, stage_if_changed};
use crate::schema;

#[derive(Default)]
pub struct SetCollision;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SetCollisionRequest {
    pub region: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub solid: bool,
}

/// The replayable plan: the region handle resolved to its stable id.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SetCollisionPlan {
    pub region_stable_id: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub solid: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct SetCollisionOutput {
    pub tiles_changed: u64,
}

impl Operation for SetCollision {
    type Request = SetCollisionRequest;
    type Plan = SetCollisionPlan;
    type Output = SetCollisionOutput;

    const ID: &'static str = "rpg.set_collision";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Experimental;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "set explicit collision overrides on a rectangle (survives later paints)".into(),
            input_schema: schemars::schema_for!(SetCollisionRequest),
            example: json!({"region": "town", "x": 0, "y": 0, "w": 2, "h": 2, "solid": true}),
            avoid_when: vec!["the tile's solidity should follow its terrain — paint it instead".into()],
        }
    }

    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
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
        Ok(SetCollisionPlan {
            region_stable_id: stable_id,
            x: req.x,
            y: req.y,
            w: req.w,
            h: req.h,
            solid: req.solid,
        })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let path = schema::collision_path(&plan.region_stable_id);
        let mut collision = project.files.get(&path).cloned().ok_or_else(|| {
            OpError::Diff(format!("region {} lacks {path}", plan.region_stable_id))
        })?;
        schema::apply_collision_override(&mut collision, plan.x, plan.y, plan.w, plan.h, plan.solid).map_err(OpError::Diff)?;
        Ok(diff_of(project, vec![(path, collision)]))
    }

    fn validate(&self, _project: &Project, _plan: &Self::Plan) -> Vec<Finding> {
        Vec::new()
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let path = schema::collision_path(&plan.region_stable_id);
        let mut collision = tx.read(&path).cloned().ok_or_else(|| {
            OpError::Apply(format!("region {} lacks {path}", plan.region_stable_id))
        })?;
        let tiles_changed =
            schema::apply_collision_override(&mut collision, plan.x, plan.y, plan.w, plan.h, plan.solid).map_err(OpError::Apply)?;
        stage_if_changed(tx, path, collision);
        Ok(SetCollisionOutput { tiles_changed })
    }
}
