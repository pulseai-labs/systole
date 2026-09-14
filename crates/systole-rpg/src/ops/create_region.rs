//! `rpg.create_region` — create a region: `region.json`, `layers/terrain.json`
//! filled with `fill`, and `layers/collision.json` derived from it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use systole_core::capability::Capability;
use systole_core::finding::{Finding, Severity};
use systole_core::ids::IdKind;
use systole_core::ir::project::Project;
use systole_core::op::{Diff, Mutability, Operation, OperationDescription, OpError, Stability};
use systole_core::tx::Transaction;

use super::{codes, diff_of, invalid, make_finding, ordered, predicted_id};
use crate::schema;

#[derive(Default)]
pub struct CreateRegion;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CreateRegionRequest {
    pub id: String,
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub fill: Option<String>,
    #[serde(default)]
    pub spawn: Option<[u32; 2]>,
}

/// The replayable plan: the request with defaults resolved and `spawn`
/// clamped inside the region.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CreateRegionPlan {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub fill: String,
    pub spawn: [u32; 2],
}

#[derive(Serialize, JsonSchema)]
pub struct CreateRegionOutput {
    pub stable_id: String,
    pub path: String,
}

impl Operation for CreateRegion {
    type Request = CreateRegionRequest;
    type Plan = CreateRegionPlan;
    type Output = CreateRegionOutput;

    const ID: &'static str = "rpg.create_region";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Experimental;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "create a region: region.json plus terrain and collision layers".into(),
            input_schema: schemars::schema_for!(CreateRegionRequest),
            example: json!({"id": "town", "width": 16, "height": 16, "fill": "grass", "spawn": [1, 1]}),
            avoid_when: vec!["the region handle already exists — paint or query it instead".into()],
        }
    }

    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError> {
        if !schema::valid_handle(&req.id) {
            return Err(invalid(
                codes::REGION_INVALID_ID,
                format!("region id {:?} must match [a-z][a-z0-9_]*", req.id),
            ));
        }
        if req.width == 0
            || req.height == 0
            || req.width > schema::MAX_REGION_DIMENSION
            || req.height > schema::MAX_REGION_DIMENSION
        {
            return Err(invalid(
                codes::RECT_OUT_OF_BOUNDS,
                format!(
                    "region dimensions {}x{} must be within 1..={}",
                    req.width,
                    req.height,
                    schema::MAX_REGION_DIMENSION
                ),
            ));
        }
        if let Some(fill) = &req.fill
            && schema::Terrain::from_kind(fill).is_none()
        {
            return Err(invalid(
                codes::UNKNOWN_TERRAIN,
                format!("unknown terrain kind {fill:?}"),
            ));
        }
        Ok(())
    }

    fn materialize(&self, _project: &Project, req: Self::Request) -> Result<Self::Plan, OpError> {
        let fill = req.fill.unwrap_or_else(|| "grass".to_string());
        let fill = schema::Terrain::from_kind(&fill)
            .ok_or_else(|| invalid(codes::UNKNOWN_TERRAIN, format!("unknown terrain kind {fill:?}")))?;
        // A spawn outside the region is clamped to its nearest in-bounds tile.
        let spawn = req.spawn.unwrap_or([0, 0]);
        let spawn = [
            spawn[0].min(req.width.saturating_sub(1)),
            spawn[1].min(req.height.saturating_sub(1)),
        ];
        Ok(CreateRegionPlan {
            id: req.id,
            width: req.width,
            height: req.height,
            fill: fill.kind().to_string(),
            spawn,
        })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let stable_id = predicted_id(project, IdKind::Region);
        let fill = schema::Terrain::from_kind(&plan.fill)
            .ok_or_else(|| OpError::Diff(format!("plan carries unknown terrain {:?}", plan.fill)))?;
        Ok(diff_of(
            project,
            region_writes(&stable_id, plan, fill),
        ))
    }

    fn validate(&self, project: &Project, plan: &Self::Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Some((existing_stable_id, _)) = schema::find_region(project, &plan.id) {
            findings.push(make_finding(
                codes::REGION_DUPLICATE_ID,
                Severity::Error,
                true,
                Some(existing_stable_id.clone()),
                Some(schema::region_path(&existing_stable_id)),
                json!({
                    "requested_id": plan.id,
                    "existing_stable_id": existing_stable_id,
                }),
                Vec::new(),
            ));
        }
        ordered(findings)
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let stable_id = tx.alloc_id(IdKind::Region).to_string();
        let fill = schema::Terrain::from_kind(&plan.fill)
            .ok_or_else(|| OpError::Apply(format!("plan carries unknown terrain {:?}", plan.fill)))?;
        for (path, value) in region_writes(&stable_id, &plan, fill) {
            tx.write(path, value);
        }
        Ok(CreateRegionOutput {
            path: schema::region_path(&stable_id).to_string(),
            stable_id,
        })
    }
}

/// The three files a region create writes: `region.json`, `terrain.json`
/// filled with `fill`, `collision.json` derived from it.
fn region_writes(
    stable_id: &str,
    plan: &CreateRegionPlan,
    fill: schema::Terrain,
) -> Vec<(systole_core::ir::RelPath, serde_json::Value)> {
    let terrain = schema::terrain_file(plan.width, plan.height, fill);
    vec![
        (
            schema::region_path(stable_id),
            schema::region_file(&plan.id, stable_id, plan.width, plan.height, plan.spawn),
        ),
        (schema::terrain_path(stable_id), terrain.clone()),
        (
            schema::collision_path(stable_id),
            schema::collision_file(plan.width, plan.height, &terrain),
        ),
    ]
}
