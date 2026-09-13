//! `rpg.place_npc` — create a global npc entity and add its placement on a
//! region (ADR-0003's placement rule: the entity carries no coordinates).

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
use crate::schema::{self, Facing};

#[derive(Default)]
pub struct PlaceNpc;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PlaceNpcRequest {
    pub region: String,
    pub id: String,
    pub at: [u32; 2],
    #[serde(default)]
    pub facing: Facing,
    #[serde(default)]
    pub human_name: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub intent: String,
    #[serde(default)]
    pub constraints: Vec<String>,
}

/// The replayable plan: the region handle resolved to its stable id; the
/// entity stable id is allocated at apply.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PlaceNpcPlan {
    pub region: String,
    pub region_stable_id: String,
    pub id: String,
    pub at: [u32; 2],
    pub facing: Facing,
    pub human_name: Option<String>,
    pub tags: Vec<String>,
    pub intent: String,
    pub constraints: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct PlaceNpcOutput {
    pub stable_id: String,
    pub path: String,
}

impl Operation for PlaceNpc {
    type Request = PlaceNpcRequest;
    type Plan = PlaceNpcPlan;
    type Output = PlaceNpcOutput;

    const ID: &'static str = "rpg.place_npc";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Experimental;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "create an npc entity and place it on a region tile".into(),
            input_schema: schemars::schema_for!(PlaceNpcRequest),
            example: json!({"region": "town", "id": "elder", "at": [3, 3], "facing": "down"}),
            avoid_when: vec!["the tile marks a region exit — use rpg.mark_warp".into()],
        }
    }

    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError> {
        if !schema::valid_handle(&req.id) {
            return Err(invalid(
                codes::ENTITY_INVALID_ID,
                format!("entity id {:?} must match [a-z][a-z0-9_]*", req.id),
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
        Ok(PlaceNpcPlan {
            region: req.region,
            region_stable_id: stable_id,
            id: req.id,
            at: req.at,
            facing: req.facing,
            human_name: req.human_name,
            tags: req.tags,
            intent: req.intent,
            constraints: req.constraints,
        })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let entity_stable_id = predicted_id(project, IdKind::Ent);
        let region_path = schema::region_path(&plan.region_stable_id);
        let mut region = project.files.get(&region_path).cloned().ok_or_else(|| {
            OpError::Diff(format!("region {} lacks {region_path}", plan.region_stable_id))
        })?;
        push_placement(&mut region, &entity_stable_id, plan, OpError::Diff)?;
        Ok(diff_of(
            project,
            vec![
                (schema::npc_path(&entity_stable_id), entity_file(plan, &entity_stable_id)),
                (region_path, region),
            ],
        ))
    }

    fn validate(&self, project: &Project, plan: &Self::Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Some((existing_stable_id, _)) = schema::find_entity(project, &plan.id) {
            findings.push(make_finding(
                codes::ENTITY_DUPLICATE_ID,
                Severity::Error,
                true,
                Some(existing_stable_id.clone()),
                None,
                json!({
                    "requested_id": plan.id,
                    "existing_stable_id": existing_stable_id,
                }),
                Vec::new(),
            ));
        }
        let collision_path = schema::collision_path(&plan.region_stable_id);
        let on_solid = project
            .files
            .get(&collision_path)
            .and_then(|c| c["rows"].as_array())
            .and_then(|rows| rows.get(plan.at[1] as usize))
            .and_then(|row| row.as_str())
            .and_then(|row| row.chars().nth(plan.at[0] as usize))
            == Some('#');
        if on_solid {
            findings.push(make_finding(
                codes::PLACEMENT_ON_SOLID,
                Severity::Warning,
                false,
                Some(plan.region_stable_id.clone()),
                Some(collision_path),
                json!({ "id": plan.id, "at": plan.at }),
                vec![fix_request(
                    "rpg.set_collision",
                    json!({
                        "region": plan.region,
                        "x": plan.at[0],
                        "y": plan.at[1],
                        "w": 1,
                        "h": 1,
                        "solid": false,
                    }),
                )],
            ));
        }
        ordered(findings)
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let entity_stable_id = tx.alloc_id(IdKind::Ent).to_string();
        let region_path = schema::region_path(&plan.region_stable_id);
        let mut region = tx.read(&region_path).cloned().ok_or_else(|| {
            OpError::Apply(format!("region {} lacks {region_path}", plan.region_stable_id))
        })?;
        push_placement(&mut region, &entity_stable_id, &plan, OpError::Apply)?;
        let path = schema::npc_path(&entity_stable_id);
        tx.write(path.clone(), entity_file(&plan, &entity_stable_id));
        tx.write(region_path, region);
        Ok(PlaceNpcOutput {
            stable_id: entity_stable_id,
            path: path.to_string(),
        })
    }
}

fn entity_file(plan: &PlaceNpcPlan, entity_stable_id: &str) -> Value {
    schema::npc_file(
        &plan.id,
        entity_stable_id,
        &plan.tags,
        &plan.intent,
        &plan.constraints,
        plan.human_name.as_deref(),
        plan.facing,
    )
}

/// Append `{stable_id, at, facing}` to the region's `placements` (ADR-0003:
/// the entity carries no coordinates; the placement does).
fn push_placement(
    region: &mut Value,
    entity_stable_id: &str,
    plan: &PlaceNpcPlan,
    mk_err: fn(String) -> OpError,
) -> Result<(), OpError> {
    let placements = region["placements"]
        .as_array_mut()
        .ok_or_else(|| mk_err("region placements is not an array".into()))?;
    placements.push(json!({
        "stable_id": entity_stable_id,
        "at": plan.at,
        "facing": plan.facing,
    }));
    Ok(())
}
