//! `rpg.query_region` — the read op: the text map is the agent's working
//! view. `rows` are the terrain bytes exactly (spawn is a separate field;
//! `S` is never substituted).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use systole_core::capability::Capability;
use systole_core::ir::project::Project;
use systole_core::op::{OperationDescription, OpError, ReadOperation};

use super::require_region;
use crate::schema;

#[derive(Default)]
pub struct QueryRegion;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct QueryRegionRequest {
    pub region: String,
}

#[derive(Serialize, JsonSchema)]
pub struct PlacementOut {
    pub stable_id: String,
    pub id: String,
    pub at: [u32; 2],
    pub facing: String,
}

#[derive(Serialize, JsonSchema)]
pub struct QueryRegionOutput {
    pub id: String,
    pub stable_id: String,
    pub width: u32,
    pub height: u32,
    pub spawn: [u32; 2],
    pub legend: Value,
    pub rows: Vec<String>,
    pub collision_rows: Vec<String>,
    pub placements: Vec<PlacementOut>,
    pub warps: Vec<Value>,
}

impl ReadOperation for QueryRegion {
    type Request = QueryRegionRequest;
    type Output = QueryRegionOutput;

    const ID: &'static str = "rpg.query_region";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectRead;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "read a region's text map, placements and warps".into(),
            input_schema: schemars::schema_for!(QueryRegionRequest),
            example: json!({"region": "town"}),
            avoid_when: vec!["the answer needs more than one region — query each region instead".into()],
        }
    }

    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }

    fn query(&self, project: &Project, req: Self::Request) -> Result<Self::Output, OpError> {
        let (stable_id, region) = require_region(project, &req.region)?;
        let terrain_path = schema::terrain_path(&stable_id);
        let collision_path = schema::collision_path(&stable_id);
        let terrain = project.files.get(&terrain_path).ok_or_else(|| {
            OpError::Apply(format!("region {stable_id} lacks {terrain_path}"))
        })?;
        let collision = project.files.get(&collision_path).ok_or_else(|| {
            OpError::Apply(format!("region {stable_id} lacks {collision_path}"))
        })?;

        let (width, height) = schema::region_size(region);
        let rows = strings(terrain["rows"].as_array());
        let collision_rows = strings(collision["rows"].as_array());
        let legend = terrain
            .get("legend")
            .cloned()
            .unwrap_or_else(schema::legend);
        let spawn: [u32; 2] = serde_json::from_value(region["spawn"].clone()).unwrap_or([0, 0]);

        let empty = Vec::new();
        let placements = region["placements"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|placement| {
                let sid = placement["stable_id"].as_str().unwrap_or_default().to_string();
                let id = schema::find_entity_by_stable_id(project, &sid)
                    .and_then(|e| e["id"].as_str())
                    .unwrap_or(&sid)
                    .to_string();
                PlacementOut {
                    stable_id: sid,
                    id,
                    at: serde_json::from_value(placement["at"].clone()).unwrap_or([0, 0]),
                    facing: placement["facing"]
                        .as_str()
                        .unwrap_or("down")
                        .to_string(),
                }
            })
            .collect();
        let warps = region["warps"].as_array().cloned().unwrap_or_default();

        Ok(QueryRegionOutput {
            id: region["id"].as_str().unwrap_or_default().to_string(),
            stable_id,
            width,
            height,
            spawn,
            legend,
            rows,
            collision_rows,
            placements,
            warps,
        })
    }
}

fn strings(rows: Option<&Vec<Value>>) -> Vec<String> {
    rows.map(|rows| {
        rows.iter()
            .map(|r| r.as_str().unwrap_or_default().to_string())
            .collect()
    })
    .unwrap_or_default()
}
