//! The spec-named tests for the seven `rpg.*` ops: describe examples, inverse
//! data, determinism, the L-path shape, collision overrides surviving paints,
//! the non-blocking dangling-warp finding, and mandatory entity metadata.

mod common;

use serde_json::{json, Value};
use systole_core::ir::format::format_value;
use systole_core::op::{OpError, PlanRequest};
use systole_rpg::schema;

/// Every `describe().example` is a valid request: it survives its own
/// `validate_request` on the real dispatch path (materialize for writes,
/// query for the read).
#[test]
fn describe_examples() {
    let registry = common::registry();
    let mut project = common::project();

    // Land the town every region-dependent example refers to.
    let create = registry
        .describe("rpg.create_region")
        .expect("create_region registered");
    common::run(&mut project, "rpg.create_region", create.example.clone())
        .expect("create_region example applies");

    for desc in registry.list() {
        let req = PlanRequest {
            op_id: desc.id.clone(),
            op_version: desc.version,
            input: desc.example.clone(),
            actor: "test".into(),
        };
        match registry.materialize(&project, &req) {
            Ok(_) => {}
            Err(OpError::UnknownOp(_)) => {
                registry
                    .query(&project, &req)
                    .unwrap_or_else(|e| panic!("{} example failed query: {e}", desc.id));
            }
            Err(e) => panic!("{} example failed materialize: {e}", desc.id),
        }
    }
}

/// After each write op's apply, `Transaction::inverse()` carries the
/// before-image of every staged path, and replaying it restores the pre-state
/// byte-for-byte.
#[test]
fn inverse_data() {
    let mut project = common::project();
    let requests = [
        ("rpg.create_region", json!({"id": "town", "width": 8, "height": 8})),
        ("rpg.paint_area", json!({"region": "town", "x": 1, "y": 1, "w": 2, "h": 2, "terrain": "wall"})),
        ("rpg.paint_path", json!({"region": "town", "from": [0, 0], "to": [3, 3]})),
        ("rpg.set_collision", json!({"region": "town", "x": 5, "y": 5, "w": 2, "h": 1, "solid": true})),
        ("rpg.place_npc", json!({"region": "town", "id": "elder", "at": [4, 4]})),
        ("rpg.mark_warp", json!({"region": "town", "at": [7, 7], "to": {"region": "route_1"}})),
    ];
    for (op, input) in requests {
        let before = project.files.clone();
        let out = common::run(&mut project, op, input).expect("apply succeeds");
        assert!(!out.staged.is_empty(), "{op} staged nothing");
        for change in &out.staged {
            let recorded = out
                .inverse
                .get(change.path.as_str())
                .unwrap_or_else(|| panic!("{op}: inverse lacks {}", change.path));
            assert_eq!(
                *recorded,
                change.before.clone().unwrap_or(Value::Null),
                "{op}: inverse image of {} is not its before-image",
                change.path
            );
        }
        let restored = common::restore_inverse(&before, &out.staged, &out.inverse);
        assert_eq!(
            format_value(&serde_json::to_value(&restored).unwrap()),
            format_value(&serde_json::to_value(&before).unwrap()),
            "{op}: inverse does not restore the pre-state byte-for-byte"
        );
    }
}

/// The same request sequence on two in-memory projects yields identical
/// staged bytes and identical outputs (ADR-0010).
#[test]
fn determinism() {
    let sequence = [
        ("rpg.create_region", json!({"id": "town", "width": 16, "height": 16, "fill": "grass", "spawn": [1, 1]})),
        ("rpg.paint_area", json!({"region": "town", "x": 2, "y": 2, "w": 3, "h": 2, "terrain": "wall"})),
        ("rpg.paint_path", json!({"region": "town", "from": [1, 1], "to": [4, 3]})),
        ("rpg.set_collision", json!({"region": "town", "x": 6, "y": 6, "w": 2, "h": 2, "solid": false})),
        ("rpg.place_npc", json!({"region": "town", "id": "elder", "at": [3, 3], "facing": "down"})),
        ("rpg.mark_warp", json!({"region": "town", "at": [15, 8], "to": {"region": "route_1", "at": [1, 8]}})),
        ("rpg.query_region", json!({"region": "town"})),
    ];
    let run_all = || {
        let mut project = common::project();
        let mut staged = Vec::new();
        let mut outputs = Vec::new();
        for (op, input) in &sequence {
            let out = common::run(&mut project, op, input.clone())
                .unwrap_or_else(|e| panic!("{op}: {e}"));
            staged.push(serde_json::to_value(&out.staged).unwrap());
            outputs.push(out.output);
        }
        (staged, outputs, serde_json::to_value(&project.files).unwrap())
    };
    assert_eq!(run_all(), run_all());
}

/// The L-shape: horizontal at `from.y` to `to.x`, then vertical at `to.x` to
/// `to.y`; the corner is one tile.
#[test]
fn paint_path_l_shape() {
    let mut project = common::project();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "town", "width": 8, "height": 8}),
    )
    .unwrap();
    let out = common::run(
        &mut project,
        "rpg.paint_path",
        json!({"region": "town", "from": [1, 1], "to": [3, 4]}),
    )
    .unwrap();
    assert_eq!(out.output["tiles_changed"], json!(6));

    let terrain = &project.files[&schema::terrain_path("region_00001")];
    let rows: Vec<String> = terrain["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect();
    let expected: Vec<String> = [
        "........",
        ".---....",
        "...-....",
        "...-....",
        "...-....",
        "........",
        "........",
        "........",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(rows, expected, "L-shape: horizontal then vertical");
}

/// An explicit override survives later terrain paints; tiles without one
/// recompute from the new terrain.
#[test]
fn set_collision_override_survives_paint() {
    let mut project = common::project();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "town", "width": 8, "height": 8}),
    )
    .unwrap();

    // Solid overrides on (2,2)..(2,3); the tiles are walkable grass.
    let out = common::run(
        &mut project,
        "rpg.set_collision",
        json!({"region": "town", "x": 2, "y": 2, "w": 1, "h": 2, "solid": true}),
    )
    .unwrap();
    assert_eq!(out.output["tiles_changed"], json!(2));

    // Paint the same tiles to a walkable kind: the override must keep them
    // solid even though `path` derives walkable.
    common::run(
        &mut project,
        "rpg.paint_area",
        json!({"region": "town", "x": 2, "y": 2, "w": 1, "h": 2, "terrain": "path"}),
    )
    .unwrap();

    // The other way: a walkable override on solid terrain survives a repaint
    // to another solid kind.
    common::run(
        &mut project,
        "rpg.paint_area",
        json!({"region": "town", "x": 5, "y": 5, "w": 1, "h": 1, "terrain": "wall"}),
    )
    .unwrap();
    common::run(
        &mut project,
        "rpg.set_collision",
        json!({"region": "town", "x": 5, "y": 5, "w": 1, "h": 1, "solid": false}),
    )
    .unwrap();
    common::run(
        &mut project,
        "rpg.paint_area",
        json!({"region": "town", "x": 5, "y": 5, "w": 1, "h": 1, "terrain": "water"}),
    )
    .unwrap();

    let collision = &project.files[&schema::collision_path("region_00001")];
    let rows: Vec<String> = collision["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect();
    // (5,5) is water terrain under a walkable override: effective '.'.
    let expected: Vec<String> = [
        "........",
        "........",
        "..#.....",
        "..#.....",
        "........",
        "........",
        "........",
        "........",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(rows, expected, "overrides survive paints in both directions");
    let overrides = collision["overrides"].as_object().unwrap();
    assert_eq!(overrides.get("2,2"), Some(&json!(true)));
    assert_eq!(overrides.get("2,3"), Some(&json!(true)));
    assert_eq!(overrides.get("5,5"), Some(&json!(false)));
}

/// An unresolved warp target is a non-blocking `rpg.warp.dangling_target`
/// finding with one `rpg.create_region` PlanRequest fix — recorded now so w4
/// does not flip it blocking.
#[test]
fn mark_warp_unresolved_target_is_non_blocking() {
    let mut project = common::project();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "town", "width": 16, "height": 16}),
    )
    .unwrap();
    let out = common::run(
        &mut project,
        "rpg.mark_warp",
        json!({"region": "town", "at": [15, 8], "to": {"region": "route_1"}}),
    )
    .unwrap();

    let finding = out
        .findings
        .iter()
        .find(|f| f.code == "rpg.warp.dangling_target")
        .expect("dangling-target finding fires");
    assert!(!finding.blocking, "dangling warp target must be non-blocking");
    assert_eq!(finding.suggested_fixes.len(), 1, "one kernel fix");
    let fix = &finding.suggested_fixes[0];
    assert_eq!(fix.op_id, "rpg.create_region");
    assert_eq!(fix.op_version, 1);
    assert_eq!(fix.input["id"], json!("route_1"));

    // Non-blocking means the apply still staged the warp.
    let region = &project.files[&schema::region_path("region_00001")];
    let warps = region["warps"].as_array().unwrap();
    assert_eq!(warps.len(), 1);
    assert_eq!(warps[0]["stable_id"], json!("warp_00002"));
    assert_eq!(warps[0]["at"], json!([15, 8]));
    assert_eq!(warps[0]["to"]["region_stable_id"], Value::Null);
    assert_eq!(warps[0]["to"]["region_id"], json!("route_1"));
    assert_eq!(warps[0]["to"]["at"], Value::Null);
    assert_eq!(out.output["stable_id"], json!("warp_00002"));
}

#[test]
fn mark_warp_refuses_a_destination_outside_the_target_region() {
    let mut project = common::project();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "town", "width": 16, "height": 16}),
    )
    .unwrap();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "route_1", "width": 4, "height": 4}),
    )
    .unwrap();
    let refused = common::run(
        &mut project,
        "rpg.mark_warp",
        json!({"region": "town", "at": [15, 8], "to": {"region": "route_1", "at": [9, 9]}}),
    );
    assert!(
        matches!(refused, Err(OpError::InvalidRequest(_))),
        "expected an invalid-request refusal"
    );
}

/// The written entity carries every ADR-0003 field, and the region's
/// `placements` hold its `at` (the entity itself has no coordinates).
#[test]
fn place_npc_metadata_mandatory() {
    let mut project = common::project();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "town", "width": 8, "height": 8}),
    )
    .unwrap();
    let out = common::run(
        &mut project,
        "rpg.place_npc",
        json!({
            "region": "town", "id": "elder", "at": [3, 3], "facing": "left",
            "tags": ["quest"], "intent": "greets travellers", "constraints": ["stays put"],
        }),
    )
    .unwrap();
    assert_eq!(out.output["stable_id"], json!("ent_00002"));
    assert_eq!(out.output["path"], json!("entities/npc/ent_00002.json"));

    let entity = &project.files[&schema::npc_path("ent_00002")];
    let object = entity.as_object().unwrap();
    for field in [
        "id",
        "stable_id",
        "kind",
        "tags",
        "intent",
        "constraints",
        "owner_module",
        "human_name",
        "facing",
    ] {
        assert!(object.contains_key(field), "entity lacks ADR-0003 field {field}");
    }
    assert_eq!(entity["id"], json!("elder"));
    assert_eq!(entity["stable_id"], json!("ent_00002"));
    assert_eq!(entity["kind"], json!("npc"));
    assert_eq!(entity["owner_module"], json!("systole.rpg"));
    assert_eq!(entity["tags"], json!(["quest"]));
    assert_eq!(entity["intent"], json!("greets travellers"));
    assert_eq!(entity["constraints"], json!(["stays put"]));
    assert_eq!(entity["human_name"], Value::Null);
    assert_eq!(entity["facing"], json!("left"));
    assert!(
        object.get("at").is_none() && object.get("x").is_none() && object.get("y").is_none(),
        "the entity carries no coordinates"
    );

    let region = &project.files[&schema::region_path("region_00001")];
    assert_eq!(
        region["placements"],
        json!([{ "stable_id": "ent_00002", "at": [3, 3], "facing": "left" }])
    );
}

/// A malformed collision body absorbed from disk (overrides not an object)
/// must surface as a structured diff error, not a panic.
#[test]
fn set_collision_reports_malformed_overrides() {
    let mut project = common::project();
    common::run(
        &mut project,
        "rpg.create_region",
        json!({"id": "town", "width": 8, "height": 8}),
    )
    .unwrap();

    let key = schema::collision_path("region_00001");
    project.files.get_mut(&key).unwrap()["overrides"] = json!(7);

    let refused = common::run(
        &mut project,
        "rpg.set_collision",
        json!({"region": "town", "x": 2, "y": 2, "w": 1, "h": 1, "solid": true}),
    );
    assert!(
        matches!(refused, Err(OpError::Diff(_))),
        "expected a structured diff error"
    );
}

