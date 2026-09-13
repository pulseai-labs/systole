//! The Release-0 golden journey as a standing regression test (r0.s1.w5):
//! the ten documented journey steps driven through the built `systole`
//! binary — init, catalog discovery, the
//! 16×16 town through preview and apply, the NPC sealed inside a collision
//! ring, the reachability finding repaired through `plan --from-finding`,
//! a benign transaction rolled back byte-identically, a refused hand edit
//! absorbed by `doctor --absorb`, and the audit-entry count — plus
//! `fixtures_are_healthy`, the ir-integrity progressive-exposure control
//! over the committed examples. Each step is a named block so a failure
//! names the step.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn systole() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_systole"));
    cmd.env_remove("SYSTOLE_READ_ONLY");
    cmd.env_remove("SYSTOLE_PROJECT");
    cmd
}

/// The workspace root: this crate is `<root>/crates/systole`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// A fresh temporary directory under the cargo target dir; TempDir removes
/// it on drop, including on a failing assert's unwind.
fn temp_dir(tag: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("golden-journey-{tag}-"))
        .tempdir_in(workspace_root().join("target"))
        .unwrap()
}

fn on(root: &Path, args: &[&str]) -> Output {
    systole()
        .arg("--project")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn json(out: &Output) -> Value {
    serde_json::from_str(stdout(out).trim()).unwrap()
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect()
}

fn audit_lines(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("audit/audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn manifest(root: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(root.join("project.systole.json")).unwrap()).unwrap()
}

fn init_project(root: &Path) {
    let out = systole()
        .arg("project")
        .arg("init")
        .arg(root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "init: {}", stderr(&out));
}

fn apply_ok(root: &Path, op: &str, input: &str) -> Output {
    let out = on(root, &["apply", op, "--input", input]);
    assert_eq!(out.status.code(), Some(0), "apply {op}: {}", stderr(&out));
    out
}

fn project_hash(root: &Path) -> String {
    let out = on(root, &["--json", "project", "check"]);
    assert_eq!(out.status.code(), Some(0));
    json(&out)["project_hash"].as_str().unwrap().to_string()
}

/// Steps 1–2: `project init` and the catalog.
fn step_init_and_catalog(root: &Path) {
    init_project(root);
    assert!(
        root.join("project.systole.json").exists(),
        "step 1: manifest exists"
    );
    assert!(
        root.join("audit/audit.jsonl").exists(),
        "step 1: audit log exists"
    );
    let check = on(root, &["project", "check"]);
    assert_eq!(check.status.code(), Some(0), "step 1: check exits 0");
    assert!(
        stdout(&check).contains("rev_00000"),
        "step 1: fresh project is rev_00000"
    );

    let list = on(root, &["op", "list"]);
    assert_eq!(list.status.code(), Some(0), "step 2: op list exits 0");
    let catalog = stdout(&list);
    assert!(
        catalog.contains("rpg.create_region"),
        "step 2: catalog carries rpg.create_region"
    );
    #[cfg(not(feature = "fixture-ops"))]
    assert!(
        !catalog.contains("fixture."),
        "step 2: no fixture ops in the default build"
    );
    let describe = on(root, &["--json", "op", "describe", "rpg.create_region"]);
    assert_eq!(describe.status.code(), Some(0), "step 2: describe exits 0");
    let d = json(&describe);
    assert!(d["input_schema"].is_object(), "step 2: input_schema present");
    assert!(d.get("example").is_some(), "step 2: one example present");
}

/// Steps 3–7: build the walled town and read the two findings. Returns the
/// blocking finding's id for `plan --from-finding`.
fn step_build_and_validate(root: &Path) -> String {
    let create = r#"{"id":"town","width":16,"height":16,"spawn":[1,1]}"#;
    let manifest_before = std::fs::read(root.join("project.systole.json")).unwrap();
    let preview = on(root, &["preview", "rpg.create_region", "--input", create]);
    assert_eq!(preview.status.code(), Some(0), "step 3: preview exits 0");
    assert!(
        stdout(&preview).contains("+ regions/"),
        "step 3: preview prints the creates"
    );
    assert!(
        !stderr(&preview).contains("blocking"),
        "step 3: no blocking finding"
    );
    assert!(audit_lines(root).is_empty(), "step 3: preview audits nothing");
    assert_eq!(
        std::fs::read(root.join("project.systole.json")).unwrap(),
        manifest_before,
        "step 3: manifest untouched"
    );
    let committed = apply_ok(root, "rpg.create_region", create);
    assert!(
        stdout(&committed).contains("committed aud_00001 at rev_00001"),
        "step 3: the commit line"
    );
    assert!(
        root.join("regions/region_00001/region.json").exists(),
        "step 3: region file exists"
    );

    // Step 4: a solid 3×3 wall block, its centre walkable by collision
    // override (a closed ring with a walkable interior), and the path that
    // ends beside the ring's west tile.
    apply_ok(
        root,
        "rpg.paint_area",
        r#"{"region":"town","x":4,"y":4,"w":3,"h":3,"terrain":"wall"}"#,
    );
    apply_ok(
        root,
        "rpg.set_collision",
        r#"{"region":"town","x":5,"y":5,"w":1,"h":1,"solid":false}"#,
    );
    apply_ok(
        root,
        "rpg.paint_path",
        r#"{"region":"town","from":[1,1],"to":[3,5]}"#,
    );
    let check = on(root, &["project", "check"]);
    assert!(
        stdout(&check).contains("rev_00004"),
        "step 4: revision rev_00004"
    );
    let query = on(
        root,
        &["query", "rpg.query_region", "--input", r#"{"region":"town"}"#],
    );
    assert_eq!(query.status.code(), Some(0), "step 4: query_region exits 0");
    let q = json(&query);
    let rows = strs(&q["rows"]);
    let collision = strs(&q["collision_rows"]);
    assert!(rows[1].contains('-'), "step 4: the path is painted");
    assert_eq!(
        rows[5].chars().nth(5),
        Some('#'),
        "step 4: centre terrain stays wall"
    );
    assert_eq!(
        collision[5].chars().nth(5),
        Some('.'),
        "step 4: the override opens the centre"
    );

    // Step 5: the elder on open floor — a commit can no longer create a
    // blocking state, so the seal itself arrives via the hand edit below.
    apply_ok(
        root,
        "rpg.place_npc",
        r#"{"region":"town","id":"elder","at":[1,2],"intent":"greets the player","constraints":["stays in the room"]}"#,
    );
    let ent: Value =
        serde_json::from_slice(&std::fs::read(root.join("entities/npc/ent_00002.json")).unwrap())
            .unwrap();
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
        assert!(ent.get(field).is_some(), "step 5: entity carries {field}");
    }
    assert_eq!(ent["id"], "elder", "step 5: the elder's handle");
    assert_eq!(ent["intent"], "greets the player", "step 5: the intent");
    assert_eq!(
        ent["constraints"],
        serde_json::json!(["stays in the room"]),
        "step 5: the constraint"
    );
    let region: Value = serde_json::from_slice(
        &std::fs::read(root.join("regions/region_00001/region.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        region["placements"][0]["stable_id"], "ent_00002",
        "step 5: the region references the entity"
    );

    // Step 6: the warp to the unbuilt route_1.
    apply_ok(
        root,
        "rpg.mark_warp",
        r#"{"region":"town","at":[15,8],"to":{"region":"route_1"}}"#,
    );
    let query = on(
        root,
        &["query", "rpg.query_region", "--input", r#"{"region":"town"}"#],
    );
    let q = json(&query);
    assert_eq!(
        q["warps"][0]["to"]["region_id"], "route_1",
        "step 6: the warp appears in query_region"
    );
    assert_eq!(audit_lines(root).len(), 6, "step 6: six audit entries");
    let check = on(root, &["project", "check"]);
    assert!(
        stdout(&check).contains("rev_00006"),
        "step 6: revision rev_00006"
    );

    // Step 6.5: seal the elder by hand — a blocking state can only ever come
    // from an out-of-band edit now, and doctor --absorb adopts it as an
    // external_edit while canonicalizing the file back on disk.
    let region_path = root.join("regions/region_00001/region.json");
    let mut region_file: Value =
        serde_json::from_slice(&std::fs::read(&region_path).unwrap()).unwrap();
    region_file["placements"][0]["at"] = serde_json::json!([5, 5]);
    std::fs::write(&region_path, serde_json::to_string_pretty(&region_file).unwrap()).unwrap();
    let seal = on(root, &["project", "doctor", "--absorb"]);
    assert_eq!(
        seal.status.code(),
        Some(0),
        "step 6.5: absorb seals the elder"
    );
    assert_eq!(
        audit_lines(root).len(),
        7,
        "step 6.5: the absorb is aud_00007"
    );

    // Step 7: exactly two findings — the sealed NPC (blocking, with the
    // door-tile fix) and the dangling warp (advisory).
    let validate = on(root, &["validate", "--all"]);
    assert_eq!(
        validate.status.code(),
        Some(1),
        "step 7: a blocking finding exits 1"
    );
    let envelope = json(&on(root, &["--json", "validate", "--all"]));
    let findings = envelope["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "step 7: exactly two findings");
    let blocking: Vec<&Value> = findings.iter().filter(|f| f["blocking"] == true).collect();
    assert_eq!(blocking.len(), 1, "step 7: exactly one blocking finding");
    let npc = blocking[0];
    assert_eq!(npc["code"], "rpg.reachability.unreachable_npc");
    let fixes = npc["suggested_fixes"].as_array().unwrap();
    assert!(!fixes.is_empty(), "step 7: suggested fixes are non-empty");
    assert_eq!(fixes[0]["op_id"], "rpg.set_collision");
    assert_eq!(fixes[0]["input"]["solid"], false, "step 7: the fix opens a tile");
    assert_eq!(fixes[0]["input"]["x"], 4, "step 7: the door tile's x");
    assert_eq!(fixes[0]["input"]["y"], 5, "step 7: the door tile's y");
    let advisory: Vec<&Value> = findings.iter().filter(|f| f["blocking"] == false).collect();
    assert_eq!(advisory.len(), 1, "step 7: exactly one advisory finding");
    assert_eq!(advisory[0]["code"], "rpg.warp.dangling_target");
    npc["finding_id"].as_str().unwrap().to_string()
}

/// Step 8: the finding's suggested fix, planned by id and applied through
/// the ordinary lifecycle, clears validation.
fn step_repair(root: &Path, finding_id: &str) {
    let plan_path = root.join("fix.json");
    let plan = on(
        root,
        &[
            "plan",
            "--from-finding",
            finding_id,
            "--out",
            plan_path.to_str().unwrap(),
        ],
    );
    assert_eq!(plan.status.code(), Some(0), "step 8: plan exits 0");
    assert!(
        stdout(&plan).starts_with("plan "),
        "step 8: prints the plan id"
    );
    let apply = on(root, &["apply", plan_path.to_str().unwrap()]);
    assert_eq!(apply.status.code(), Some(0), "step 8: apply exits 0");
    assert!(
        stdout(&apply).contains("aud_00008"),
        "step 8: the fix is aud_00007"
    );
    let validate = on(root, &["validate", "--all"]);
    assert_eq!(
        validate.status.code(),
        Some(0),
        "step 8: validate exits 0 (the dangling warning stays advisory)"
    );
}

#[test]
fn golden_journey() {
    // Steps 1–8 on project `a`, with each step's evidence asserted.
    let tmp_a = temp_dir("a");
    let a = tmp_a.path().join("town");
    step_init_and_catalog(&a);
    let finding_id = step_build_and_validate(&a);
    step_repair(&a, &finding_id);
    let hash_a = project_hash(&a);

    // Determinism (ADR-0010): a second run of steps 1–8 in a second
    // temporary directory lands on the same project hash.
    let tmp_b = temp_dir("b");
    let b = tmp_b.path().join("town");
    step_init_and_catalog(&b);
    let finding_id_b = step_build_and_validate(&b);
    step_repair(&b, &finding_id_b);
    assert_eq!(
        project_hash(&b),
        hash_a,
        "step 11: determinism — equal project_hash after step 8"
    );

    // Step 9: a benign transaction rolled back under a compensating entry.
    let terrain = a.join("regions/region_00001/layers/terrain.json");
    let terrain_before = std::fs::read(&terrain).unwrap();
    let counter_before = manifest(&a)["stable_id_counter"].as_u64().unwrap();
    let benign = apply_ok(
        &a,
        "rpg.paint_area",
        r#"{"region":"town","x":10,"y":10,"w":2,"h":2,"terrain":"path"}"#,
    );
    assert!(
        stdout(&benign).contains("aud_00009"),
        "step 9: the benign transaction is aud_00009"
    );
    let rollback = on(&a, &["rollback", "aud_00009"]);
    assert_eq!(rollback.status.code(), Some(0), "step 9: rollback exits 0");
    assert!(
        stdout(&rollback).contains("rolled back aud_00009 as aud_00010 at rev_00010"),
        "step 9: the rollback line"
    );
    let last = audit_lines(&a).pop().unwrap();
    assert!(
        last.contains("\"rollback_of\":\"aud_00009\""),
        "step 9: the compensating entry names its target"
    );
    assert_eq!(
        std::fs::read(&terrain).unwrap(),
        terrain_before,
        "step 9: terrain.json byte-identical to its pre-commit bytes"
    );
    assert_eq!(
        manifest(&a)["stable_id_counter"].as_u64().unwrap(),
        counter_before,
        "step 9: the stable-id counter did not decrement"
    );
    let validate = on(&a, &["validate", "--all"]);
    assert_eq!(
        validate.status.code(),
        Some(0),
        "step 9: validate still exits 0"
    );

    // Step 10: a hand edit is refused, then absorbed by doctor --absorb.
    let collision = a.join("regions/region_00001/layers/collision.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&collision).unwrap()).unwrap();
    let mut rows: Vec<String> = strs(&file["rows"]).iter().map(|s| s.to_string()).collect();
    let mut row: Vec<char> = rows[10].chars().collect();
    // A tile far from the ring, the path, the spawn and the warp: one
    // walkable tile flipped solid walls nothing in.
    row[10] = '#';
    rows[10] = row.into_iter().collect();
    file["rows"] = serde_json::json!(rows);
    std::fs::write(&collision, serde_json::to_string_pretty(&file).unwrap()).unwrap();

    let manifest_before = std::fs::read(a.join("project.systole.json")).unwrap();
    let entries_before = audit_lines(&a).len();
    let check = on(&a, &["project", "check"]);
    assert_eq!(check.status.code(), Some(2), "step 10: the hand edit is refused");
    let err = stderr(&check);
    assert!(err.contains("collision.json"), "step 10: the changed file is named");
    assert!(
        err.contains("rev_00010"),
        "step 10: the recorded revision is named"
    );
    assert_eq!(
        std::fs::read(a.join("project.systole.json")).unwrap(),
        manifest_before,
        "step 10: the refusal writes nothing"
    );
    assert_eq!(
        audit_lines(&a).len(),
        entries_before,
        "step 10: no new audit line"
    );
    let validate = on(&a, &["validate", "--all"]);
    assert_eq!(
        validate.status.code(),
        Some(2),
        "step 10: validate refuses too"
    );

    let doctor = on(&a, &["project", "doctor", "--absorb"]);
    assert_eq!(doctor.status.code(), Some(0), "step 10: absorb exits 0");
    let last = audit_lines(&a).pop().unwrap();
    assert!(
        last.contains("\"op_id\":\"core.external_edit\""),
        "step 10: the external_edit entry is recorded"
    );
    let check = on(&a, &["project", "check"]);
    assert_eq!(check.status.code(), Some(0), "step 10: check recovers");
    let validate = on(&a, &["validate", "--all"]);
    assert_eq!(
        validate.status.code(),
        Some(0),
        "step 10: validate exits 0 after the absorb"
    );

    // Step 11: the audit-entry count.
    let n = audit_lines(&a).len();
    println!("audit entries: {n}");
    assert_eq!(n, 11, "step 11: eleven audit entries");
    assert_eq!(
        manifest(&a)["audit_head"]["id"], "aud_00011",
        "step 11: the audit head is aud_00011"
    );
}

/// The ir-integrity progressive-exposure control: both committed fixtures
/// check clean, the walled-NPC fixture yields exactly the two findings w4
/// recorded, and neither carries a runtime `.systole/` directory.
#[test]
fn fixtures_are_healthy() {
    let root = workspace_root();
    let reference = root.join("examples/reference");
    let walled = root.join("examples/walled-npc");

    let check = on(&reference, &["project", "check"]);
    assert_eq!(check.status.code(), Some(0), "reference: check exits 0");
    let check = on(&walled, &["project", "check"]);
    assert_eq!(check.status.code(), Some(0), "walled-npc: check exits 0");

    let validate = on(&walled, &["--json", "validate", "--all"]);
    assert_eq!(
        validate.status.code(),
        Some(1),
        "walled-npc: the blocking finding exits 1"
    );
    let envelope = json(&validate);
    let mut codes: Vec<&str> = envelope["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    codes.sort();
    assert_eq!(
        codes,
        ["rpg.reachability.unreachable_npc", "rpg.warp.dangling_target"],
        "walled-npc: exactly the two recorded findings"
    );

    assert!(
        !reference.join(".systole").exists(),
        "reference carries no .systole/"
    );
    assert!(
        !walled.join(".systole").exists(),
        "walled-npc carries no .systole/"
    );
}
