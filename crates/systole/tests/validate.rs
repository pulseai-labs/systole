//! CLI behavior locks for r0.s1.w4: the `validate --all` →
//! `plan --from-finding` → `apply` repair loop, its exit-code ladder, and the
//! `finding.*` refusal codes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

fn systole() -> Command {
    Command::new(env!("CARGO_BIN_EXE_systole"))
}

/// A fresh tempdir plus a not-yet-created project path inside it.
fn temp_project(tag: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(tag);
    (dir, path)
}

fn init_project(tag: &str) -> (TempDir, PathBuf) {
    let (guard, root) = temp_project(tag);
    let out = systole()
        .arg("project")
        .arg("init")
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "init failed: {out:?}");
    (guard, root)
}

fn on(root: &Path, args: &[&str]) -> Output {
    systole()
        .arg("--project")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}

fn apply(root: &Path, op: &str, input: &str) {
    let out = on(root, &["apply", op, "--input", input]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "apply {op} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The walled-NPC project: `elder` sealed inside a closed 3×3 ring.
fn walled_project(tag: &str) -> (TempDir, PathBuf) {
    let (guard, root) = init_project(tag);
    apply(
        &root,
        "rpg.create_region",
        r#"{"id":"town","width":16,"height":16,"spawn":[1,1]}"#,
    );
    apply(
        &root,
        "rpg.paint_area",
        r#"{"region":"town","x":4,"y":4,"w":3,"h":3,"terrain":"wall"}"#,
    );
    apply(
        &root,
        "rpg.paint_area",
        r#"{"region":"town","x":5,"y":5,"w":1,"h":1,"terrain":"floor"}"#,
    );
    apply(
        &root,
        "rpg.place_npc",
        r#"{"region":"town","id":"elder","at":[2,2]}"#,
    );
    // Seal elder by hand: under the commit-time validator gate a blocking
    // state can only arrive out-of-band; doctor --absorb adopts the edit.
    let region_path = root
        .join("regions")
        .join("region_00001")
        .join("region.json");
    let mut region_file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&region_path).unwrap()).unwrap();
    region_file["placements"][0]["at"] = serde_json::json!([5, 5]);
    std::fs::write(&region_path, serde_json::to_string_pretty(&region_file).unwrap()).unwrap();
    let seal = on(&root, &["project", "doctor", "--absorb"]);
    assert_eq!(seal.status.code(), Some(1), "seal absorb failed: {seal:?}");
    (guard, root)
}

#[test]
fn the_repair_loop_walls_an_npc_in_then_fixes_it() {
    let (_guard, root) = walled_project("w4t");
    let out = on(&root, &["validate", "--all"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rpg.reachability.unreachable_npc"),
        "validate output: {stdout}"
    );

    let plan_path = root.join("plans").join("fix.json");
    let plan = on(
        &root,
        &[
            "plan",
            "--from-finding",
            "rpg.reachability.unreachable_npc",
            "--out",
            plan_path.to_str().unwrap(),
        ],
    );
    assert_eq!(plan.status.code(), Some(0), "plan: {plan:?}");
    assert!(plan_path.exists());

    let apply = on(&root, &["apply", plan_path.to_str().unwrap()]);
    assert_eq!(apply.status.code(), Some(0), "apply: {apply:?}");

    let after = on(&root, &["validate", "--all"]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "the applied fix clears the blocking finding: {}",
        String::from_utf8_lossy(&after.stdout)
    );
}

#[test]
fn validate_json_envelope_carries_suggested_fixes() {
    let (_guard, root) = walled_project("w4j");
    let out = on(&root, &["--json", "validate", "--all"]);
    assert_eq!(out.status.code(), Some(1));
    let line = String::from_utf8_lossy(&out.stdout);
    let envelope: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(envelope["ok"], false);
    let findings = envelope["findings"].as_array().unwrap();
    let npc = findings
        .iter()
        .find(|f| f["code"] == "rpg.reachability.unreachable_npc")
        .expect("the walled npc finding");
    let fixes = npc["suggested_fixes"].as_array().unwrap();
    assert!(!fixes.is_empty());
    assert_eq!(fixes[0]["op_id"], "rpg.set_collision");
}

#[test]
fn an_unknown_finding_is_finding_unknown_exit_2() {
    let (_guard, root) = walled_project("w4u");
    let out = on(
        &root,
        &[
            "--json",
            "plan",
            "--from-finding",
            "finding_0000000000000000",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("finding.unknown"));
}

#[test]
fn an_out_of_range_fix_index_is_finding_no_fix() {
    let (_guard, root) = walled_project("w4n");
    let out = on(
        &root,
        &[
            "--json",
            "plan",
            "--from-finding",
            "rpg.reachability.unreachable_npc",
            "--fix",
            "7",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("finding.no_fix"));
}

#[test]
fn a_code_matching_two_findings_is_finding_ambiguous() {
    let (_guard, root) = init_project("w4a");
    apply(
        &root,
        "rpg.create_region",
        r#"{"id":"town","width":16,"height":16,"spawn":[1,1]}"#,
    );
    // Two warps to two unbuilt regions: two `dangling_target` findings, so
    // the code alone does not select one.
    apply(
        &root,
        "rpg.mark_warp",
        r#"{"region":"town","at":[15,8],"to":{"region":"route_1"}}"#,
    );
    apply(
        &root,
        "rpg.mark_warp",
        r#"{"region":"town","at":[0,8],"to":{"region":"route_2"}}"#,
    );
    let out = on(
        &root,
        &["--json", "plan", "--from-finding", "rpg.warp.dangling_target"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("finding.ambiguous"));
}

#[test]
fn read_only_allows_validate_but_refuses_plan_from_finding() {
    let (_guard, root) = walled_project("w4r");
    let validate = systole()
        .env("SYSTOLE_READ_ONLY", "1")
        .arg("--project")
        .arg(&root)
        .args(["validate", "--all"])
        .output()
        .unwrap();
    assert_eq!(
        validate.status.code(),
        Some(1),
        "validate is a read and stays allowed"
    );

    let plan_path = root.join("plans").join("ro.json");
    let plan = systole()
        .env("SYSTOLE_READ_ONLY", "1")
        .arg("--project")
        .arg(&root)
        .args([
            "plan",
            "--from-finding",
            "rpg.reachability.unreachable_npc",
            "--out",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(plan.status.code(), Some(2));
    assert!(!plan_path.exists(), "the refusal writes no plan file");
}

#[test]
fn validate_output_is_deterministic() {
    let (_guard, root) = walled_project("w4d");
    let a = on(&root, &["--json", "validate", "--all"]);
    let b = on(&root, &["--json", "validate", "--all"]);
    assert_eq!(a.stdout, b.stdout);
    assert!(!a.stdout.is_empty());
}
