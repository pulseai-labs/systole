//! CLI behavior locks for r0.s1.w1: the `SYSTOLE_READ_ONLY` kill switch's
//! scope (writes refused, reads allowed), the non-empty init refusal, and the
//! clean-checkout check on `examples/reference`.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn systole() -> Command {
    Command::new(env!("CARGO_BIN_EXE_systole"))
}

/// A fresh tempdir plus a not-yet-created project path inside it; the TempDir
/// cleans up when the test ends.
fn temp_project(tag: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(tag);
    (dir, path)
}

#[test]
fn read_only_refuses_init_and_writes_nothing() {
    let (_guard, target) = temp_project("w1f");
    let out = systole()
        .env("SYSTOLE_READ_ONLY", "1")
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!target.exists(), "the kill switch must create nothing");
    assert!(String::from_utf8_lossy(&out.stderr).contains("refused"));
}

#[test]
fn read_only_refuses_format_write_but_allows_format_check() {
    let (_guard, target) = temp_project("w1ro");
    let init = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));

    let write = systole()
        .env("SYSTOLE_READ_ONLY", "1")
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("format")
        .output()
        .unwrap();
    assert_eq!(
        write.status.code(),
        Some(2),
        "format without --check is a write and must be refused"
    );

    let check = systole()
        .env("SYSTOLE_READ_ONLY", "1")
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("format")
        .arg("--check")
        .output()
        .unwrap();
    assert_eq!(
        check.status.code(),
        Some(0),
        "format --check is a read and stays allowed under the kill switch"
    );

    let plain_check = systole()
        .env("SYSTOLE_READ_ONLY", "1")
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(plain_check.status.code(), Some(0));
}

#[test]
fn init_refuses_a_non_empty_directory_with_exit_2() {
    let (_guard, target) = temp_project("w1b");
    let first = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0));

    let second = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&second.stderr);
    let expected = format!(
        "refused: {} is not empty; pass --force {} to initialize anyway",
        target.display(),
        target.display()
    );
    assert!(
        stderr.contains(&expected),
        "refusal text must name the directory: {stderr}"
    );

    let forced = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .arg("--force")
        .output()
        .unwrap();
    assert_eq!(forced.status.code(), Some(0), "--force proceeds");
}

#[test]
fn format_refuses_while_a_pending_marker_exists() {
    let (_guard, target) = temp_project("w1fmt");
    let init = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));

    // The marker an interrupted commit leaves behind in audit/pending/.
    std::fs::write(
        target.join("audit/pending/tx_probe.json"),
        "{\"transaction_id\":\"tx_probe\",\"phase\":\"prepared\",\"plan_id\":null,\"files\":[]}",
    )
    .unwrap();

    let fmt = systole()
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("format")
        .output()
        .unwrap();
    assert_eq!(
        fmt.status.code(),
        Some(2),
        "format refuses while a marker is pending"
    );
    assert!(
        String::from_utf8_lossy(&fmt.stderr).contains("doctor"),
        "the refusal names doctor: {}",
        String::from_utf8_lossy(&fmt.stderr)
    );

    // --check is a read: it stays allowed.
    let check = systole()
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("format")
        .arg("--check")
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(0));
}

#[test]
fn pending_marker_refuses_every_operation_until_doctor() {
    let (_guard, target) = temp_project("w1pend");
    let init = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));

    std::fs::write(
        target.join("audit/pending/tx_probe.json"),
        "{\"transaction_id\":\"tx_probe\",\"phase\":\"prepared\",\"plan_id\":null,\"files\":[]}",
    )
    .unwrap();

    for args in [
        vec!["validate", "--all"],
        vec!["apply", "rpg.create_region", "--input", "{}"],
        vec!["rollback", "aud_00001"],
    ] {
        let out = systole()
            .arg("--project")
            .arg(&target)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} refuses while a marker is pending"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("doctor"),
            "{args:?} names doctor: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn check_and_open_refuse_a_tampered_audit_log() {
    let (_guard, target) = temp_project("w1aud");
    let init = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));
    let applied = systole()
        .arg("--project")
        .arg(&target)
        .arg("apply")
        .arg("rpg.create_region")
        .arg("--input")
        .arg(r#"{"id":"town","width":16,"height":16,"spawn":[1,1]}"#)
        .output()
        .unwrap();
    assert_eq!(applied.status.code(), Some(0));

    // A truncation the project hash cannot see: audit/ is outside it.
    // The manifest still names aud_00001 but the log no longer reaches it.
    let log = target.join("audit/audit.jsonl");
    let mut bytes = std::fs::read(&log).unwrap();
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    let keep = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    bytes.truncate(keep);
    std::fs::write(&log, &bytes).unwrap();

    let check = systole()
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2), "check refuses a broken chain");
    assert!(
        String::from_utf8_lossy(&check.stderr).contains("audit chain broken"),
        "stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    let validated = systole()
        .arg("--project")
        .arg(&target)
        .arg("validate")
        .arg("--all")
        .output()
        .unwrap();
    assert_eq!(
        validated.status.code(),
        Some(2),
        "every Engine::open path refuses a broken chain"
    );
}

#[test]
fn reference_project_passes_check_from_checkout() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let out = systole()
        .arg("--project")
        .arg(root.join("examples/reference"))
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("project ok"));
}

#[test]
fn force_init_replaces_the_tree_atomically() {
    let (_guard, target) = temp_project("w1force");
    let init = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));
    let applied = systole()
        .arg("--project")
        .arg(&target)
        .arg("apply")
        .arg("rpg.create_region")
        .arg("--input")
        .arg(r#"{"id":"town","width":16,"height":16,"spawn":[1,1]}"#)
        .output()
        .unwrap();
    assert_eq!(applied.status.code(), Some(0));
    assert!(target.join("regions/region_00001").exists());
    assert!(std::fs::read_to_string(target.join("audit/audit.jsonl"))
        .unwrap()
        .contains("aud_00001"));

    let forced = systole()
        .arg("project")
        .arg("init")
        .arg(&target)
        .arg("--force")
        .output()
        .unwrap();
    assert_eq!(forced.status.code(), Some(0), "--force proceeds");

    // The fresh layout is whole: no stale region, empty audit, rev_00000,
    // and `project check` passes — the old tree was swapped out, not
    // truncated in place.
    assert!(
        !target.join("regions/region_00001").exists(),
        "stale IR files are gone"
    );
    assert!(
        std::fs::read_to_string(target.join("audit/audit.jsonl"))
            .unwrap()
            .is_empty(),
        "audit log replaced, not left stale"
    );
    let check = systole()
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(0));
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(target.join("project.systole.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["project_revision"], "rev_00000");
    // No scratch dirs leaked beside the project.
    let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".systole-init")
        })
        .collect();
    assert!(leftovers.is_empty(), "staging/trash cleaned up");
}

/// `project check --json` keeps the structured contract on failure: missing
/// and malformed projects emit a parseable error object on stdout, not
/// human-only text on stderr.
#[test]
fn check_json_emits_structured_errors_for_missing_and_broken_projects() {
    let (_guard, target) = temp_project("w1j");

    // Missing project.
    let missing = systole()
        .arg("--json")
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let parsed: serde_json::Value =
        serde_json::from_slice(&missing.stdout).expect("missing-project output parses as JSON");
    assert!(parsed["error"]["code"].is_string());

    // Malformed manifest.
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("project.systole.json"), b"{ not json").unwrap();
    let broken = systole()
        .arg("--json")
        .arg("--project")
        .arg(&target)
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(broken.status.code(), Some(2));
    let parsed: serde_json::Value =
        serde_json::from_slice(&broken.stdout).expect("malformed-project output parses as JSON");
    assert!(parsed["error"]["code"].is_string());

    // Integrity failure: a hand-edited IR file under --json.
    let (_guard2, target2) = temp_project("w1j2");
    let init = systole()
        .arg("project")
        .arg("init")
        .arg(&target2)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));
    std::fs::create_dir_all(target2.join("entities/note")).unwrap();
    std::fs::write(
        target2.join("entities/note/extra.json"),
        b"{\"kind\": \"note\"}",
    )
    .unwrap();
    let tampered = systole()
        .arg("--json")
        .arg("--project")
        .arg(&target2)
        .arg("project")
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(tampered.status.code(), Some(2));
    let parsed: serde_json::Value =
        serde_json::from_slice(&tampered.stdout).expect("integrity-failure output parses as JSON");
    assert_eq!(parsed["error"]["code"], "project.integrity");
}
