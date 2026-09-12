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
