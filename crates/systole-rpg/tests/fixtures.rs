//! Fixture-driven coverage: `tests/fixtures/<op>/{success,failure}.json`
//! drives every registered `rpg.*` op through the request envelope path.
//! Setup steps build project state in memory; the request then asserts on the
//! op's output, findings, and staged files (or its error code on failure).

mod common;

use std::path::PathBuf;

use serde_json::Value;
use systole_core::ir::RelPath;

const OPS: [&str; 7] = [
    "create_region",
    "mark_warp",
    "paint_area",
    "paint_path",
    "place_npc",
    "query_region",
    "set_collision",
];

fn load(op: &str, name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(op)
        .join(format!("{name}.json"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

#[test]
fn fixtures() {
    for op in OPS {
        for name in ["success", "failure"] {
            let fixture = load(op, name);
            let label = format!("{op}/{name}");
            let mut project = common::project();

            let empty = Vec::new();
            for step in fixture["setup"].as_array().unwrap_or(&empty) {
                let out = common::run(
                    &mut project,
                    step["op_id"].as_str().unwrap(),
                    step["input"].clone(),
                )
                .unwrap_or_else(|e| panic!("{label} setup {}: {e}", step["op_id"]));
                assert!(
                    !out.findings.iter().any(|f| f.blocking),
                    "{label} setup was blocked"
                );
            }

            let op_id = format!("rpg.{op}");
            let expect = &fixture["expect"];
            let result = common::run(&mut project, &op_id, fixture["request"].clone());

            if expect["ok"].as_bool().unwrap() {
                let out = result.unwrap_or_else(|e| panic!("{label}: {e}"));
                let blocking: Vec<&str> = out
                    .findings
                    .iter()
                    .filter(|f| f.blocking)
                    .map(|f| f.code.as_str())
                    .collect();
                assert!(blocking.is_empty(), "{label}: blocking findings {blocking:?}");

                if let Some(expected) = expect["output"].as_object() {
                    for (key, v) in expected {
                        assert_eq!(&out.output[key], v, "{label}: output.{key}");
                    }
                }
                for path in expect["files"].as_array().unwrap_or(&empty) {
                    let rel = RelPath::new(path.as_str().unwrap());
                    assert!(project.files.contains_key(&rel), "{label}: missing {rel}");
                }
                let mut want: Vec<&str> = expect["findings"]
                    .as_array()
                    .unwrap_or(&empty)
                    .iter()
                    .map(|c| c.as_str().unwrap())
                    .collect();
                let mut got: Vec<&str> = out.findings.iter().map(|f| f.code.as_str()).collect();
                want.sort();
                got.sort();
                assert_eq!(got, want, "{label}: finding codes");
            } else {
                let code = expect["error_code"].as_str().unwrap();
                match result {
                    Err(e) => {
                        assert!(e.to_string().contains(code), "{label}: {e} lacks {code}");
                    }
                    Ok(out) => {
                        let blocking = out
                            .findings
                            .iter()
                            .find(|f| f.blocking)
                            .unwrap_or_else(|| panic!("{label}: expected failure, got none"));
                        assert_eq!(blocking.code, code, "{label}: blocking code");
                    }
                }
            }
        }
    }
}
