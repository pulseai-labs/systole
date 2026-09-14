//! `systole op list` and `systole op describe <id>` — the op catalog.

use std::path::Path;

use super::{compose, mutability_str};

pub fn list(json: bool) -> i32 {
    let (registry, _) = compose();
    if json {
        println!(
            "{}",
            serde_json::to_string(&registry.list()).expect("descriptions serialize")
        );
    } else {
        for m in registry.list_meta() {
            println!(
                "{}  v{}  {}  {}  {}",
                m.id,
                m.version,
                m.capability.as_str(),
                mutability_str(m.mutability),
                m.summary
            );
        }
    }
    0
}

pub fn describe(root: &Path, id: &str, json: bool) -> i32 {
    let (registry, _) = compose();
    match registry.describe(id) {
        Some(desc) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&desc).expect("description serializes")
                );
            } else {
                println!("{}  v{}", desc.id, desc.version);
                println!("{}", desc.summary);
                println!("schema:");
                println!(
                    "{}",
                    String::from_utf8_lossy(&systole_core::ir::format::format_value(
                        &serde_json::to_value(&desc.input_schema)
                            .expect("a schema serializes")
                    ))
                );
                println!("example: {}", desc.example);
                if !desc.avoid_when.is_empty() {
                    println!("avoid when:");
                    for note in &desc.avoid_when {
                        println!("  - {note}");
                    }
                }
            }
            0
        }
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": {
                            "code": "op.unknown",
                            "message": format!("unknown operation: {id}"),
                        },
                        "project_root": root.display().to_string(),
                    })
                );
            } else {
                eprintln!("unknown operation: {id}");
            }
            2
        }
    }
}
