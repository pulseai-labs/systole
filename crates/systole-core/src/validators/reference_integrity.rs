//! `core.reference_integrity` — genre-agnostic stable-id checks (ADR-0002,
//! ADR-0003): every field named `stable_id` or ending in `_stable_id` is a
//! reference; it must resolve to a declared object of the kind its field name
//! implies, and objects must be self-consistent. All findings are blocking and
//! carry no kernel fix — Release 0 has no delete or re-id operation, so these
//! states arise only from out-of-band edits and `doctor` names the file.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::finding::{finding_id, Finding, Location, Severity};
use crate::ir::project::Project;
use crate::ir::RelPath;
use crate::module::Validator;

pub const CODE_UNRESOLVED: &str = "core.ref.unresolved";
pub const CODE_KIND_MISMATCH: &str = "core.ref.kind_mismatch";
pub const CODE_STABLE_ID_MISMATCH: &str = "core.object.stable_id_mismatch";
pub const CODE_DUPLICATE_HANDLE: &str = "core.object.duplicate_handle";

/// The known kind prefixes (`IdKind`): a `<kind>_stable_id` field expects its
/// reference to carry that prefix. A bare `stable_id` constrains nothing, and
/// an unknown `<other>_stable_id` prefix resolves against any kind.
const KIND_PREFIXES: [&str; 4] = ["ent", "region", "flag", "warp"];

pub struct ReferenceIntegrity;

impl Validator for ReferenceIntegrity {
    fn id(&self) -> &'static str {
        "core.reference_integrity"
    }

    fn run(&self, project: &Project) -> Vec<Finding> {
        let mut declared: BTreeMap<String, ()> = BTreeMap::new();
        // (object kind, id handle) → the files declaring it.
        let mut handles: BTreeMap<(String, String), Vec<RelPath>> = BTreeMap::new();
        let mut findings = Vec::new();
        // (pointer, field name, referenced value, file path, file's own id).
        let mut refs: Vec<(String, String, String, RelPath, Option<String>)> = Vec::new();

        for (path, value) in &project.files {
            let object = object_file(path);
            let own_stable_id = value.get("stable_id").and_then(Value::as_str);

            if let Some((path_sid, kind)) = &object {
                if let Some(declared_id) = own_stable_id {
                    declared.insert(declared_id.to_string(), ());
                }
                if own_stable_id != Some(path_sid.as_str()) {
                    findings.push(object_finding(
                        CODE_STABLE_ID_MISMATCH,
                        own_stable_id,
                        path,
                        json!({
                            "path_stable_id": path_sid,
                            "declared_stable_id": own_stable_id,
                            "message": format!(
                                "no suggested fix: an object's stable id cannot be re-issued by a \
                                 Release 0 operation — repair {path} by hand or via `systole project doctor`"
                            ),
                        }),
                    ));
                }
                if let Some(handle) = value.get("id").and_then(Value::as_str) {
                    handles
                        .entry((kind.to_string(), handle.to_string()))
                        .or_default()
                        .push(path.clone());
                }
                // A region's `warps[].stable_id` entries are declared inline —
                // registered here and excluded from the reference walk.
                if *kind == "region" {
                    if let Some(warps) = value.get("warps").and_then(Value::as_array) {
                        for warp in warps {
                            if let Some(w) = warp.get("stable_id").and_then(Value::as_str) {
                                declared.insert(w.to_string(), ());
                            }
                        }
                    }
                }
            }

            collect_refs(value, "", object.is_some(), path, own_stable_id, &mut refs);
        }

        for (pointer, field, referenced, path, own_id) in refs {
            if !declared.contains_key(&referenced) {
                findings.push(object_finding(
                    CODE_UNRESOLVED,
                    own_id.as_deref(),
                    &path,
                    json!({
                        "pointer": pointer,
                        "value": referenced,
                        "message": format!(
                            "no suggested fix: stable-id references cannot be repaired by a \
                             Release 0 operation — repair {path} by hand or via `systole project doctor`"
                        ),
                    }),
                ));
                continue;
            }
            if let Some(expected) = expected_prefix(&field) {
                if id_prefix(&referenced) != Some(expected) {
                    findings.push(object_finding(
                        CODE_KIND_MISMATCH,
                        own_id.as_deref(),
                        &path,
                        json!({
                            "pointer": pointer,
                            "value": referenced,
                            "expected_kind": expected,
                            "actual_kind": id_prefix(&referenced),
                            "message": format!(
                                "no suggested fix: stable-id references cannot be repaired by a \
                                 Release 0 operation — repair {path} by hand or via `systole project doctor`"
                            ),
                        }),
                    ));
                }
            }
        }

        for ((kind, handle), paths) in &handles {
            if paths.len() > 1 {
                let first = &paths[0];
                let first_id = project
                    .files
                    .get(first)
                    .and_then(|v| v.get("stable_id"))
                    .and_then(Value::as_str);
                findings.push(object_finding(
                    CODE_DUPLICATE_HANDLE,
                    first_id,
                    first,
                    json!({
                        "kind": kind,
                        "id": handle,
                        "paths": paths.iter().map(RelPath::as_str).collect::<Vec<_>>(),
                        "message": format!(
                            "no suggested fix: duplicate handles cannot be resolved by a Release 0 \
                             operation — repair {first} by hand or via `systole project doctor`"
                        ),
                    }),
                ));
            }
        }

        findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
        findings
    }
}

/// The `(path stable id, handle kind)` of an addressable object file:
/// `regions/<sid>/region.json` → (`<sid>`, `region`);
/// `entities/<kind>/<sid>.json` → (`<sid>`, `<kind>`). Any other file is
/// walked for references but declares no object.
fn object_file(path: &RelPath) -> Option<(String, String)> {
    let segs: Vec<&str> = path.as_str().split('/').collect();
    match segs.as_slice() {
        ["regions", sid, "region.json"] => Some((sid.to_string(), "region".to_string())),
        ["entities", kind, file] => file
            .strip_suffix(".json")
            .map(|sid| (sid.to_string(), kind.to_string())),
        _ => None,
    }
}

/// A finding located at the file that produced it; the id comes from the
/// single shared formula.
fn object_finding(
    code: &str,
    stable_id: Option<&str>,
    path: &RelPath,
    evidence: Value,
) -> Finding {
    let location = Location {
        stable_id: stable_id.map(str::to_string),
        path: Some(path.clone()),
    };
    Finding {
        finding_id: finding_id(code, &location, &evidence),
        code: code.to_string(),
        severity: Severity::Error,
        location,
        evidence,
        suggested_fixes: Vec::new(),
        blocking: true,
    }
}

/// Walk a JSON value collecting `(pointer, field, value)` for every
/// `stable_id`/`*_stable_id` string field that is a reference — everything
/// except the object file's own top-level `stable_id` (a self-declaration)
/// and `warps[i].stable_id` (inline warp declarations). `null` is not a
/// reference.
fn collect_refs(
    value: &Value,
    pointer: &str,
    is_object_file: bool,
    path: &RelPath,
    own_stable_id: Option<&str>,
    out: &mut Vec<(String, String, String, RelPath, Option<String>)>,
) {
    if let Value::Object(map) = value {
        for (key, child) in map {
            let child_pointer = format!("{pointer}/{}", escape_pointer(key));
            let is_reference = if key == "stable_id" || key.ends_with("_stable_id") {
                match child {
                    Value::String(_) => {
                        !(pointer.is_empty() && is_object_file && key == "stable_id")
                            && !is_warp_declaration(&child_pointer)
                    }
                    _ => false, // null and non-strings are not references
                }
            } else {
                false
            };
            if is_reference {
                out.push((
                    child_pointer.clone(),
                    key.clone(),
                    child.as_str().unwrap_or_default().to_string(),
                    path.clone(),
                    own_stable_id.map(str::to_string),
                ));
            }
            collect_refs(
                child,
                &child_pointer,
                is_object_file,
                path,
                own_stable_id,
                out,
            );
        }
    } else if let Value::Array(items) = value {
        for (i, item) in items.iter().enumerate() {
            collect_refs(
                item,
                &format!("{pointer}/{i}"),
                is_object_file,
                path,
                own_stable_id,
                out,
            );
        }
    }
}

/// `/warps/<n>/stable_id` — the inline declaration of a warp object.
fn is_warp_declaration(pointer: &str) -> bool {
    let segs: Vec<&str> = pointer.split('/').collect();
    segs.len() == 4 && segs[1] == "warps" && segs[3] == "stable_id"
}

/// RFC-6901 escaping for object keys inside a pointer.
fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// The kind a `<kind>_stable_id` field expects, when `<kind>` is a known
/// `IdKind` prefix; `None` for bare `stable_id` and unknown prefixes.
fn expected_prefix(field: &str) -> Option<&'static str> {
    let prefix = field.strip_suffix("_stable_id")?;
    KIND_PREFIXES.iter().find(|k| **k == prefix).copied()
}

/// The kind prefix of a stable id's string form (`ent_00002` → `ent`).
fn id_prefix(stable_id: &str) -> Option<&str> {
    stable_id.split_once('_').map(|(prefix, _)| prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::ir::lock::Lock;
    use crate::ir::manifest::{Engine, Manifest, ModuleEntry};
    use crate::module::Validator;

    fn project(files: Vec<(&str, Value)>) -> Project {
        let engine = Engine {
            name: "systole".into(),
            version: "0.1.0".into(),
        };
        Project {
            root: PathBuf::new(),
            manifest: Manifest {
                engine: engine.clone(),
                project_schema: 1,
                modules: BTreeMap::from([(
                    "systole.rpg".to_string(),
                    ModuleEntry {
                        version: "0.1.0".into(),
                        schema: 1,
                    },
                )]),
                stable_id_counter: 0,
                project_revision: "rev_00000".into(),
                project_hash: "sha256:test".into(),
                audit_head: None,
                files: BTreeMap::new(),
            },
            lock: Lock {
                engine,
                modules: BTreeMap::new(),
            },
            files: files
                .into_iter()
                .map(|(p, v)| (RelPath::new(p), v))
                .collect(),
        }
    }

    /// The smallest self-consistent town: one region whose placement names an
    /// entity that exists, and one dangling-free warp.
    fn clean_project() -> Project {
        project(vec![
            (
                "regions/region_00001/region.json",
                json!({
                    "id": "town",
                    "stable_id": "region_00001",
                    "kind": "region",
                    "placements": [
                        {"stable_id": "ent_00002", "at": [5, 5], "facing": "down"}
                    ],
                    "warps": [
                        {
                            "stable_id": "warp_00003",
                            "at": [15, 8],
                            "to": {
                                "region_id": "route_1",
                                "region_stable_id": "region_00004",
                                "at": null
                            }
                        }
                    ]
                }),
            ),
            (
                "entities/npc/ent_00002.json",
                json!({"id": "elder", "stable_id": "ent_00002", "kind": "npc"}),
            ),
            (
                "regions/region_00004/region.json",
                json!({
                    "id": "route_1",
                    "stable_id": "region_00004",
                    "kind": "region",
                    "placements": [],
                    "warps": []
                }),
            ),
        ])
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.code.as_str()).collect()
    }

    #[test]
    fn a_clean_project_yields_no_findings() {
        let findings = ReferenceIntegrity.run(&clean_project());
        assert!(findings.is_empty(), "unexpected: {findings:?}");
    }

    #[test]
    fn an_unresolved_placement_reference_is_a_blocking_finding() {
        let mut p = clean_project();
        let region = p
            .files
            .get_mut(&RelPath::new("regions/region_00001/region.json"))
            .unwrap();
        region["placements"][0]["stable_id"] = json!("ent_09999");
        let findings = ReferenceIntegrity.run(&p);
        assert_eq!(codes(&findings), vec![CODE_UNRESOLVED]);
        assert!(findings[0].blocking);
        assert_eq!(findings[0].evidence["pointer"], "/placements/0/stable_id");
        assert_eq!(findings[0].evidence["value"], "ent_09999");
        assert!(findings[0].suggested_fixes.is_empty());
        assert!(findings[0].evidence["message"]
            .as_str()
            .is_some_and(|m| m.contains("doctor")));
    }

    #[test]
    fn a_reference_to_the_wrong_kind_is_kind_mismatch() {
        let mut p = clean_project();
        let region = p
            .files
            .get_mut(&RelPath::new("regions/region_00001/region.json"))
            .unwrap();
        region["warps"][0]["to"]["region_stable_id"] = json!("ent_00002");
        let findings = ReferenceIntegrity.run(&p);
        assert_eq!(codes(&findings), vec![CODE_KIND_MISMATCH]);
        assert_eq!(findings[0].evidence["expected_kind"], "region");
        assert_eq!(findings[0].evidence["actual_kind"], "ent");
    }

    #[test]
    fn a_stable_id_that_disagrees_with_its_path_is_a_mismatch() {
        let mut p = clean_project();
        let entity = p
            .files
            .get_mut(&RelPath::new("entities/npc/ent_00002.json"))
            .unwrap();
        entity["stable_id"] = json!("ent_00004");
        let findings = ReferenceIntegrity.run(&p);
        // The placement still references ent_00002, which nothing declares
        // now — both findings are truthful (sorted by finding_id).
        let mut got = codes(&findings);
        got.sort_unstable();
        assert_eq!(got, vec![CODE_STABLE_ID_MISMATCH, CODE_UNRESOLVED]);
    }

    #[test]
    fn two_objects_of_one_kind_sharing_a_handle_is_a_duplicate() {
        let mut files: Vec<(&str, Value)> = Vec::new();
        files.push((
            "entities/npc/ent_00001.json",
            json!({"id": "elder", "stable_id": "ent_00001", "kind": "npc"}),
        ));
        files.push((
            "entities/npc/ent_00002.json",
            json!({"id": "elder", "stable_id": "ent_00002", "kind": "npc"}),
        ));
        files.push((
            "entities/item/ent_00003.json",
            json!({"id": "elder", "stable_id": "ent_00003", "kind": "item"}),
        ));
        let findings = ReferenceIntegrity.run(&project(files));
        assert_eq!(codes(&findings), vec![CODE_DUPLICATE_HANDLE]);
        assert_eq!(findings[0].evidence["id"], "elder");
        assert_eq!(findings[0].evidence["paths"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_null_reference_emits_nothing() {
        let mut p = clean_project();
        let region = p
            .files
            .get_mut(&RelPath::new("regions/region_00001/region.json"))
            .unwrap();
        region["warps"][0]["to"]["region_stable_id"] = Value::Null;
        assert!(ReferenceIntegrity.run(&p).is_empty());
    }

    #[test]
    fn finding_ids_are_deterministic_and_evidence_bound() {
        let a = ReferenceIntegrity.run(&clean_project_with_broken_ref());
        let b = ReferenceIntegrity.run(&clean_project_with_broken_ref());
        assert_eq!(a[0].finding_id, b[0].finding_id);
        assert!(a[0].finding_id.starts_with("finding_"));
        let c = ReferenceIntegrity.run(&clean_project_with_broken_ref_at("/warps/0/to/region_stable_id"));
        assert_ne!(a[0].finding_id, c[0].finding_id);
    }

    fn clean_project_with_broken_ref() -> Project {
        let mut p = clean_project();
        p.files
            .get_mut(&RelPath::new("regions/region_00001/region.json"))
            .unwrap()["placements"][0]["stable_id"] = json!("ent_09999");
        p
    }

    fn clean_project_with_broken_ref_at(_pointer: &str) -> Project {
        let mut p = clean_project();
        p.files
            .get_mut(&RelPath::new("regions/region_00001/region.json"))
            .unwrap()["warps"][0]["to"]["region_stable_id"] = json!("ent_09999");
        p
    }
}
