//! Spec-pinned unit tests for r0.s1.w1 (AC-2): canonical format idempotence
//! and byte stability, hash domain exclusions, stable-id rendering,
//! transaction before-images, and the registry describe round-trip.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use systole_core::capability::Capability;
use systole_core::ids::{IdAllocator, IdKind, StableId};
use systole_core::ir::format::format_value;
use systole_core::ir::project::Project;
use systole_core::ir::RelPath;
use systole_core::module::ModuleManifest;
use systole_core::op::{
    Diff, Operation, OperationDescription, OpError, PlanRequest, Stability, Mutability,
};
use systole_core::registry::Registry;
use systole_core::revision;
use systole_core::tx::Transaction;

fn rpg_modules() -> Vec<ModuleManifest> {
    vec![ModuleManifest {
        module_id: "systole.rpg".into(),
        version: "0.1.0".into(),
        schema: 1,
        depends_on: vec![],
    }]
}

fn init_project(dir: &std::path::Path) -> Project {
    Project::init(dir, false, &rpg_modules()).expect("init")
}

#[test]
fn canonical_format_is_idempotent_and_byte_stable() {
    let value = json!({
        "z": 1,
        "a": { "y": [1, 2, { "k": "v" }], "b": null },
        "m": "s"
    });
    let once = format_value(&value);
    let reparsed: serde_json::Value =
        serde_json::from_slice(&once).expect("canonical bytes parse");
    let twice = format_value(&reparsed);
    assert_eq!(once, twice, "format_value is idempotent");
    assert_eq!(*once.last().unwrap(), b'\n', "trailing newline");

    let text = String::from_utf8(once.clone()).unwrap();
    assert!(text.starts_with("{\n  \"a\""), "keys are sorted: {text}");
    let z = text.find("\n  \"z\"").expect("sorted key z present");
    let m = text.find("\n  \"m\"").expect("sorted key m present");
    assert!(z > m, "a < m < z ordering");

    // Byte stability: a separately constructed equal value serializes equally.
    let again = json!({
        "m": "s",
        "a": { "b": null, "y": [1, 2, { "k": "v" }] },
        "z": 1
    });
    assert_eq!(format_value(&again), once, "byte-stable across constructions");

    // Integers never serialize as floats.
    assert!(text.contains("\"z\": 1\n") || text.contains("\"z\": 1\r"));
    assert!(!text.contains("\"z\": 1.0"));
}

#[test]
fn project_hash_excludes_history_dirs_and_blanked_manifest_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let project = init_project(root);
    let recorded_hash = project.manifest.project_hash.clone();

    // Out-of-domain additions do not change the recorded hash or fail verify.
    std::fs::write(root.join("audit/audit.jsonl"), b"{\"entry\": 1}\n").unwrap();
    std::fs::write(root.join("plans/saved.json"), b"{\"plan\": 1}\n").unwrap();
    std::fs::create_dir_all(root.join(".systole")).unwrap();
    std::fs::write(root.join(".systole/write.lock"), b"junk").unwrap();

    let reloaded = Project::load(root).expect("history edits must not refuse the load");
    assert_eq!(reloaded.manifest.project_hash, recorded_hash);
    revision::verify(&reloaded).expect("verify passes with history-only edits");

    // The three blanked fields do not enter the manifest's own hashed bytes.
    let mut edited = project.manifest.clone();
    edited.project_revision = "rev_99999".into();
    edited.audit_head = Some(systole_core::ir::manifest::AuditHead {
        id: "aud_00001".into(),
        hash: "sha256:deadbeef".into(),
    });
    let blank_a = revision::blanked_manifest_value(&project.manifest);
    let blank_b = revision::blanked_manifest_value(&edited);
    assert_eq!(
        format_value(&blank_a),
        format_value(&blank_b),
        "revision and audit_head must be blanked before hashing"
    );
    assert!(blank_a.get("project_hash").unwrap().is_null());
    assert!(blank_a.get("project_revision").unwrap().is_null());
    assert!(blank_a.get("audit_head").unwrap().is_null());
}

#[test]
fn stable_id_renders_with_five_digit_padding() {
    assert_eq!(
        StableId { kind: IdKind::Ent, n: 41 }.to_string(),
        "ent_00041"
    );
    assert_eq!(
        StableId { kind: IdKind::Region, n: 3 }.to_string(),
        "region_00003"
    );
    assert_eq!(
        StableId { kind: IdKind::Flag, n: 12 }.to_string(),
        "flag_00012"
    );

    // One shared counter advances across kinds and never repeats a number.
    let mut alloc = IdAllocator::new(0);
    assert_eq!(alloc.next(IdKind::Ent).to_string(), "ent_00001");
    assert_eq!(alloc.next(IdKind::Region).to_string(), "region_00002");
    assert_eq!(alloc.next(IdKind::Ent).to_string(), "ent_00003");
}

#[test]
fn transaction_records_before_images_as_inverse_data() {
    let tmp = tempfile::tempdir().unwrap();
    let mut project = init_project(tmp.path());

    let existing = RelPath::new("regions/region_00001/region.json");
    let existing_value = json!({ "id": "town" });
    project.files.insert(existing.clone(), existing_value.clone());
    let doomed = RelPath::new("entities/npc/ent_00001.json");
    let doomed_value = json!({ "id": "npc-1" });
    project.files.insert(doomed.clone(), doomed_value.clone());

    let mut tx = Transaction::new(&project);
    tx.write(existing.clone(), json!({ "id": "town", "size": 16 }));
    let fresh = RelPath::new("regions/region_00002/region.json");
    tx.write(fresh.clone(), json!({ "id": "route" }));
    tx.delete(doomed.clone());

    let inverse = tx.inverse();
    let table = inverse.as_object().expect("inverse data is an object");
    assert_eq!(table.get(existing.as_str()), Some(&existing_value));
    assert_eq!(
        table.get(fresh.as_str()),
        Some(&serde_json::Value::Null),
        "a creation's before-image is null"
    );
    assert_eq!(table.get(doomed.as_str()), Some(&doomed_value));

    // Staged-over-project view: reads see the staged state.
    assert_eq!(tx.read(&existing), Some(&json!({ "id": "town", "size": 16 })));
    assert_eq!(tx.read(&fresh), Some(&json!({ "id": "route" })));
    assert_eq!(tx.read(&doomed), None, "deleted path reads back None");

    let staged = tx.staged();
    assert_eq!(staged.len(), 3, "two writes and one delete");
    let ex = staged.iter().find(|c| c.path == existing).unwrap();
    assert_eq!(ex.before, Some(existing_value.clone()));
    assert_eq!(ex.after, Some(json!({ "id": "town", "size": 16 })));
    let dl = staged.iter().find(|c| c.path == doomed).unwrap();
    assert_eq!(dl.before, Some(doomed_value.clone()));
    assert_eq!(dl.after, None, "a delete stages after = None");

    // Id allocations inside a transaction do not touch the project counter.
    let id = tx.alloc_id(IdKind::Ent);
    assert_eq!(id.to_string(), "ent_00001");
    assert_eq!(project.manifest.stable_id_counter, 0);
}

// --- A test-only operation proving the registry contracts -------------------

#[derive(Default)]
struct ProbeOp;

#[derive(Serialize, Deserialize, JsonSchema)]
struct ProbeRequest {
    name: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct ProbePlan {
    name: String,
    upper: String,
}

#[derive(Serialize, JsonSchema)]
struct ProbeOutput {
    name: String,
}

impl Operation for ProbeOp {
    type Request = ProbeRequest;
    type Plan = ProbePlan;
    type Output = ProbeOutput;

    const ID: &'static str = "core.test.probe";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Internal;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "test-only probe operation".into(),
            input_schema: schemars::schema_for!(ProbeRequest),
            example: json!({ "name": "alpha" }),
            avoid_when: vec!["never; test-only".into()],
        }
    }

    fn validate_request(&self, req: &Self::Request) -> Result<(), OpError> {
        if req.name.is_empty() {
            return Err(OpError::InvalidRequest("name must not be empty".into()));
        }
        Ok(())
    }

    fn materialize(
        &self,
        _project: &Project,
        req: Self::Request,
    ) -> Result<Self::Plan, OpError> {
        Ok(ProbePlan {
            upper: req.name.to_uppercase(),
            name: req.name,
        })
    }

    fn diff(&self, _project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let path = RelPath::new(format!("regions/{}/region.json", plan.name));
        Ok(Diff {
            changes: vec![systole_core::op::FileChange {
                path,
                before: None,
                after: Some(json!({ "id": plan.name })),
            }],
        })
    }

    fn validate(
        &self,
        _project: &Project,
        _plan: &Self::Plan,
    ) -> Vec<systole_core::finding::Finding> {
        Vec::new()
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let path = RelPath::new(format!("regions/{}/region.json", plan.name));
        tx.write(path, json!({ "id": plan.name }));
        Ok(ProbeOutput { name: plan.name })
    }
}

#[test]
fn registry_register_then_list_and_describe_round_trips() {
    let mut registry = Registry::new();
    registry.register::<ProbeOp>();

    let expected = ProbeOp::describe();
    let listed = registry.list();
    let seen = listed
        .iter()
        .find(|d| d.id == "core.test.probe")
        .expect("list() contains the registered op");
    assert_eq!(seen.id, expected.id);
    assert_eq!(seen.version, expected.version);
    assert_eq!(seen.summary, expected.summary);
    assert_eq!(seen.example, expected.example);

    let described = registry
        .describe("core.test.probe")
        .expect("describe() finds the registered op");
    assert_eq!(described.id, expected.id);
    assert_eq!(described.version, expected.version);
    assert_eq!(described.avoid_when, expected.avoid_when);
    assert!(registry.describe("core.test.missing").is_none());

    // Envelope dispatch: materialize through the type-erased registry.
    let tmp = tempfile::tempdir().unwrap();
    let project = init_project(tmp.path());
    let plan = registry
        .materialize(
            &project,
            &PlanRequest {
                op_id: "core.test.probe".into(),
                op_version: 1,
                input: json!({ "name": "alpha" }),
                actor: "test".into(),
            },
        )
        .expect("materialize dispatches by envelope");
    assert_eq!(plan.op_id, "core.test.probe");
    assert_eq!(plan.base_project_revision, "rev_00000");
    assert_eq!(plan.payload.get("upper"), Some(&json!("ALPHA")));

    // The diff and apply seams round-trip the payload back through the op.
    let diff = registry.diff(&project, &plan).expect("diff");
    assert_eq!(diff.changes.len(), 1);
    let mut tx = Transaction::new(&project);
    let out = registry.apply(&mut tx, plan).expect("apply");
    assert_eq!(out.get("name"), Some(&json!("alpha")));
    assert_eq!(tx.staged().len(), 1);
}
