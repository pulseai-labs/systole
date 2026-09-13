//! Engine-side tests for r0.s1.w2 (AC-2): the capability policy, the write
//! lock, the audit chain, the two-phase commit, rollback, doctor, and the
//! determinism invariant.

use serde_json::json;
use systole_core::audit::{self, AuditEntry};
use systole_core::capability::{Capability, Decision, Policy};
use systole_core::ir::format::format_line;
use systole_core::ir::manifest::AuditHead;
use systole_core::lock::{LockError, WriteLock};
use systole_core::op::FileChange;
use systole_core::ir::RelPath;
use systole_core::revision::digest_of;

#[test]
fn policy_table_allows_prompts_denies_and_unknown_actors_deny_all() {
    // cli_local: allow project.read / project.write, prompt destructive.delete,
    // deny everything else.
    assert_eq!(
        Policy::resolve("cli_local", Capability::ProjectRead),
        Decision::Allow
    );
    assert_eq!(
        Policy::resolve("cli_local", Capability::ProjectWrite),
        Decision::Allow
    );
    assert_eq!(
        Policy::resolve("cli_local", Capability::DestructiveDelete),
        Decision::Prompt
    );
    for cap in [
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::NetworkCall,
        Capability::SecretsRead,
        Capability::AssetImport,
        Capability::AssetGenerateRemote,
        Capability::RuntimeLaunch,
        Capability::BundleWrite,
    ] {
        assert_eq!(
            Policy::resolve("cli_local", cap),
            Decision::Deny,
            "{cap:?} must be denied for cli_local"
        );
    }
    // An unknown actor is deny-all, even for project.read.
    assert_eq!(
        Policy::resolve("nobody", Capability::ProjectRead),
        Decision::Deny
    );
}

#[test]
fn write_lock_refuses_a_second_holder_and_names_its_pid() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let first = WriteLock::acquire(root).expect("first acquire succeeds");
    let held = WriteLock::acquire(root).expect_err("second acquire is refused");
    match held {
        LockError::Held { pid } => assert_eq!(pid, std::process::id()),
        other => panic!("expected Held, got {other:?}"),
    }
    assert!(root.join(".systole/write.lock").exists());

    drop(first);
    let third = WriteLock::acquire(root).expect("released lock re-acquires");
    drop(third);
}

// --- audit chain -----------------------------------------------------------

fn fake_entry(n: u64, prev_hash: &str) -> AuditEntry {
    AuditEntry {
        audit_id: format!("aud_{n:05}"),
        transaction_id: format!("tx_{n:016x}"),
        timestamp: "2026-09-13T00:00:00Z".into(),
        actor: "cli_local".into(),
        op_id: "core.test".into(),
        op_version: 1,
        input_hash: digest_of(b"input"),
        plan_id: Some("plan_deadbeef".into()),
        capability: "project.write".into(),
        approval: "allow".into(),
        base_project_revision: format!("rev_{:05}", n - 1),
        project_revision: format!("rev_{n:05}"),
        pre_project_hash: digest_of(b"pre"),
        post_project_hash: digest_of(b"post"),
        changes: vec![FileChange {
            path: RelPath::new("entities/note/ent_00001.json"),
            before: None,
            after: Some(json!({ "id": "note.ent_00001" })),
        }],
        output: json!({ "stable_id": "ent_00001" }),
        rollback_of: None,
        hash_alg: "sha256".into(),
        prev_hash: prev_hash.into(),
    }
}

fn write_log(root: &std::path::Path, lines: &[Vec<u8>]) {
    let audit_dir = root.join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
    }
    std::fs::write(audit_dir.join("audit.jsonl"), bytes).unwrap();
}

#[test]
fn audit_entry_serializes_as_one_compact_canonical_line() {
    let entry = fake_entry(1, audit::GENESIS_PREV_HASH);
    let line = audit::canonical_line(&entry);
    let text = String::from_utf8(line.clone()).unwrap();
    assert!(!text.contains('\n'), "one line, no embedded newline");
    assert!(text.starts_with("{\""));
    assert!(!text.contains("\": "), "compact, no insignificant whitespace");
    // Sorted keys: audit_id is the first key byte-wise.
    assert!(text.starts_with("{\"actor\"") || text.starts_with("{\"approval\"") || text.starts_with("{\"audit_id\""), "keys sorted: {text}");
    // Round-trips through parse unchanged (it is already canonical).
    let reparsed: serde_json::Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(format_line(&reparsed), line);
    // rollback_of is absent unless set.
    assert!(!text.contains("rollback_of"));
    let mut rb = entry.clone();
    rb.rollback_of = Some("aud_00000".into());
    assert!(String::from_utf8(audit::canonical_line(&rb))
        .unwrap()
        .contains("\"rollback_of\":\"aud_00000\""));
}

#[test]
fn audit_chain_verifies_and_a_tampered_middle_entry_breaks_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let e1 = fake_entry(1, audit::GENESIS_PREV_HASH);
    let l1 = audit::canonical_line(&e1);
    let e2 = fake_entry(2, &digest_of(&l1));
    let l2 = audit::canonical_line(&e2);
    let e3 = fake_entry(3, &digest_of(&l2));
    let l3 = audit::canonical_line(&e3);
    write_log(root, &[l1.clone(), l2.clone(), l3.clone()]);

    let head = AuditHead {
        id: "aud_00003".into(),
        hash: digest_of(&l3),
    };
    let entries = audit::verify_chain(root, Some(&head)).expect("clean chain verifies");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].prev_hash, audit::GENESIS_PREV_HASH);

    // Tamper with the middle entry, keeping the line canonical: the successor's
    // prev_hash then disagrees — the first bad entry is aud_00003 at index 2.
    let mut tampered = e2.clone();
    tampered.output = json!({ "stable_id": "ent_99999" });
    let l2t = audit::canonical_line(&tampered);
    write_log(root, &[l1.clone(), l2t, l3.clone()]);
    let brk = audit::verify_chain(root, Some(&head)).expect_err("tampered chain must break");
    assert_eq!(brk.index, 2, "the first entry that fails verification is the successor");
    assert_eq!(brk.audit_id.as_deref(), Some("aud_00003"));
    assert!(brk.reason.contains("prev_hash"), "{}", brk.reason);

    // A tampered audit_id breaks at the tampered entry itself.
    let mut tampered_id = e2.clone();
    tampered_id.audit_id = "aud_00007".into();
    let l2i = audit::canonical_line(&tampered_id);
    write_log(root, &[l1.clone(), l2i, l3.clone()]);
    let brk2 = audit::verify_chain(root, Some(&head)).expect_err("id tamper must break");
    assert_eq!(brk2.index, 1);
}

#[test]
fn audit_head_must_name_the_last_line() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let e1 = fake_entry(1, audit::GENESIS_PREV_HASH);
    let l1 = audit::canonical_line(&e1);
    write_log(root, &[l1.clone()]);

    // Head pointing at a different hash breaks.
    let wrong = AuditHead {
        id: "aud_00001".into(),
        hash: digest_of(b"not-the-line"),
    };
    assert!(audit::verify_chain(root, Some(&wrong)).is_err());
    // Entries present but manifest head null breaks.
    assert!(audit::verify_chain(root, None).is_err());
    // Head set but log empty breaks.
    std::fs::write(root.join("audit/audit.jsonl"), b"").unwrap();
    let some = AuditHead {
        id: "aud_00001".into(),
        hash: digest_of(&l1),
    };
    assert!(audit::verify_chain(root, Some(&some)).is_err());
    // Empty log + null head verifies (a fresh project).
    assert_eq!(
        audit::verify_chain(root, None).unwrap().len(),
        0
    );
}

#[test]
fn rfc3339_timestamps_match_known_epochs() {
    assert_eq!(audit::rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
    assert_eq!(audit::rfc3339_from_unix(1700000000), "2023-11-14T22:13:20Z");
    assert_eq!(audit::rfc3339_from_unix(951827696), "2000-02-29T12:34:56Z");
}

// --- engine / two-phase commit / doctor ------------------------------------

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use systole_core::doctor;
use systole_core::engine::{Engine, EngineError};
use systole_core::finding::{Finding, Location, Severity};
use systole_core::ir::project::{Project, ProjectError};
use systole_core::module::ModuleManifest;
use systole_core::op::{
    Diff, Mutability, Operation, OperationDescription, OpError, PlanRequest, Stability,
};
use systole_core::registry::Registry;
use systole_core::tx::commit as two_phase;
use systole_core::tx::Transaction;

fn rpg_modules() -> Vec<ModuleManifest> {
    vec![ModuleManifest {
        module_id: "systole.rpg".into(),
        version: "0.1.0".into(),
        schema: 1,
        depends_on: vec![],
    }]
}

/// A write op shaped like the spec's fixture.put_note: allocates
/// `entities/note/ent_NNNNN.json`; empty text is a blocking finding.
#[derive(Default)]
struct NoteOp;

#[derive(Serialize, Deserialize, JsonSchema)]
struct NoteReq {
    text: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct NotePlan {
    text: String,
}

#[derive(Serialize, JsonSchema)]
struct NoteOut {
    stable_id: String,
}

fn note_path(n: u64) -> RelPath {
    RelPath::new(format!("entities/note/ent_{n:05}.json"))
}

fn note_value(sid: &str, text: &str) -> serde_json::Value {
    json!({
        "id": format!("note.{sid}"),
        "stable_id": sid,
        "kind": "note",
        "tags": [],
        "intent": "",
        "constraints": [],
        "owner_module": "test",
        "text": text,
    })
}

impl Operation for NoteOp {
    type Request = NoteReq;
    type Plan = NotePlan;
    type Output = NoteOut;

    const ID: &'static str = "test.put_note";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Internal;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "write a note entity".into(),
            input_schema: schemars::schema_for!(NoteReq),
            example: json!({ "text": "hello" }),
            avoid_when: vec!["test-only".into()],
        }
    }

    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }

    fn materialize(&self, _project: &Project, req: Self::Request) -> Result<Self::Plan, OpError> {
        Ok(NotePlan { text: req.text })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let path = note_path(project.manifest.stable_id_counter + 1);
        Ok(Diff {
            changes: vec![FileChange {
                path: path.clone(),
                before: project.files.get(&path).cloned(),
                after: Some(note_value(
                    &format!("ent_{:05}", project.manifest.stable_id_counter + 1),
                    &plan.text,
                )),
            }],
        })
    }

    fn validate(&self, _project: &Project, plan: &Self::Plan) -> Vec<Finding> {
        if plan.text.is_empty() {
            return vec![Finding {
                finding_id: "test.note.empty".into(),
                code: "test.note.empty".into(),
                severity: Severity::Error,
                location: Location {
                    stable_id: None,
                    path: Some(note_path(1)),
                },
                evidence: json!({}),
                suggested_fixes: vec![],
                blocking: true,
            }];
        }
        Vec::new()
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let sid = tx.alloc_id(systole_core::ids::IdKind::Ent).to_string();
        tx.write(note_path(sid[4..].parse().unwrap()), note_value(&sid, &plan.text));
        Ok(NoteOut { stable_id: sid })
    }
}

/// A write op that never materializes under the policy (denied capability).
#[derive(Default)]
struct NetOp;

#[derive(Serialize, Deserialize, JsonSchema)]
struct EmptyReq {}

#[derive(Serialize, Deserialize, JsonSchema)]
struct EmptyPlan {}

#[derive(Serialize, JsonSchema)]
struct EmptyOut {}

impl Operation for NetOp {
    type Request = EmptyReq;
    type Plan = EmptyPlan;
    type Output = EmptyOut;

    const ID: &'static str = "test.net";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::NetworkCall;
    const STABILITY: Stability = Stability::Internal;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "denied capability probe".into(),
            input_schema: schemars::schema_for!(EmptyReq),
            example: json!({}),
            avoid_when: vec!["always".into()],
        }
    }
    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }
    fn materialize(&self, _p: &Project, _r: Self::Request) -> Result<Self::Plan, OpError> {
        Ok(EmptyPlan {})
    }
    fn diff(&self, _p: &Project, _pl: &Self::Plan) -> Result<Diff, OpError> {
        Ok(Diff { changes: vec![] })
    }
    fn validate(&self, _p: &Project, _pl: &Self::Plan) -> Vec<Finding> {
        Vec::new()
    }
    fn apply(&self, _tx: &mut Transaction, _pl: Self::Plan) -> Result<Self::Output, OpError> {
        Ok(EmptyOut {})
    }
}

/// A write op declaring destructive.delete — resolves to prompt, refused.
#[derive(Default)]
struct DelOp;

impl Operation for DelOp {
    type Request = EmptyReq;
    type Plan = EmptyPlan;
    type Output = EmptyOut;

    const ID: &'static str = "test.del";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::DestructiveDelete;
    const STABILITY: Stability = Stability::Internal;
    const MUTABILITY: Mutability = Mutability::Destructive;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "prompt-capability probe".into(),
            input_schema: schemars::schema_for!(EmptyReq),
            example: json!({}),
            avoid_when: vec!["always".into()],
        }
    }
    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }
    fn materialize(&self, _p: &Project, _r: Self::Request) -> Result<Self::Plan, OpError> {
        Ok(EmptyPlan {})
    }
    fn diff(&self, _p: &Project, _pl: &Self::Plan) -> Result<Diff, OpError> {
        Ok(Diff { changes: vec![] })
    }
    fn validate(&self, _p: &Project, _pl: &Self::Plan) -> Vec<Finding> {
        Vec::new()
    }
    fn apply(&self, _tx: &mut Transaction, _pl: Self::Plan) -> Result<Self::Output, OpError> {
        Ok(EmptyOut {})
    }
}

fn test_registry() -> Registry {
    let mut r = Registry::new();
    r.register::<NoteOp>();
    r.register::<NetOp>();
    r.register::<DelOp>();
    r
}

fn open_engine(root: &std::path::Path) -> Engine {
    Engine::open(root, test_registry()).expect("engine opens")
}

fn note_req(text: &str) -> PlanRequest {
    PlanRequest {
        op_id: "test.put_note".into(),
        op_version: 1,
        input: json!({ "text": text }),
        actor: "cli_local".into(),
    }
}

fn apply_note(engine: &mut Engine, text: &str) -> AuditEntry {
    let req = note_req(text);
    let plan = engine.materialize(&req).expect("materialize");
    let preview = engine.preview(&plan).expect("preview");
    assert!(!preview.blocking);
    engine.commit(&req, plan).expect("commit")
}

#[test]
fn commit_advances_revision_and_writes_a_chained_audit_entry() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());

    let entry = apply_note(&mut engine, "hello");
    assert_eq!(entry.audit_id, "aud_00001");
    assert_eq!(entry.prev_hash, audit::GENESIS_PREV_HASH);
    assert_eq!(entry.project_revision, "rev_00001");
    assert_eq!(entry.base_project_revision, "rev_00000");
    assert_eq!(entry.op_id, "test.put_note");
    assert_eq!(entry.op_version, 1);
    assert_eq!(entry.approval, "allow");
    assert!(entry.input_hash.starts_with("sha256:"));
    assert_eq!(
        entry.post_project_hash,
        engine.project().manifest.project_hash
    );
    assert_eq!(
        engine.project().manifest.audit_head.as_ref().unwrap().id,
        "aud_00001"
    );
    assert_eq!(
        engine.project().manifest.audit_head.as_ref().unwrap().hash,
        audit::entry_hash(&entry)
    );
    assert!(tmp.path().join("entities/note/ent_00001.json").exists());
    assert_eq!(engine.project().manifest.stable_id_counter, 1);

    // The on-disk line is the entry's canonical line.
    let lines = audit::read_lines(tmp.path()).unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], audit::canonical_line(&entry));
}

#[test]
fn stale_plan_is_refused_on_revision_and_on_hash_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());

    let req = note_req("a");
    let plan = engine.materialize(&req).unwrap();
    apply_note(&mut engine, "b");

    // The plan's base revision is now behind → StalePlan.
    match engine.commit(&req, plan.clone()) {
        Err(EngineError::StalePlan { hint, .. }) => {
            assert_eq!(hint, "re-run systole plan against the current revision")
        }
        other => panic!("expected StalePlan, got {other:?}"),
    }

    // A forged base hash at the right revision is the same refusal.
    let mut engine = open_engine(tmp.path());
    let plan2 = engine.materialize(&req).unwrap();
    let mut forged = plan2.clone();
    forged.base_project_hash = "sha256:deadbeef".into();
    match engine.commit(&req, forged) {
        Err(EngineError::StalePlan { .. }) => {}
        other => panic!("expected StalePlan on hash mismatch, got {other:?}"),
    }
    // Nothing was written by either refusal.
    assert_eq!(audit::read_lines(tmp.path()).unwrap().len(), 1);
}

#[test]
fn blocking_findings_refuse_the_commit_and_write_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());

    let req = note_req("");
    let plan = engine.materialize(&req).unwrap();
    match engine.commit(&req, plan) {
        Err(EngineError::Blocked(findings)) => {
            assert!(findings.iter().any(|f| f.code == "test.note.empty"))
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
    assert!(audit::read_lines(tmp.path()).unwrap().is_empty());
    assert!(!tmp.path().join("entities/note").exists());
    assert_eq!(engine.project().manifest.project_revision, "rev_00000");
}

#[test]
fn engine_refuses_denied_and_prompt_capabilities() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let engine = open_engine(tmp.path());

    let denied = PlanRequest {
        op_id: "test.net".into(),
        op_version: 1,
        input: json!({}),
        actor: "cli_local".into(),
    };
    match engine.materialize(&denied) {
        Err(EngineError::CapabilityDenied { capability, .. }) => {
            assert_eq!(capability, "network.call")
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }

    let prompt = PlanRequest {
        op_id: "test.del".into(),
        op_version: 1,
        input: json!({}),
        actor: "cli_local".into(),
    };
    match engine.materialize(&prompt) {
        Err(EngineError::ApprovalRequired { capability, .. }) => {
            assert_eq!(capability, "destructive.delete")
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }
}

#[test]
fn crash_after_marker_before_any_rename_rolls_back_under_doctor() {
    let tmp = tempfile::tempdir().unwrap();
    let project = Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let engine = open_engine(tmp.path());
    let req = note_req("hello");
    let plan = engine.materialize(&req).unwrap();
    let mut tx = Transaction::new(engine.project());
    let output = engine.registry().apply(&mut tx, plan.clone()).unwrap();
    drop(engine);

    // Simulated crash: the pending marker exists but no temp was ever written.
    let prepared = two_phase::plan_commit(
        tmp.path(),
        &project,
        tx.staged(),
        tx.staged(),
        tx.stable_id_counter(),
        two_phase::CommitMeta {
            actor: "cli_local".into(),
            op_id: plan.op_id.clone(),
            op_version: plan.op_version,
            input: req.input.clone(),
            plan_id: Some(plan.plan_id.clone()),
            capability: "project.write".into(),
            approval: "allow".into(),
            rollback_of: None,
            output,
        },
    )
    .unwrap();
    let mut marker = prepared.marker.clone();
    two_phase::write_marker(tmp.path(), &mut marker, "prepared").unwrap();

    let report = doctor::run(tmp.path(), false, &[]).expect("doctor resolves");
    assert!(matches!(
        report.recovered,
        Some(doctor::Recovery::RolledBack { .. })
    ));
    assert!(!tmp.path().join("entities/note").exists());
    assert!(audit::read_lines(tmp.path()).unwrap().is_empty());
    assert_eq!(
        std::fs::read_dir(tmp.path().join("audit/pending"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".json"))
            .count(),
        0,
        "marker removed"
    );
    Project::load(tmp.path()).expect("pre-state still verifies");
}

#[test]
fn crash_after_all_renames_before_append_completes_under_doctor() {
    let tmp = tempfile::tempdir().unwrap();
    let project = Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let engine = open_engine(tmp.path());
    let req = note_req("hello");
    let plan = engine.materialize(&req).unwrap();
    let mut tx = Transaction::new(engine.project());
    let output = engine.registry().apply(&mut tx, plan.clone()).unwrap();
    drop(engine);

    // Simulated crash: marker + temps written, phase renaming, all renames
    // applied — the append never ran.
    let prepared = two_phase::plan_commit(
        tmp.path(),
        &project,
        tx.staged(),
        tx.staged(),
        tx.stable_id_counter(),
        two_phase::CommitMeta {
            actor: "cli_local".into(),
            op_id: plan.op_id.clone(),
            op_version: plan.op_version,
            input: req.input.clone(),
            plan_id: Some(plan.plan_id.clone()),
            capability: "project.write".into(),
            approval: "allow".into(),
            rollback_of: None,
            output,
        },
    )
    .unwrap();
    let mut marker = prepared.marker.clone();
    two_phase::write_marker(tmp.path(), &mut marker, "prepared").unwrap();
    two_phase::write_temps(tmp.path(), &prepared).unwrap();
    two_phase::write_marker(tmp.path(), &mut marker, "renaming").unwrap();
    two_phase::apply_renames(tmp.path(), &prepared).unwrap();

    let report = doctor::run(tmp.path(), false, &[]).expect("doctor resolves");
    assert!(matches!(
        report.recovered,
        Some(doctor::Recovery::Completed { .. })
    ));
    // The entry was appended exactly once.
    let lines = audit::read_lines(tmp.path()).unwrap();
    assert_eq!(lines.len(), 1);
    // And a second doctor run is a clean no-op.
    let report2 = doctor::run(tmp.path(), false, &[]).expect("doctor is stable");
    assert!(report2.recovered.is_none());
    assert_eq!(report2.entries, 1);
    assert!(tmp.path().join("entities/note/ent_00001.json").exists());
    Project::load(tmp.path()).expect("completed state verifies");
}

#[test]
fn rollback_restores_every_touched_file_byte_for_byte() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());

    apply_note(&mut engine, "a");
    let first_bytes = std::fs::read(tmp.path().join("entities/note/ent_00001.json")).unwrap();
    let manifest_after_first = std::fs::read(tmp.path().join("project.systole.json")).unwrap();
    apply_note(&mut engine, "b");
    assert_eq!(engine.project().manifest.stable_id_counter, 2);

    // Head-only: the first entry is no longer the head.
    match engine.rollback("aud_00001") {
        Err(EngineError::NotHead { requested, head }) => {
            assert_eq!(requested, "aud_00001");
            assert_eq!(head.as_deref(), Some("aud_00002"));
        }
        other => panic!("expected NotHead, got {other:?}"),
    }

    let rb = engine.rollback("aud_00002").expect("rollback head");
    assert_eq!(rb.rollback_of.as_deref(), Some("aud_00002"));
    assert_eq!(rb.op_id, "core.rollback");
    assert_eq!(rb.project_revision, "rev_00003");

    // The created file is gone; the counter never decrements.
    assert!(!tmp.path().join("entities/note/ent_00002.json").exists());
    assert_eq!(engine.project().manifest.stable_id_counter, 2);
    // The first commit's file is byte-for-byte intact.
    assert_eq!(
        std::fs::read(tmp.path().join("entities/note/ent_00001.json")).unwrap(),
        first_bytes
    );
    // The manifest carries its own new revision (not the first commit's bytes).
    assert_ne!(
        std::fs::read(tmp.path().join("project.systole.json")).unwrap(),
        manifest_after_first
    );
    // Two entries: the original and the compensating one.
    assert_eq!(audit::read_lines(tmp.path()).unwrap().len(), 3);
    Project::load(tmp.path()).expect("post-rollback state verifies");
}

#[test]
fn same_requests_on_same_ir_give_equal_hashes_and_changes() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    Project::init(a.path(), false, &rpg_modules()).unwrap();
    Project::init(b.path(), false, &rpg_modules()).unwrap();
    let mut ea = open_engine(a.path());
    let mut eb = open_engine(b.path());

    let ea_entry = apply_note(&mut ea, "same");
    let eb_entry = apply_note(&mut eb, "same");

    assert_eq!(
        ea.project().manifest.project_hash,
        eb.project().manifest.project_hash,
        "determinism: equal post-hash (ADR-0010)"
    );
    assert_eq!(
        serde_json::to_value(&ea_entry.changes).unwrap(),
        serde_json::to_value(&eb_entry.changes).unwrap(),
        "determinism: equal changes"
    );
    assert_eq!(ea_entry.plan_id, eb_entry.plan_id);
    assert_eq!(ea_entry.transaction_id, eb_entry.transaction_id);
}

#[test]
fn doctor_on_a_clean_project_reports_ok() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());
    apply_note(&mut engine, "hello");

    let report = doctor::run(tmp.path(), false, &[]).expect("doctor runs");
    assert!(report.recovered.is_none());
    assert_eq!(report.entries, 1);
    assert!(report.absorbed.is_none());
}

#[test]
fn absorb_records_an_external_edit_entry_and_restores_verification() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());
    apply_note(&mut engine, "hello");
    drop(engine);

    // Out-of-band edit: rewrite the note file by hand.
    std::fs::write(
        tmp.path().join("entities/note/ent_00001.json"),
        "{\"id\":\"note.ent_00001\",\"stable_id\":\"ent_00001\",\"kind\":\"note\",\"tags\":[],\"intent\":\"\",\"constraints\":[],\"owner_module\":\"test\",\"text\":\"edited\"}\n",
    )
    .unwrap();
    match Project::load(tmp.path()) {
        Err(ProjectError::Integrity(_)) => {}
        other => panic!("load must refuse the hand edit, got {other:?}"),
    }

    // Without absorb, doctor refuses with the integrity error.
    assert!(doctor::run(tmp.path(), false, &[]).is_err());

    let report = doctor::run(tmp.path(), true, &[]).expect("absorb runs");
    assert!(report.absorbed.is_some());
    let lines = audit::read_lines(tmp.path()).unwrap();
    assert_eq!(lines.len(), 2);
    let entry: AuditEntry = serde_json::from_slice(&lines[1]).unwrap();
    assert_eq!(entry.op_id, "core.external_edit");
    assert_eq!(entry.project_revision, "rev_00002");
    Project::load(tmp.path()).expect("absorbed state verifies");
}

#[test]
fn commit_refuses_a_plan_whose_request_does_not_match() {
    let tmp = tempfile::tempdir().unwrap();
    Project::init(tmp.path(), false, &rpg_modules()).unwrap();
    let mut engine = open_engine(tmp.path());

    let req = note_req("hello");
    let plan = engine.materialize(&req).unwrap();

    // A different input produces a different plan_id → the envelope disagrees.
    let wrong_req = note_req("different");
    match engine.commit(&wrong_req, plan) {
        Err(EngineError::InvalidRequest(_)) => {}
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
    assert!(audit::read_lines(tmp.path()).unwrap().is_empty());
}
