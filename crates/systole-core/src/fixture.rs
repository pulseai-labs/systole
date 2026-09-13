//! Fixture operations (spec §7): compiled in only under the `fixture-ops`
//! cargo feature so the default binary ships a clean catalog. They prove the
//! engine lifecycle end to end — `fixture.put_note` writes, `fixture.get_note`
//! reads, and `fixture.forbidden` exists to prove the deny path.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::capability::Capability;
use crate::finding::{Finding, Location, Severity};
use crate::ids::IdKind;
use crate::ir::project::Project;
use crate::ir::RelPath;
use crate::op::{
    Diff, FileChange, Mutability, Operation, OperationDescription, OpError, ReadOperation,
    Stability,
};
use crate::tx::Transaction;

fn note_path(stable_id: &str) -> RelPath {
    RelPath::new(format!("entities/note/{stable_id}.json"))
}

fn note_value(stable_id: &str, text: &str) -> serde_json::Value {
    json!({
        "id": format!("note.{stable_id}"),
        "stable_id": stable_id,
        "kind": "note",
        "tags": [],
        "intent": "",
        "constraints": [],
        "owner_module": "fixture",
        "text": text,
    })
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PutNoteRequest {
    /// The note body.
    pub text: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PutNotePlan {
    pub text: String,
}

#[derive(Serialize, JsonSchema)]
pub struct PutNoteOutput {
    pub stable_id: String,
}

/// `fixture.put_note` v1 — write, `project.write`.
#[derive(Default)]
pub struct PutNote;

impl Operation for PutNote {
    type Request = PutNoteRequest;
    type Plan = PutNotePlan;
    type Output = PutNoteOutput;

    const ID: &'static str = "fixture.put_note";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectWrite;
    const STABILITY: Stability = Stability::Internal;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "write a note entity (test fixture)".into(),
            input_schema: schemars::schema_for!(PutNoteRequest),
            example: json!({ "text": "hello" }),
            avoid_when: vec!["anywhere but tests — this is a fixture".into()],
        }
    }

    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }

    fn materialize(&self, _project: &Project, req: Self::Request) -> Result<Self::Plan, OpError> {
        Ok(PutNotePlan { text: req.text })
    }

    fn diff(&self, project: &Project, plan: &Self::Plan) -> Result<Diff, OpError> {
        let n = project.manifest.stable_id_counter + 1;
        let stable_id = format!("ent_{n:05}");
        let path = note_path(&stable_id);
        Ok(Diff {
            changes: vec![FileChange {
                path: path.clone(),
                before: project.files.get(&path).cloned(),
                after: Some(note_value(&stable_id, &plan.text)),
            }],
        })
    }

    fn validate(&self, _project: &Project, plan: &Self::Plan) -> Vec<Finding> {
        if plan.text.is_empty() {
            return vec![Finding {
                finding_id: "fixture.note.empty".into(),
                code: "fixture.note.empty".into(),
                severity: Severity::Error,
                location: Location {
                    stable_id: None,
                    path: None,
                },
                evidence: json!({ "reason": "text is empty" }),
                suggested_fixes: vec![],
                blocking: true,
            }];
        }
        Vec::new()
    }

    fn apply(&self, tx: &mut Transaction, plan: Self::Plan) -> Result<Self::Output, OpError> {
        let stable_id = tx.alloc_id(IdKind::Ent).to_string();
        tx.write(note_path(&stable_id), note_value(&stable_id, &plan.text));
        Ok(PutNoteOutput { stable_id })
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ForbiddenRequest {}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ForbiddenPlan {}

#[derive(Serialize, JsonSchema)]
pub struct ForbiddenOutput {}

/// `fixture.forbidden` v1 — write, `network.call`: never materializes under
/// the `cli_local` policy; exists to prove the deny path.
#[derive(Default)]
pub struct Forbidden;

impl Operation for Forbidden {
    type Request = ForbiddenRequest;
    type Plan = ForbiddenPlan;
    type Output = ForbiddenOutput;

    const ID: &'static str = "fixture.forbidden";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::NetworkCall;
    const STABILITY: Stability = Stability::Internal;
    const MUTABILITY: Mutability = Mutability::Write;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "denied-capability probe (test fixture)".into(),
            input_schema: schemars::schema_for!(ForbiddenRequest),
            example: json!({}),
            avoid_when: vec!["always — its capability is denied to every actor".into()],
        }
    }

    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }

    fn materialize(&self, _project: &Project, _req: Self::Request) -> Result<Self::Plan, OpError> {
        Ok(ForbiddenPlan {})
    }

    fn diff(&self, _project: &Project, _plan: &Self::Plan) -> Result<Diff, OpError> {
        Ok(Diff { changes: vec![] })
    }

    fn validate(&self, _project: &Project, _plan: &Self::Plan) -> Vec<Finding> {
        Vec::new()
    }

    fn apply(&self, _tx: &mut Transaction, _plan: Self::Plan) -> Result<Self::Output, OpError> {
        Ok(ForbiddenOutput {})
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GetNoteRequest {
    /// The note's stable id, e.g. `ent_00001`.
    pub stable_id: String,
}

#[derive(Serialize, JsonSchema)]
pub struct GetNoteOutput(pub serde_json::Value);

/// `fixture.get_note` v1 — read, `project.read`.
#[derive(Default)]
pub struct GetNote;

impl ReadOperation for GetNote {
    type Request = GetNoteRequest;
    type Output = GetNoteOutput;

    const ID: &'static str = "fixture.get_note";
    const VERSION: u32 = 1;
    const CAPABILITY: Capability = Capability::ProjectRead;

    fn describe() -> OperationDescription {
        OperationDescription {
            id: Self::ID.into(),
            version: Self::VERSION,
            summary: "read a note entity (test fixture)".into(),
            input_schema: schemars::schema_for!(GetNoteRequest),
            example: json!({ "stable_id": "ent_00001" }),
            avoid_when: vec!["anywhere but tests — this is a fixture".into()],
        }
    }

    fn validate_request(&self, _req: &Self::Request) -> Result<(), OpError> {
        Ok(())
    }

    fn query(&self, project: &Project, req: Self::Request) -> Result<Self::Output, OpError> {
        project
            .files
            .get(&note_path(&req.stable_id))
            .cloned()
            .map(GetNoteOutput)
            .ok_or_else(|| {
                OpError::InvalidRequest(format!("no note {}", req.stable_id))
            })
    }
}
