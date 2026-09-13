//! `systole project doctor [--absorb]` — resolve interrupted commits, verify
//! the chain and the load-time hash, optionally absorb a hand edit.

use std::path::Path;

use super::{module_validators, print_findings, report_project_error};
use systole_core::doctor::{self, DoctorError, Recovery};

pub fn run(root: &Path, absorb: bool, json: bool) -> i32 {
    match doctor::run(root, absorb, &module_validators()) {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": !report.blocking,
                        "project_root": root.display().to_string(),
                        "entries": report.entries,
                        "recovered": report.recovered.as_ref().map(|r| match r {
                            Recovery::Completed { transaction_id } => serde_json::json!({
                                "completed": transaction_id }),
                            Recovery::RolledBack { transaction_id } => serde_json::json!({
                                "rolled_back": transaction_id }),
                        }),
                        "absorbed": report.absorbed,
                        "findings": report.findings,
                        "blocking": report.blocking,
                    })
                );
            } else {
                let line = match (&report.recovered, &report.absorbed) {
                    (Some(Recovery::Completed { transaction_id }), _) => format!(
                        "doctor ok: completed pending transaction {transaction_id}, \
                         {} entries, chain verified",
                        report.entries
                    ),
                    (Some(Recovery::RolledBack { transaction_id }), _) => format!(
                        "doctor ok: rolled back pending transaction {transaction_id}, \
                         {} entries, chain verified",
                        report.entries
                    ),
                    (None, Some(audit_id)) => format!(
                        "doctor ok: absorbed external edit as {audit_id}, \
                         {} entries, chain verified",
                        report.entries
                    ),
                    (None, None) => format!(
                        "doctor ok: {} entries, chain verified, no pending transaction",
                        report.entries
                    ),
                };
                println!("{line}");
                print_findings(&report.findings);
            }
            if report.blocking {
                1
            } else {
                0
            }
        }
        Err(err) => report_doctor_error(root, &err, json),
    }
}

fn report_doctor_error(root: &Path, err: &DoctorError, json: bool) -> i32 {
    match err {
        DoctorError::Project(pe) => {
            if json {
                structured(root, "project.error", &pe.to_string(), 2)
            } else {
                report_project_error(root, pe)
            }
        }
        DoctorError::Integrity(integrity) => {
            // The w1 refusal shape: out-of-band edits are named, then the
            // recorded revision and the absorb hint.
            if json {
                structured(root, "project.integrity", &integrity.to_string(), 2)
            } else {
                report_project_error(
                    root,
                    &systole_core::ir::project::ProjectError::Integrity(integrity.clone()),
                )
            }
        }
        DoctorError::ReadOnly => {
            if json {
                structured(root, "project.read_only", "refused: SYSTOLE_READ_ONLY=1", 2)
            } else {
                eprintln!("refused: SYSTOLE_READ_ONLY=1");
                2
            }
        }
        DoctorError::Locked { pid } => {
            if json {
                structured(root, "project.locked", &format!("project is locked by pid {pid}"), 2)
            } else {
                eprintln!("project is locked by pid {pid}");
                2
            }
        }
        DoctorError::Chain(brk) => {
            if json {
                structured(root, "audit.chain_broken", &brk.to_string(), 2)
            } else {
                eprintln!("{brk}");
                2
            }
        }
        other => {
            if json {
                structured(root, "engine.io", &other.to_string(), 2)
            } else {
                eprintln!("{other}");
                2
            }
        }
    }
}

fn structured(root: &Path, code: &str, message: &str, exit: i32) -> i32 {
    println!(
        "{}",
        serde_json::json!({
            "error": { "code": code, "message": message },
            "project_root": root.display().to_string(),
        })
    );
    exit
}
