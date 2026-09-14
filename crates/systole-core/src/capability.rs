//! Capabilities an operation can declare (ADR-0005). The constant lives on the
//! `Operation` trait; the engine's policy check over them is `r0.s1.w2`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Capability {
    ProjectRead,
    ProjectWrite,
    DestructiveDelete,
    FilesystemRead,
    FilesystemWrite,
    NetworkCall,
    SecretsRead,
    AssetImport,
    AssetGenerateRemote,
    RuntimeLaunch,
    BundleWrite,
}

/// The policy decision for an (actor, capability) pair (ADR-0005).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Prompt,
    Deny,
}

/// The static capability policy: a table keyed by actor (ADR-0005). Release 0
/// ships exactly one actor, `cli_local`; an unknown actor is deny-all. `Prompt`
/// is declared but unreachable — no interactive path exists in Release 0, so a
/// `Prompt` decision is rendered as a structured refusal by the caller.
pub struct Policy;

impl Policy {
    pub fn resolve(actor: &str, capability: Capability) -> Decision {
        match actor {
            "cli_local" => match capability {
                Capability::ProjectRead | Capability::ProjectWrite => Decision::Allow,
                Capability::DestructiveDelete => Decision::Prompt,
                _ => Decision::Deny,
            },
            _ => Decision::Deny,
        }
    }
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ProjectRead => "project.read",
            Capability::ProjectWrite => "project.write",
            Capability::DestructiveDelete => "destructive.delete",
            Capability::FilesystemRead => "filesystem.read",
            Capability::FilesystemWrite => "filesystem.write",
            Capability::NetworkCall => "network.call",
            Capability::SecretsRead => "secrets.read",
            Capability::AssetImport => "asset.import",
            Capability::AssetGenerateRemote => "asset.generate-remote",
            Capability::RuntimeLaunch => "runtime.launch",
            Capability::BundleWrite => "bundle.write",
        }
    }
}
