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
