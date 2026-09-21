//! Signed, hierarchical TOML pipeline configuration.
//!
//! Defines the shared schema for OSS/self-hosted Maskura processing chains and
//! the private dashboard's portable export: named scopes carrying dedicated,
//! ordered read and write chains, Ed25519-signed over a canonical CBOR body.

pub mod direction;
pub mod error;
pub mod plugin_ref;
pub mod schema;
pub mod signing;

pub use direction::Direction;
pub use error::ConfigError;
pub use plugin_ref::PluginRef;
pub use schema::{
    DirectionPipeline, PipelineFile, SCHEMA_VERSION, ScopeOverride, StepDef, WorkspaceScope,
};
pub use signing::TrustRoots;
