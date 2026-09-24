//! Signed, hierarchical TOML pipeline configuration.
//!
//! Defines the shared schema for OSS/self-hosted Maskura processing chains and
//! the private dashboard's portable export: named scopes carrying dedicated,
//! ordered read and write chains, Ed25519-signed over a canonical CBOR body.
//!
//! Also hosts the customer policy-approval protocol (ADR 0022): the `[policy]`
//! envelope section, activation receipts with hash-chain verification, WebAuthn
//! approval-proof verification, and the customer-pinned trust bundle /
//! checkpoint formats. These establish approval evidence and trusted-gateway
//! enforcement — not per-operation execution proofs.

pub mod canonical;
pub mod direction;
pub mod effective_state;
pub mod error;
pub mod plugin_ref;
pub mod policy;
pub mod receipt;
pub mod schema;
pub mod signing;
pub mod trust;
pub mod webauthn;

pub use direction::Direction;
pub use effective_state::{
    EffectiveState, PolicyOperation, ResolvedDestination, ResolvedLimits, ResolvedRoute,
    ResolvedStep, StorageMode,
};
pub use error::ConfigError;
pub use plugin_ref::PluginRef;
pub use policy::{FailBehavior, FilterLockEntry, PolicyLimits, PolicyRoute, PolicySection};
pub use receipt::{
    ChainReport, GENESIS_PREV, RECEIPT_SCHEMA_VERSION, ReceiptAction, ReceiptBody, ReceiptPurpose,
    ReceiptStanding, SignedReceipt, receipt_body_hash, verify_receipt, verify_receipt_chain,
};
pub use schema::{
    DirectionPipeline, PipelineFile, SCHEMA_VERSION, ScopeOverride, StepDef, WorkspaceScope,
};
pub use signing::{TrustRoots, parse_trust_roots};
pub use trust::{
    CHECKPOINT_SCHEMA_VERSION, Checkpoint, CredentialStatus, TRUST_BUNDLE_SCHEMA_VERSION,
    TrustBundle, TrustCredential, parse_trust_bundle_json,
};
pub use webauthn::{
    AssertionExpectation, CHALLENGE_VERSION, ChallengeContext, ChallengeKind, CoseEs256Key,
    WebAuthnProof, verify_assertion,
};
