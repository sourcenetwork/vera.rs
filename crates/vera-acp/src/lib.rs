//! Access Control Policy (ACP) types.
//!
//! Vendored from defradb.rs at 8d34d9c (trimmed to the surface vera uses:
//! the `DocumentACP` interface, policy YAML parsing, and zanzibar re-exports).
//! The upstream crate additionally carries local/persistent stores, relation
//! tuples, node ACP and the persistent zanzibar document ACP; vera implements
//! its own on-chain ACP module and QMDB-backed store.

mod dac;
pub mod error;
mod identity;
pub mod policy_yaml;

pub use dac::{DocumentACP, MaybeSendSync};
pub use error::{Error, Result};
pub use identity::Identity;
mod permission;
pub use permission::DocumentPermission;

// Re-export key zanzibar engine types from the standalone zanzibar crate
pub use ::zanzibar::{
    EvaluationStep, EvaluationTrace, MemoryZanzibarStore, PermissionCheckRequest, PermissionEngine,
    PermissionExplanation, Policy, Relation, RelationExpression, Relationship, Resource,
    StepResult, StorePolicyOptions, Subject, SubjectRestriction, ZanzibarStore,
};
