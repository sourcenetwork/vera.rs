//! Standalone Zanzibar permission engine with pluggable KV backend.
//!
//! Implements the Google Zanzibar permission model:
//! - Policy-based resource/relation definitions
//! - Userset rewrite rules (computed usersets, tuple-to-userset)
//! - Set operations (union, intersection, difference)
//! - Goal-tree search with cycle detection
//!
//! Exclusions fail with `IndeterminateExclusion` when a cycle prevents proving
//! the excluded branch false: one that leads from the excluded branch back to a
//! relation still being evaluated above it. Cycles among the relationships
//! beneath a branch resolve to their least fixed point, so they neither hide a
//! reachable grant nor make an exclusion indeterminate. Unresolved exclusions
//! never authorize access.
//!
//! Storage is pluggable via the `ZanzibarStore` trait. Consumers implement
//! the trait against their own KV store (e.g., redb, QMDB, rocksdb).

pub mod did;
pub mod engine;
pub mod error;
pub mod expression;
pub mod lookup;
pub mod store;
pub mod thread_bounds;
pub mod types;

pub use did::Did;
pub use engine::PermissionEngine;
pub use expression::RelationExpression;
pub use lookup::PolicyLookupTable;
pub use store::{MemoryZanzibarStore, ZanzibarStore};
pub use types::{
    decode_subject, encode_subject, Policy, PolicySpecification, Relation, Relationship, Resource,
    Subject, SubjectRestriction,
};
