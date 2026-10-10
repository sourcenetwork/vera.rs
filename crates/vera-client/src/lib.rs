//! Rust client library for vera (EVM + BLS transaction paths).
//!
//! Provides [`VeraClient`] for interacting with a vera node via JSON-RPC.
//! Includes typed query methods for each precompile module (ACP, Bulletin, Vera)
//! and standard Ethereum RPC wrappers.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Operator approval types, signing and submission.
pub mod administration;
/// Certified ownership-amendment history.
pub mod amendments;
mod bearer;
mod bls_signer;
/// Certified bulletin records and bounded listings.
pub mod bulletin;
mod client;
/// Certified access decisions bound to an expected request.
pub mod decisions;
mod document_acp;
mod error;
mod native_tx;
/// Signed threshold-service node commands and certified records.
pub mod nodes;
mod permission;
/// Certified native policy discovery.
pub mod policies;
mod policy_records;
mod query;
mod readiness;
mod receipt;
mod record;
/// Certified registration commitment discovery.
pub mod registrations;
pub mod relationships;
/// Certified operator relay grants.
pub mod relays;
/// Threshold-service ring commands and certified state.
pub mod rings;
/// Encrypted documents and signing derivations.
pub mod threshold_objects;
/// Certified token lifecycle reads.
pub mod tokens;
pub use vera_domain::{ExecutionReceipt, ReceiptResponse, ReceiptResponseError};
pub use vera_permission::{
    AccessRequest, Actor, ModuleId, Object, Operation, PERMISSION_LIMITS, PermissionLimits,
    PermissionProof, PermissionRead, PermissionResponse, PolicyPrefixPageProof,
    PolicyPrefixPageResponse, PolicyPrefixProof, PolicyPrefixResponse, PrefixProof, PrefixResponse,
    RECORD_PROOF_BYTES, ReadLimits, RecordProof, RecordResponse, object_owner_prefix,
    verify_permission_proof,
};
mod signer;
mod subject;
mod tx;
mod types;
mod worker;
pub use worker::NativeWorker;

pub use bearer::{
    create_bearer_token, create_operation_token, create_relay_token, create_scoped_bearer_token,
};
pub use bls_signer::BlsSigner;
pub use client::{
    ACP_ADDRESS, BULLETIN_ADDRESS, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS, VeraClient,
    parse_policy_id,
};
pub use document_acp::VeraDocumentACP;
pub use error::ClientError;
pub use readiness::{ReadinessError, VerifiedReadiness};
pub use signer::EvmSigner;
pub use subject::RelationshipSubject;
pub use types::{Log, NativeReceipt, NodeStatus, TransactionReceipt};
pub use vera_crypto::jwt::DelegationScope;
