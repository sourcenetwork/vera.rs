//! Rust client library for vera.
//!
//! Provides [`VeraClient`] for interacting with a vera node via JSON-RPC:
//! native BLS submissions, verified readers that check evidence against a
//! trusted consensus key, and typed queries for each module (ACP, Bulletin,
//! Vera).
//!
//! The typed queries (`get_*`, `has_relationship`, `verify_access_request`
//! and the other helpers answered by `vera_call`) are UNAUTHENTICATED: the
//! node's unproven answer, with no finality certificate or state proof. They
//! must not grant access or be recorded as a decision. The `read_*` methods
//! and [`VeraClient::verify_current_access`] are the authenticated path.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Operator approval types, signing and submission.
pub mod administration;
/// Certified ownership-amendment history.
pub mod amendments;
/// Anchors in another deployment and policy snapshots verified against them.
pub mod anchoring;
mod bearer;
mod bls_signer;
/// Certified bulletin records and bounded listings.
pub mod bulletin;
mod client;
/// Certified access decisions bound to an expected request.
pub mod decisions;
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
mod revision_cache;
pub use revision_cache::DEFAULT_VERIFIED_REVISIONS;
/// Certified registration commitment discovery.
pub mod registrations;
pub mod relationships;
/// Certified operator relay grants.
pub mod relays;
/// Threshold-service ring commands and certified state.
pub mod rings;
/// Term certificates: approving and verifying a switch of the active device.
pub mod term;
/// Encrypted documents and signing derivations.
pub mod threshold_objects;
/// Certified token lifecycle reads.
pub mod tokens;
pub use vera_domain::{
    ExecutionReceipt, MAX_REFUSAL_MESSAGE_BYTES, NativeCallRequest, NativeCallSimulation,
    ReceiptResponse, ReceiptResponseError, Refusal, RefusalKind, RefusingModule, SimulatedLog,
    ViewCallResult,
};
pub use vera_permission::{
    AccessRequest, Actor, ModuleId, Object, Operation, PERMISSION_LIMITS, PermissionLimits,
    PermissionProof, PermissionRead, PermissionResponse, PolicyPrefixPageProof,
    PolicyPrefixPageResponse, PolicyPrefixProof, PolicyPrefixResponse, PrefixProof, PrefixResponse,
    RECORD_PROOF_BYTES, ReadLimits, RecordProof, RecordResponse, object_owner_prefix,
    verify_permission_proof,
};
mod policy_id;
mod policy_operation;
mod subject;
mod types;
pub use policy_id::{PolicyMarshalingType, PolicyNonce, predict_policy_id, random_policy_nonce};
pub use policy_operation::{PolicyOperation, PolicyOperationLead};
mod token_revocation;
pub use token_revocation::TokenRevocation;
mod unsigned_token;
mod worker;
pub use worker::NativeWorker;

pub use bearer::{
    create_bearer_token, create_operation_token, create_operation_token_with_lead,
    create_relay_token, create_scoped_bearer_token,
};
pub use bls_signer::BlsSigner;
pub use client::{
    ACP_ADDRESS, ANCHOR_ADDRESS, BULLETIN_ADDRESS, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS,
    VeraClient, parse_policy_id,
};
pub use error::ClientError;
/// Signing key for native service and authorization requests.
pub use k256_native::ecdsa::SigningKey as Secp256k1SigningKey;
pub use readiness::{ReadinessError, VerifiedReadiness};
pub use subject::RelationshipSubject;
pub use types::{Log, NodeStatus, TransactionReceipt};
pub use unsigned_token::UnsignedToken;
pub use vera_crypto::jwt::DelegationScope;
