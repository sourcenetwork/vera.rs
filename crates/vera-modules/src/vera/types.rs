#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::Timestamp;

/// Status of a JWS token in the invalidation registry.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(use_discriminant = true)]
pub enum JWSTokenStatus {
    Unspecified = 0,
    Valid = 1,
    Invalid = 2,
}

/// A stored JWS token record tracking lifecycle and usage.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct JWSTokenRecord {
    pub token_hash: String,
    pub bearer_token: String,
    pub issuer_did: String,
    pub authorized_account: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub status: JWSTokenStatus,
    pub first_used_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub invalidated_at: Option<Timestamp>,
    pub invalidated_by: String,
}
