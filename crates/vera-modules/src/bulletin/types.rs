//! Bulletin domain types — namespaces, posts and collaborators.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::Timestamp;

/// A registered namespace for organizing posts.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Namespace {
    pub id: String,
    pub creator: String,
    pub owner_did: String,
    pub created_at: Timestamp,
}

/// A post within a namespace (payload + optional proof).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Post {
    pub id: String,
    pub namespace: String,
    pub creator_did: String,
    pub payload: Vec<u8>,
    pub proof: Vec<u8>,
}

/// A collaborator on a namespace.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Collaborator {
    pub did: String,
    pub namespace: String,
}
