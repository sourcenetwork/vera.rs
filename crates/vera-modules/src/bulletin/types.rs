//! Bulletin domain types — namespaces, posts, collaborators, and native tx operations.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use vera_identity::Did;

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

/// Native BLS transaction operations for the Bulletin module.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum BulletinOp {
    RegisterNamespace {
        namespace: String,
    },
    CreatePost {
        namespace: String,
        payload: Vec<u8>,
        proof: Vec<u8>,
        artifact: String,
    },
    AddCollaborator {
        namespace: String,
        collaborator: String,
    },
    RemoveCollaborator {
        namespace: String,
        collaborator: String,
    },
    UpdateParams {
        params: BulletinParams,
    },
}

/// Module-level parameters (governance-controlled).
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct BulletinParams {}

/// Actor identity for Bulletin operations (wraps a DID).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BulletinActor(
    #[borsh(
        serialize_with = "crate::borsh_did::serialize_did",
        deserialize_with = "crate::borsh_did::deserialize_did"
    )]
    pub Did,
);
