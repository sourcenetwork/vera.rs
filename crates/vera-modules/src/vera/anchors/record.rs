//! The latest anchor of one deployment, as stored and as proven to readers.

use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::AnchorError;

const DEPLOYMENT_NAMESPACE: &[u8] = b"vera/anchor/deployment/v1\0";
const KEY_PREFIX: &[u8] = b"anchor/v2/";
/// Longest stored anchor record, in bytes.
pub const MAX_ANCHOR_RECORD_BYTES: usize = 1024;
/// Length of the canonical encoding of a deployment's consensus key.
pub const CONSENSUS_KEY_BYTES: usize = 96;

/// The identifier of the deployment whose blocks verify against the consensus
/// key with canonical encoding `consensus_key`.
#[must_use]
pub fn deployment_id(consensus_key: &[u8]) -> B256 {
    let mut hash = Sha256::new();
    hash.update(DEPLOYMENT_NAMESPACE);
    hash.update(consensus_key);
    B256::from_slice(&hash.finalize())
}

/// Storage key of a deployment's latest anchor in the identity partition.
#[must_use]
pub fn anchor_key(deployment: &B256) -> Vec<u8> {
    [KEY_PREFIX, hex::encode(deployment).as_bytes()].concat()
}

/// The newest finalized revision of a deployment recorded in this deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRecord {
    /// [`deployment_id`] of `consensus_key`.
    pub deployment: B256,
    /// Canonical encoding of the deployment's consensus key.
    pub consensus_key: Bytes,
    /// Number of anchors this deployment has recorded, this one included.
    pub sequence: u64,
    /// Position of the anchor among every anchor the recording deployment
    /// recorded, of any deployment, in execution order; 1 for the first.
    pub order: u64,
    /// Height of the anchored revision.
    pub height: u64,
    /// Identifier of the anchored block.
    pub block_hash: B256,
    /// Term of the anchored block.
    pub term: u64,
    /// Timestamp of the anchored block.
    pub timestamp: u64,
    /// Native module state root of the anchored block.
    pub module_state_root: B256,
    /// Height of the revision of this deployment that recorded the anchor.
    pub anchored_at: u64,
}

impl AnchorRecord {
    /// Decode a stored record and check it belongs to `deployment`.
    ///
    /// The consensus key is checked by length and by its binding to
    /// `deployment`; a reader that verifies a revision against it decodes it.
    pub fn decode(deployment: &B256, bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_ANCHOR_RECORD_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        if record.deployment != *deployment
            || record.consensus_key.len() != CONSENSUS_KEY_BYTES
            || deployment_id(&record.consensus_key) != *deployment
            || record.sequence == 0
            || record.order == 0
        {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(record)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("anchor records serialize")
    }
}
