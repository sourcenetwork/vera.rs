use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Result, invalid};

/// Maximum JSON request and stored node-record size.
pub const MAX_NODE_BYTES: usize = 48 * 1024;
/// Maximum entries in each node's allowed-policy or allowed-ring list.
pub const MAX_NODE_TARGETS: usize = 256;

/// Threshold-service peer identity and controller authority.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    /// Service transport peer identifier.
    pub peer_id: String,
    /// Canonical compressed secp256k1 controller key, in lowercase hex.
    pub controller_key: String,
    /// Policies this service node permits its rings to use.
    pub allowed_policy_ids: Vec<String>,
    /// Rings this service node explicitly permits.
    pub allowed_ring_ids: Vec<String>,
}

impl NodeInfo {
    /// Validate bounded identifiers, keys and canonical set ordering.
    pub fn validate(&self) -> Result<()> {
        identifier(&self.peer_id, 256)?;
        validate_key(&self.controller_key)?;
        for entries in [&self.allowed_policy_ids, &self.allowed_ring_ids] {
            if entries.len() > MAX_NODE_TARGETS || entries.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid("node targets must be bounded, unique and sorted"));
            }
            for entry in entries {
                identifier(entry, 128)?;
            }
        }
        Ok(())
    }

    /// Whether this node permits a ring directly or through its policy.
    pub fn allows_ring(&self, policy_id: &str, ring_id: &str) -> bool {
        self.allowed_policy_ids.iter().any(|id| id == policy_id)
            || self.allowed_ring_ids.iter().any(|id| id == ring_id)
    }
}

/// Durable node identity, metadata and next expected command sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRecord {
    /// Original node signing key; controller transfers do not change this identity.
    pub node_key: String,
    /// Current service metadata and authority.
    pub info: NodeInfo,
    /// Next expected command sequence, beginning at one after registration.
    pub sequence: u64,
}

impl NodeRecord {
    /// Validate a decoded record against its requested storage identity.
    pub fn validate(&self, node_key: &str) -> Result<()> {
        validate_key(node_key)?;
        if self.node_key != node_key || self.sequence == 0 {
            return Err(invalid("node record identity or sequence"));
        }
        self.info.validate()
    }
}

/// A policy or ring that a service node permits.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NodeTarget {
    /// Permit rings using this policy.
    Policy(String),
    /// Permit this ring directly.
    Ring(String),
}

/// Registration requires the node key; later changes require its current controller.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NodeCommand {
    /// Create a previously unregistered node.
    Register(NodeInfo),
    /// Replace the service transport peer identifier.
    SetPeer(String),
    /// Transfer subsequent management authority to another key.
    TransferController(String),
    /// Add a policy or ring to the node's allowed set.
    Allow(NodeTarget),
    /// Remove a policy or ring from the node's allowed set.
    Disallow(NodeTarget),
}

/// Exact node operation covered by the controller's signature.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRequest {
    /// Trusted initial deployment state identity.
    pub deployment_root: [u8; 32],
    /// Deployment identifier.
    pub deployment_id: u64,
    /// Canonical compressed node identity key.
    pub node_key: String,
    /// Expected per-node sequence; registration uses zero.
    pub sequence: u64,
    /// Last valid execution time, in Unix seconds.
    pub expires_at: u64,
    /// Requested metadata or authority change.
    pub command: NodeCommand,
}

impl NodeRequest {
    /// Domain-separated digest of the bounded canonical Borsh request.
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let bytes = borsh::to_vec(self).map_err(invalid)?;
        if bytes.len() > MAX_NODE_BYTES {
            return Err(invalid("node request exceeds byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"vera/orbis/node/v1\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

/// Controller authorization independent of the native submission worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNodeRequest {
    /// Signed operation.
    pub request: NodeRequest,
    /// Canonical lowercase compressed signing key.
    pub signer_key: String,
    /// Compact low-S ECDSA signature in lowercase hex.
    pub signature: String,
}

pub(super) fn validate_key(key: &str) -> Result<Vec<u8>> {
    let bytes = key_shape(key)?;
    vera_crypto::secp256k1::decode_pubkey(&bytes).map_err(invalid)?;
    Ok(bytes)
}

/// The one accepted spelling of a compressed key, without the curve check
/// that registration performs.
pub(in crate::vera) fn key_shape(key: &str) -> Result<Vec<u8>> {
    if key.len() != 66 {
        return Err(invalid("node keys must contain 33 bytes"));
    }
    let bytes = hex::decode(key).map_err(invalid)?;
    if hex::encode(&bytes) != key {
        return Err(invalid("node keys must use lowercase hexadecimal"));
    }
    if !matches!(bytes[0], 0x02 | 0x03) {
        return Err(invalid("node keys must be compressed points"));
    }
    Ok(bytes)
}

pub(super) fn identifier(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid("invalid node peer or target identifier"));
    }
    Ok(())
}
