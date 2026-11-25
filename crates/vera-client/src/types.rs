//! Client-side response types for JSON-RPC deserialization.

use alloy_primitives::{Address, B256, Bytes};
use serde::{Deserialize, Serialize};

/// Execution result of a native request, returned by `vera_getTransactionReceipt`.
///
/// Execution data only: it carries no finality evidence.
/// [`VeraClient::read_receipt`](crate::VeraClient::read_receipt) verifies a
/// receipt against a trusted consensus key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    /// Request identifier.
    pub transaction_hash: B256,
    /// Index of the request in its block.
    #[serde(with = "hex_u64")]
    pub transaction_index: u64,
    /// Block hash.
    pub block_hash: B256,
    /// Block number.
    #[serde(with = "hex_u64")]
    pub block_number: u64,
    /// Module address the request called.
    pub target: Address,
    /// DID of the BLS signer.
    pub signer_did: String,
    /// The signer's sequence.
    #[serde(with = "hex_u64")]
    pub nonce: u64,
    /// Gas used by this request.
    #[serde(with = "hex_u64")]
    pub gas_used: u64,
    /// Gas used in the block up to and including this request.
    #[serde(with = "hex_u64")]
    pub cumulative_gas_used: u64,
    /// Whether the module call ran to completion.
    pub success: bool,
    /// Events the call emitted.
    pub logs: Vec<Log>,
    /// Why a module refused the request; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<vera_domain::Refusal>,
}

/// Event log of a receipt.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    /// Emitting module address.
    pub address: Address,
    /// Indexed log topics.
    pub topics: Vec<B256>,
    /// Non-indexed log data.
    pub data: Bytes,
    /// Block number containing this log.
    #[serde(with = "hex_u64")]
    pub block_number: u64,
    /// Request identifier.
    pub transaction_hash: B256,
    /// Index of the request in its block.
    #[serde(with = "hex_u64")]
    pub transaction_index: u64,
    /// Block hash.
    pub block_hash: B256,
    /// Log index in block.
    #[serde(with = "hex_u64")]
    pub log_index: u64,
}

/// Node status returned by `vera_nodeStatus`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// Chain ID.
    pub chain_id: u64,
    /// This node's validator index in its startup configuration.
    pub validator_index: u32,
    /// Startup validator count, not the active epoch membership.
    #[serde(default)]
    pub validator_count: u32,
    /// Seconds since node started.
    pub uptime_secs: u64,
    /// Entered consensus view, or null when live consensus telemetry is unavailable.
    pub current_view: Option<u64>,
    /// Latest published finalized execution height, including restored durable history.
    pub finalized_height: Option<u64>,
    /// Newest revision in the execution index that serves receipt, revision and
    /// proof reads, or null on a node without an index.
    pub head_height: Option<u64>,
    /// Epoch of `finalized_height`; reported together with its view.
    pub finalized_epoch: Option<u64>,
    /// View of `finalized_height`, not the live consensus view.
    pub finalized_view: Option<u64>,
    /// Finalized callbacks processed in this run; this is not a height.
    pub finalized_count: u64,
    /// Number of blocks proposed by this node in this run.
    pub proposed_count: u64,
    /// Number of nullified rounds, or null when unobserved.
    pub nullified_count: Option<u64>,
    /// Authenticated connected peer count, or null when unobserved.
    pub peer_count: Option<u64>,
    /// Leadership in the entered consensus view, or null when unobserved.
    pub is_leader: Option<bool>,
    /// Whether this node is backfilling historical blocks.
    #[serde(default)]
    pub backfilling: bool,
    /// Revision recovered through snapshot transfer, or its persisted startup floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_revision: Option<u64>,
}

/// Serde helper for hex-encoded u64 fields in RPC responses.
mod hex_u64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:#x}"))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_default() {
        let receipt = TransactionReceipt::default();
        assert_eq!(receipt.transaction_hash, B256::ZERO);
        assert!(receipt.logs.is_empty());
        assert!(!receipt.success);
    }

    #[test]
    fn log_default() {
        let log = Log::default();
        assert_eq!(log.address, Address::ZERO);
        assert!(log.topics.is_empty());
    }

    #[test]
    fn node_status_default() {
        let status = NodeStatus::default();
        assert_eq!(status.chain_id, 0);
        assert!(status.is_leader.is_none());
        assert!(!status.backfilling);
        assert_eq!(status.validator_count, 0);
    }

    #[test]
    fn node_status_serde_roundtrip() {
        let status = NodeStatus {
            chain_id: 1337,
            validator_index: 2,
            validator_count: 4,
            uptime_secs: 3600,
            current_view: None,
            finalized_height: Some(500),
            head_height: Some(500),
            finalized_epoch: Some(5),
            finalized_view: Some(100),
            finalized_count: 50,
            proposed_count: 10,
            nullified_count: None,
            peer_count: None,
            is_leader: None,
            backfilling: false,
            snapshot_revision: Some(450),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: NodeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, 1337);
        assert!(parsed.is_leader.is_none());
        assert!(parsed.current_view.is_none());
        assert!(parsed.peer_count.is_none());
        assert!(parsed.nullified_count.is_none());
        assert_eq!(parsed.finalized_height, Some(500));
        assert_eq!(parsed.finalized_epoch, Some(5));
        assert_eq!(parsed.finalized_view, Some(100));
        assert_eq!(parsed.snapshot_revision, Some(450));
        assert_eq!(parsed.finalized_count, 50);
        assert_eq!(parsed.validator_count, 4);
        assert!(!parsed.backfilling);
    }

    #[test]
    fn node_status_backward_compat() {
        let json = serde_json::json!({
            "chainId": 1337,
            "validatorIndex": 2,
            "uptimeSecs": 3600,
            "currentView": 100,
            "finalizedCount": 50,
            "proposedCount": 10,
            "nullifiedCount": 5,
            "peerCount": 3,
            "isLeader": true
        });
        let parsed: NodeStatus = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.validator_count, 0);
        assert!(!parsed.backfilling);
        assert_eq!(parsed.current_view, Some(100));
        assert_eq!(parsed.is_leader, Some(true));
        assert!(parsed.finalized_height.is_none());
        assert!(parsed.finalized_epoch.is_none());
        assert!(parsed.finalized_view.is_none());
        assert!(parsed.snapshot_revision.is_none());
    }

    #[test]
    fn receipt_deserializes_the_node_encoding() {
        let json = serde_json::json!({
            "transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "transactionIndex": "0x0",
            "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000002",
            "blockNumber": "0xa",
            "target": "0x0000000000000000000000000000000000000810",
            "signerDid": "did:key:signer",
            "nonce": "0x49",
            "gasUsed": "0x5208",
            "cumulativeGasUsed": "0x5209",
            "success": false,
            "logs": [],
            "refusal": {"module": "acp", "kind": "unauthorized", "message": "not the owner"}
        });
        let receipt: TransactionReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(receipt.block_number, 10);
        assert_eq!(receipt.target, crate::ACP_ADDRESS);
        assert_eq!(receipt.signer_did, "did:key:signer");
        assert_eq!(receipt.nonce, 73);
        assert_eq!(receipt.gas_used, 21000);
        assert_eq!(receipt.cumulative_gas_used, 21001);
        assert!(!receipt.success);
        assert_eq!(
            receipt.refusal.unwrap().kind,
            vera_domain::RefusalKind::Unauthorized
        );
    }
}
