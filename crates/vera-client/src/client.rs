//! Core [`VeraClient`] struct with JSON-RPC transport.

use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::{Address, B256, FixedBytes};
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::error::ClientError;
use crate::revision_cache::{DEFAULT_VERIFIED_REVISIONS, RevisionCache};
use crate::types::{NodeStatus, TransactionReceipt};

mod admission;
mod envelope;
mod simulation;
mod submission;

/// ACP module address (`0x0810`).
pub const ACP_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x10);

/// Bulletin module address (`0x0811`).
pub const BULLETIN_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x11);

/// Vera module address (`0x0812`).
pub const VERA_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x12);

/// ValidatorRegistry module address (`0x0813`).
pub const VALIDATOR_REGISTRY_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x13);

/// Anchor module address (`0x0814`).
pub const ANCHOR_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x14);

const fn address_from_last_two_bytes(hi: u8, lo: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = hi;
    bytes[19] = lo;
    Address::new(bytes)
}

/// Client for interacting with a vera node via JSON-RPC.
///
/// Provides the node's `vera_*` methods, verified readers, native
/// submission helpers and unauthenticated typed queries for each module.
#[derive(Debug)]
pub struct VeraClient {
    rpc_url: String,
    http: reqwest::Client,
    id: AtomicU64,
    requests: tokio::sync::Semaphore,
    request_queue: Option<admission::RequestQueue>,
    revisions: RevisionCache,
}

impl VeraClient {
    /// Create a new client targeting the given JSON-RPC endpoint.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            http: reqwest::Client::new(),
            id: AtomicU64::new(1),
            requests: tokio::sync::Semaphore::new(64),
            request_queue: None,
            revisions: RevisionCache::new(DEFAULT_VERIFIED_REVISIONS),
        }
    }

    /// Bound the verified revisions this client remembers (default:
    /// [`DEFAULT_VERIFIED_REVISIONS`]). A remembered revision served with the
    /// evidence it was verified with is not verified again; other evidence is
    /// verified in full, and zero verifies every response's.
    #[must_use]
    pub fn with_verified_revisions(mut self, maximum: usize) -> Self {
        self.revisions = RevisionCache::new(maximum);
        self
    }

    /// Finality checks under `trusted` that verify each revision's certificate once.
    pub(crate) const fn established<'a>(
        &'a self,
        trusted: &'a vera_domain::ConsensusPublicKey,
    ) -> crate::revision_cache::Established<'a> {
        self.revisions.under(trusted)
    }

    /// Bound concurrent HTTP calls, including response decoding (default: 64).
    /// Saturation returns `ClientCapacityExhausted` unless request waiting is enabled.
    #[must_use]
    pub fn with_max_concurrent_requests(mut self, maximum: std::num::NonZeroU32) -> Self {
        self.requests = tokio::sync::Semaphore::new(maximum.get() as usize);
        self
    }

    fn next_id(&self) -> u64 {
        self.id.fetch_add(1, Ordering::Relaxed)
    }

    // ── Low-level transport ─────────────────────────────────────────

    /// Send a JSON-RPC request and deserialize the `result` into `T`.
    ///
    /// Responses must match the request ID and protocol version, fit within the
    /// server's largest response budget, and arrive within ten seconds after
    /// admission to an HTTP request slot.
    pub async fn rpc_call_typed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ClientError> {
        self.rpc_call_bounded(
            method,
            params,
            vera_permission::PERMISSION_RESPONSE_BYTES.max(vera_domain::RECEIPT_RESPONSE_BYTES),
        )
        .await
    }

    pub(crate) async fn rpc_call_bounded<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        maximum: usize,
    ) -> Result<T, ClientError> {
        let _permit = self.request_permit().await?;
        debug!(method, "JSON-RPC request");
        let id = self.next_id();
        let mut response = self
            .http
            .post(&self.rpc_url)
            .timeout(std::time::Duration::from_secs(10))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "method": method, "params": params, "id": id,
            }))
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|size| size > maximum as u64)
        {
            return Err(ClientError::ResponseTooLarge(maximum));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > maximum - bytes.len() {
                return Err(ClientError::ResponseTooLarge(maximum));
            }
            bytes.extend_from_slice(&chunk);
        }
        envelope::decode(&bytes, id)
    }

    // ── Vera RPC wrappers ────────────────────────────────────────────

    /// Return the deployment's chain ID (`vera_nodeStatus` `chainId`).
    pub async fn chain_id(&self) -> Result<u64, ClientError> {
        Ok(self.node_status().await?.chain_id)
    }

    /// Return the newest revision in the node's execution index
    /// (`vera_nodeStatus` `headHeight`): the revision its receipt, revision
    /// and proof reads have reached.
    pub async fn block_number(&self) -> Result<u64, ClientError> {
        self.node_status()
            .await?
            .head_height
            .ok_or(ClientError::InvalidResponse(
                "node status has no execution head",
            ))
    }

    /// Fetch the execution result of a native request (`vera_getTransactionReceipt`).
    ///
    /// Returns `None` if the request has not yet been included. The receipt
    /// is execution data without finality evidence; [`Self::read_receipt`]
    /// verifies a receipt against a trusted consensus key.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceipt>, ClientError> {
        self.rpc_call_typed(
            "vera_getTransactionReceipt",
            serde_json::json!([format!("{tx_hash:?}")]),
        )
        .await
    }

    /// Submit a BLS-signed native transaction (`vera_sendNativeTx`).
    pub async fn send_native_tx(&self, raw_tx: &[u8]) -> Result<B256, ClientError> {
        let hex: String = self
            .rpc_call_typed(
                "vera_sendNativeTx",
                serde_json::json!([format!("0x{}", hex::encode(raw_tx))]),
            )
            .await?;
        parse_hex_b256(&hex)
    }

    /// Fetch the current node status (`vera_nodeStatus`).
    pub async fn node_status(&self) -> Result<NodeStatus, ClientError> {
        self.rpc_call_typed("vera_nodeStatus", serde_json::json!([]))
            .await
    }

    /// Fetch the on-chain native nonce for a BLS identity (`vera_getNativeNonce`).
    pub async fn get_native_nonce(&self, did: &str) -> Result<u64, ClientError> {
        let hex: String = self
            .rpc_call_typed("vera_getNativeNonce", serde_json::json!([did]))
            .await?;
        parse_hex_u64(&hex)
    }
}

/// Parse a hex-encoded policy ID string into a 32-byte fixed array.
///
/// Accepts optional `0x` prefix. The input must decode to exactly 32 bytes.
pub fn parse_policy_id(hex: &str) -> Result<FixedBytes<32>, ClientError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        hex::decode(hex).map_err(|e| ClientError::AbiDecode(format!("invalid policy ID: {e}")))?;
    if bytes.len() != 32 {
        return Err(ClientError::AbiDecode(format!(
            "policy ID must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(FixedBytes::from_slice(&bytes))
}

fn parse_hex_u64(hex: &str) -> Result<u64, ClientError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16)
        .map_err(|e| ClientError::AbiDecode(format!("invalid hex u64: {e}")))
}

fn parse_hex_b256(hex: &str) -> Result<B256, ClientError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        hex::decode(hex).map_err(|e| ClientError::AbiDecode(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ClientError::AbiDecode(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompile_addresses() {
        assert_eq!(
            format!("{ACP_ADDRESS:?}"),
            "0x0000000000000000000000000000000000000810"
        );
        assert_eq!(
            format!("{BULLETIN_ADDRESS:?}"),
            "0x0000000000000000000000000000000000000811"
        );
        assert_eq!(
            format!("{VERA_ADDRESS:?}"),
            "0x0000000000000000000000000000000000000812"
        );
    }

    #[test]
    fn parse_hex_u64_ok() {
        assert_eq!(parse_hex_u64("0xa").unwrap(), 10);
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u64("ff").unwrap(), 255);
    }

    #[test]
    fn parse_hex_b256_ok() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let b = parse_hex_b256(hex).unwrap();
        assert_eq!(b, B256::with_last_byte(1));
    }

    #[test]
    fn parse_hex_b256_wrong_length() {
        let err = parse_hex_b256("0xaabb").unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn client_new() {
        let client = VeraClient::new("http://localhost:8545");
        assert_eq!(client.rpc_url, "http://localhost:8545");
    }

    #[test]
    fn parse_policy_id_with_prefix() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let id = parse_policy_id(hex).unwrap();
        assert_eq!(id[31], 1);
    }

    #[test]
    fn parse_policy_id_without_prefix() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000002";
        let id = parse_policy_id(hex).unwrap();
        assert_eq!(id[31], 2);
    }

    #[test]
    fn parse_policy_id_wrong_length() {
        let err = parse_policy_id("0xaabb").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn parse_policy_id_invalid_hex() {
        let err = parse_policy_id("not-valid-hex").unwrap_err();
        assert!(err.to_string().contains("invalid policy ID"));
    }
}

#[cfg(test)]
mod permission_transport;
#[cfg(test)]
mod readiness_tests;
#[cfg(test)]
mod stub;
#[cfg(test)]
mod submission_tests;
