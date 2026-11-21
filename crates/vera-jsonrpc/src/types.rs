//! JSON-RPC response types of the receipt methods.

use alloy_primitives::{Address, B256, Bytes, U64};
use serde::{Deserialize, Serialize};

/// The execution result of a native request, as `vera_getTransactionReceipt` returns it.
///
/// Execution data only: `vera_getReceiptProof` returns the receipt commitment
/// with its finality evidence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionReceipt {
    /// Request identifier.
    pub transaction_hash: B256,
    /// Index of the request in its block.
    pub transaction_index: U64,
    /// Block hash.
    pub block_hash: B256,
    /// Block number.
    pub block_number: U64,
    /// Module address the request called.
    pub target: Address,
    /// DID of the BLS signer.
    pub signer_did: String,
    /// The signer's sequence.
    pub nonce: U64,
    /// Gas used by this request.
    pub gas_used: U64,
    /// Gas used in the block up to and including this request.
    pub cumulative_gas_used: U64,
    /// Whether the module call ran to completion.
    pub success: bool,
    /// Events the call emitted.
    pub logs: Vec<RpcLog>,
    /// Why a module refused the request; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<vera_domain::Refusal>,
}

/// Event log of a receipt.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcLog {
    /// Emitting module address.
    pub address: Address,
    /// Log topics.
    pub topics: Vec<B256>,
    /// Log data.
    pub data: Bytes,
    /// Block number.
    pub block_number: U64,
    /// Request identifier.
    pub transaction_hash: B256,
    /// Index of the request in its block.
    pub transaction_index: U64,
    /// Block hash.
    pub block_hash: B256,
    /// Log index in block.
    pub log_index: U64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_serializes_the_native_fields_in_camel_case() {
        let receipt = RpcTransactionReceipt {
            signer_did: "did:key:signer".into(),
            success: true,
            ..Default::default()
        };
        let json = serde_json::to_value(&receipt).unwrap();
        let mut fields: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "blockHash",
                "blockNumber",
                "cumulativeGasUsed",
                "gasUsed",
                "logs",
                "nonce",
                "signerDid",
                "success",
                "target",
                "transactionHash",
                "transactionIndex",
            ]
        );
    }
}
