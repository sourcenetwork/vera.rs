use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::{ConsensusPublicKey, ExecutionReceipt, LightBlock, LightBlockError};

/// Transport budget for a finalized revision and its committed receipts.
pub const RECEIPT_RESPONSE_BYTES: usize = crate::LIGHT_BLOCK_RESPONSE_BYTES + (8 << 20);

/// Complete ordered receipt evidence for one finalized revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptResponse {
    /// Finality evidence checked against independently configured consensus trust.
    pub revision: LightBlock,
    /// Execution limit included in the receipt commitment.
    pub gas_limit: u64,
    /// Receipts in the committed execution order.
    #[serde(deserialize_with = "read_receipts")]
    pub receipts: Vec<ExecutionReceipt>,
}

fn read_receipts<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ExecutionReceipt>, D::Error> {
    struct Receipts;
    impl<'de> serde::de::Visitor<'de> for Receipts {
        type Value = Vec<ExecutionReceipt>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "at most {} receipts",
                crate::light_block::LIGHT_BLOCK_MAX_TXS
            )
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut receipts = Vec::new();
            while receipts.len() < crate::light_block::LIGHT_BLOCK_MAX_TXS {
                let Some(receipt) = seq.next_element()? else {
                    return Ok(receipts);
                };
                receipts.push(receipt);
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("too many execution receipts"));
            }
            Ok(receipts)
        }
    }
    deserializer.deserialize_seq(Receipts)
}

/// Receipt evidence failed verification.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptResponseError {
    /// Finality evidence is invalid.
    #[error(transparent)]
    Finality(#[from] LightBlockError),
    /// Receipt fields do not satisfy the committed response contract.
    #[error("invalid receipt evidence: {0}")]
    Invalid(&'static str),
}

impl ReceiptResponse {
    /// Verify finality, the complete commitment and the requested submission ID.
    /// An absent response is not proof that a submission was rejected or never accepted.
    /// A refusal's module and kind are verified; its message is the serving node's text.
    pub fn verify(
        &self,
        submission: B256,
        trusted: &ConsensusPublicKey,
    ) -> Result<&ExecutionReceipt, ReceiptResponseError> {
        let block = crate::verify_finalized_block(&self.revision, trusted)?;
        if self.receipts.len() != block.txs.len() {
            return Err(ReceiptResponseError::Invalid("receipt count"));
        }
        if self
            .receipts
            .iter()
            .any(|r| r.success() && r.refusal.is_some())
        {
            return Err(ReceiptResponseError::Invalid(
                "refusal on a successful receipt",
            ));
        }
        if block.receipt_commitment != crate::receipt_commitment(self.gas_limit, &self.receipts) {
            return Err(ReceiptResponseError::Invalid("receipt commitment"));
        }
        let mut matches = self.receipts.iter().filter(|r| r.tx_hash == submission);
        let receipt = matches.next().ok_or(ReceiptResponseError::Invalid(
            "requested submission missing",
        ))?;
        if matches.next().is_some() {
            return Err(ReceiptResponseError::Invalid("duplicate submission"));
        }
        Ok(receipt)
    }
}
