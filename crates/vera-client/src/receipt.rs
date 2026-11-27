use alloy_primitives::B256;
use vera_domain::{ConsensusPublicKey, RECEIPT_RESPONSE_BYTES, ReceiptResponse};

use crate::{ClientError, VeraClient};

impl VeraClient {
    /// Fetch and verify execution results for an exact locally computed submission ID.
    /// `None` means no evidence is available; it does not authorize sequence reuse.
    pub async fn read_receipt(
        &self,
        submission: B256,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<ReceiptResponse>, ClientError> {
        self.verified_receipt(submission, serde_json::json!([submission]), trusted)
            .await
    }

    /// Fetch and verify as [`Self::read_receipt`] does for a submission that
    /// was not finalized at or below revision `after`.
    ///
    /// `None` then means the submission is not finalized or its revision has
    /// no certificate yet. Once the node holds no record of it and has pruned
    /// a revision above `after`, the read fails with
    /// [`ClientError::HistoryPruned`].
    pub async fn read_receipt_after(
        &self,
        submission: B256,
        after: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<ReceiptResponse>, ClientError> {
        let params = serde_json::json!([submission, format!("{after:#x}")]);
        self.verified_receipt(submission, params, trusted).await
    }

    async fn verified_receipt(
        &self,
        submission: B256,
        params: serde_json::Value,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<ReceiptResponse>, ClientError> {
        let response: Option<ReceiptResponse> = self
            .rpc_call_bounded("vera_getReceiptProof", params, RECEIPT_RESPONSE_BYTES)
            .await?;
        if let Some(response) = &response {
            response.verify(submission, trusted)?;
        }
        Ok(response)
    }
}
