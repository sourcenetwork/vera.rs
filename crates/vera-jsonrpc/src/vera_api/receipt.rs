use alloy_primitives::{B256, Log};
use jsonrpsee::core::RpcResult;
use vera_domain::{ExecutionReceipt, RECEIPT_RESPONSE_BYTES, ReceiptResponse};
use vera_permission::encoded_size;

use super::{
    VeraApiImpl,
    permission::{error, request_error, retryable},
};

impl VeraApiImpl {
    pub(super) async fn receipt_proof(&self, hash: B256) -> RpcResult<Option<ReceiptResponse>> {
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("receipt index unavailable"))?;
        let Some(execution) = index.receipt_revision(&hash) else {
            return self.archived_receipt(hash).await;
        };
        let _permit = self.state.proof_permit()?;
        let started = tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
            .then(std::time::Instant::now);
        let block = &execution.block;
        let Some(revision) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.try_captured_revision(block),
        )
        .await
        .map_err(|_| retryable("receipt finality deadline exceeded"))??
        else {
            return Ok(None);
        };
        let finality_elapsed = started.map(|started| started.elapsed());
        if execution.receipts.len() != block.transaction_hashes.len()
            || execution
                .receipts
                .iter()
                .zip(&block.transaction_hashes)
                .any(|(receipt, hash)| {
                    receipt.transaction_hash != *hash
                        || receipt.block_hash != block.hash
                        || receipt.block_number != block.number
                })
        {
            return Err(error("incomplete receipt index"));
        }
        // Execution groups native submissions first while preserving order within each group.
        let receipts = execution.receipts.iter();
        let receipts = receipts
            .clone()
            .filter(|receipt| receipt.signer_did.is_some())
            .chain(receipts.filter(|receipt| receipt.signer_did.is_none()))
            .map(|r| {
                ExecutionReceipt::new(
                    r.transaction_hash,
                    r.status,
                    r.gas_used,
                    r.cumulative_gas_used,
                    r.logs
                        .iter()
                        .map(|l| Log::new_unchecked(l.address, l.topics.clone(), l.data.clone()))
                        .collect(),
                    r.contract_address,
                )
                .with_refusal(r.refusal.clone())
            })
            .collect::<Vec<_>>();
        let response = ReceiptResponse {
            revision,
            gas_limit: block.gas_limit,
            receipts,
        };
        validate_size(&response)?;
        if let Some((started, finality)) = started.zip(finality_elapsed) {
            tracing::debug!(target: "vera_diagnostics", height = block.number,
                receipts = response.receipts.len(), finality_us = finality.as_micros(),
                assembly_us = (started.elapsed() - finality).as_micros(),
                "receipt proof stages");
        }
        Ok(Some(response))
    }

    async fn archived_receipt(&self, hash: B256) -> RpcResult<Option<ReceiptResponse>> {
        let Some(lookup) = self.receipt_proof_lookup.clone() else {
            return Ok(None);
        };
        let index = self
            .index
            .clone()
            .ok_or_else(|| error("receipt index unavailable"))?;
        let permit = self.state.light_lookup_permit()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let response = lookup(hash).map_err(error)?;
            if let Some(response) = &response {
                // History commits before the live query state is published.
                if response.revision.height > index.head_block_number() {
                    return Ok(None);
                }
                validate_size(response)?;
            }
            Ok(response)
        })
        .await
        .map_err(error)?
    }
}

fn validate_size(response: &ReceiptResponse) -> RpcResult<()> {
    encoded_size(&response.receipts, 8 << 20).map_err(request_error)?;
    encoded_size(response, RECEIPT_RESPONSE_BYTES - 1024).map_err(request_error)?;
    Ok(())
}
