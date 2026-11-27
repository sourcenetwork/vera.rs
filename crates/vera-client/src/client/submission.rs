//! Sign-and-submit helpers and receipt polling.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes};
use vera_domain::NativeTx;

use super::VeraClient;
use crate::{bls_signer::BlsSigner, error::ClientError, types::TransactionReceipt};

const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Native requests reach other validators by gossip, so the helpers poll for two minutes.
const RECEIPT_POLL_ATTEMPTS: u32 = 400;

impl VeraClient {
    /// Sign at the signer's current sequence and submit.
    ///
    /// The sequence advances only once the node returns the request's own
    /// identifier, so a rejected or unsent request leaves it reusable.
    ///
    /// A reply lost after the request was sent returns
    /// [`ClientError::SubmissionUnknown`] with the request's identifier and
    /// sequence, and also leaves the sequence unchanged. Settle it with
    /// [`Self::confirm_submission`]. Dropping this future while the request is
    /// in flight leaves the same state without the error.
    pub(crate) async fn submit_native(
        &self,
        signer: &BlsSigner,
        target: Address,
        calldata: Bytes,
    ) -> Result<B256, ClientError> {
        let _in_order = signer.submission().await;
        let sequence = signer.nonce();
        let wire = signer.sign_native_tx_with_sequence(target, calldata, sequence)?;
        let expected = NativeTx::decode_wire(&wire)
            .map_err(|e| ClientError::Signing(e.to_string()))?
            .tx_id()
            .0;
        match self.send_native_tx(&wire).await {
            Ok(returned) if returned == expected => {}
            Ok(_) => {
                return Err(ClientError::InvalidResponse(
                    "native submission identifier mismatch",
                ));
            }
            Err(error) if reply_lost(&error) => {
                return Err(ClientError::SubmissionUnknown {
                    tx_hash: expected,
                    sequence,
                    source: Box::new(error),
                });
            }
            Err(error) => return Err(error),
        }
        signer.admitted(sequence);
        Ok(expected)
    }

    /// Settle a submission that failed with [`ClientError::SubmissionUnknown`].
    ///
    /// Polls for the receipt of `tx_hash` as [`Self::wait_for_receipt`] does. A
    /// receipt, successful or not, shows the node consumed `sequence`, so the
    /// signer moves past it and never back. Without a receipt the sequence
    /// stays where it was: the request is either still pending or was never
    /// admitted. Repeating the original call then signs the same bytes under
    /// the same identifier, so it cannot take effect twice: a node that
    /// already admitted the request rejects the repeat. Signing different
    /// content at this sequence is likewise rejected once the first request
    /// was admitted, and supersedes it only if it never was.
    pub async fn confirm_submission(
        &self,
        signer: &BlsSigner,
        tx_hash: B256,
        sequence: u64,
        interval: Duration,
        max_attempts: u32,
    ) -> Result<TransactionReceipt, ClientError> {
        let receipt = self
            .wait_for_receipt(tx_hash, interval, max_attempts)
            .await?;
        signer.admitted(sequence);
        Ok(receipt)
    }

    /// Sign and submit a native BLS transaction, then poll for the receipt.
    pub(crate) async fn send_native_precompile_tx(
        &self,
        signer: &BlsSigner,
        target: Address,
        calldata: Bytes,
    ) -> Result<TransactionReceipt, ClientError> {
        let tx_hash = self.submit_native(signer, target, calldata).await?;
        self.executed(tx_hash).await
    }

    pub(super) async fn executed(&self, tx_hash: B256) -> Result<TransactionReceipt, ClientError> {
        let receipt = self
            .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
            .await?;
        if !receipt.success {
            let refusal = receipt.refusal.clone().ok_or(ClientError::InvalidResponse(
                "failed receipt names no refusal",
            ))?;
            return Err(ClientError::Refused {
                refusal,
                receipt: Some(Box::new(receipt)),
            });
        }
        Ok(receipt)
    }

    /// Poll for a transaction receipt until it appears or attempts are exhausted.
    ///
    /// Throttled polls are retried. Connection failures, timeouts and HTTP 5xx
    /// replies are retried until `interval * max_attempts` has elapsed. Every
    /// failure names the transaction, which may still execute.
    ///
    /// A node that pruned the receipt answers as it does for a request it
    /// never saw, so this polls until its attempts run out;
    /// [`Self::wait_for_receipt_after`] stops instead.
    pub async fn wait_for_receipt(
        &self,
        tx_hash: B256,
        interval: Duration,
        max_attempts: u32,
    ) -> Result<TransactionReceipt, ClientError> {
        self.poll_receipt(tx_hash, None, interval, max_attempts)
            .await
    }

    /// Poll as [`Self::wait_for_receipt`] does for a request that was not
    /// finalized at or below revision `after`, such as [`Self::block_number`]
    /// read before it was submitted.
    ///
    /// Polling ends with [`ClientError::ReceiptPruned`] as soon as the node
    /// holds no receipt and has pruned a revision above `after`.
    pub async fn wait_for_receipt_after(
        &self,
        tx_hash: B256,
        after: u64,
        interval: Duration,
        max_attempts: u32,
    ) -> Result<TransactionReceipt, ClientError> {
        self.poll_receipt(tx_hash, Some(after), interval, max_attempts)
            .await
    }

    async fn poll_receipt(
        &self,
        tx_hash: B256,
        after: Option<u64>,
        interval: Duration,
        max_attempts: u32,
    ) -> Result<TransactionReceipt, ClientError> {
        let started = tokio::time::Instant::now();
        let outage_budget = interval.saturating_mul(max_attempts);
        for _ in 0..max_attempts {
            let polled = match after {
                Some(after) => self.get_transaction_receipt_after(tx_hash, after).await,
                None => self.get_transaction_receipt(tx_hash).await,
            };
            match polled {
                Ok(Some(receipt)) => return Ok(receipt),
                Ok(None) => {}
                Err(error) if error.is_throttled() => {}
                Err(error) if is_outage(&error) && started.elapsed() < outage_budget => {}
                Err(ClientError::HistoryPruned { floor, .. }) => {
                    return Err(ClientError::ReceiptPruned { tx_hash, floor });
                }
                Err(error) => {
                    return Err(ClientError::ReceiptUnavailable {
                        tx_hash,
                        source: Box::new(error),
                    });
                }
            }
            tokio::time::sleep(interval).await;
        }
        Err(ClientError::ReceiptTimeout {
            tx_hash,
            attempts: max_attempts,
        })
    }
}

/// Whether a failed send may have reached the node: the connection was made
/// and no reply came back from it.
fn reply_lost(error: &ClientError) -> bool {
    matches!(error, ClientError::Transport(error)
        if !error.is_connect() && !error.is_builder()
            && error.status().is_none_or(|status| status.is_server_error()))
}

fn is_outage(error: &ClientError) -> bool {
    matches!(error, ClientError::Transport(error) if error.status().is_none_or(|status| status.is_server_error()))
}
