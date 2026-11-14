//! Sign-and-submit helpers and receipt polling.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes};
use vera_domain::NativeTx;

use super::VeraClient;
use crate::{
    bls_signer::BlsSigner, error::ClientError, signer::EvmSigner, types::TransactionReceipt,
};

const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Native requests reach other validators by gossip, so the helpers poll for two minutes.
const RECEIPT_POLL_ATTEMPTS: u32 = 400;

impl VeraClient {
    /// Sign at the signer's current sequence and submit.
    ///
    /// The sequence advances only once the node returns the request's own
    /// identifier, so a rejected or unsent request leaves it reusable. After a
    /// transport failure admission is unknown and the sequence is also left
    /// unchanged; see [`BlsSigner::set_next_sequence`].
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
        if self.send_native_tx(&wire).await? != expected {
            return Err(ClientError::InvalidResponse(
                "native submission identifier mismatch",
            ));
        }
        signer.admitted(sequence);
        Ok(expected)
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

    /// Sign and submit a precompile transaction, then poll for the receipt.
    pub(crate) async fn send_precompile_tx(
        &self,
        signer: &EvmSigner,
        target: Address,
        calldata: Bytes,
    ) -> Result<TransactionReceipt, ClientError> {
        let nonce = self.get_nonce(signer.address()).await?;
        let raw = signer.sign_tx(target, calldata, nonce)?;
        let tx_hash = self.send_raw_transaction(&raw).await?;
        self.executed(tx_hash).await
    }

    async fn executed(&self, tx_hash: B256) -> Result<TransactionReceipt, ClientError> {
        let receipt = self
            .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
            .await?;
        if receipt.status == 0 {
            return Err(ClientError::TxReverted {
                status: 0,
                receipt: Box::new(receipt),
            });
        }
        Ok(receipt)
    }

    /// Poll for a transaction receipt until it appears or attempts are exhausted.
    ///
    /// Throttled polls are retried. Connection failures, timeouts and HTTP 5xx
    /// replies are retried until `interval * max_attempts` has elapsed. Every
    /// failure names the transaction, which may still execute.
    pub async fn wait_for_receipt(
        &self,
        tx_hash: B256,
        interval: Duration,
        max_attempts: u32,
    ) -> Result<TransactionReceipt, ClientError> {
        let started = tokio::time::Instant::now();
        let outage_budget = interval.saturating_mul(max_attempts);
        for _ in 0..max_attempts {
            match self.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => return Ok(receipt),
                Ok(None) => {}
                Err(error) if error.is_throttled() => {}
                Err(error) if is_outage(&error) && started.elapsed() < outage_budget => {}
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

fn is_outage(error: &ClientError) -> bool {
    matches!(error, ClientError::Transport(error) if error.status().is_none_or(|status| status.is_server_error()))
}
