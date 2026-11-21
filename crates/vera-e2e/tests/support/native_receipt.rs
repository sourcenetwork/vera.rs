use alloy_primitives::B256;
use vera_client::{TransactionReceipt, VeraClient};
use vera_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};

/// Poll `vera_getTransactionReceipt` until the submission's receipt appears.
///
/// Request failures are retried within the polling budget, so a node that is
/// briefly unavailable does not fail the wait.
pub(super) async fn wait(client: &VeraClient, submission: B256) -> TransactionReceipt {
    let mut last_error = None;
    for _ in 0..RECEIPT_POLL_ATTEMPTS {
        match client.get_transaction_receipt(submission).await {
            Ok(Some(receipt)) => return receipt,
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
    }
    panic!("no receipt for {submission}; last error: {last_error:?}")
}
