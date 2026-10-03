use std::time::Duration;

use alloy_primitives::B256;
use vera_client::VeraClient;
use vera_domain::{ConsensusPublicKey, ReceiptResponse};

pub(super) async fn wait_for_proof(
    client: &VeraClient,
    submission: B256,
    trusted: &ConsensusPublicKey,
) -> ReceiptResponse {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = client
                .read_receipt(submission, trusted)
                .await
                .expect("receipt proof request must succeed")
            {
                return proof;
            }
            tokio::time::sleep(vera_e2e::RECEIPT_POLL_INTERVAL).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("receipt proof deadline for {submission}"))
}
