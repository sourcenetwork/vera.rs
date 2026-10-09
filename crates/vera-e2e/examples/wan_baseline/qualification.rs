use alloy_primitives::B256;
use tokio::time::timeout;
use vera_client::{AccessRequest, Actor, Object, Operation, PERMISSION_LIMITS, VeraClient};
use vera_domain::{ConsensusPublicKey, ReceiptResponse};

use super::driver::{Observation, POLL_INTERVAL, REQUEST_TIMEOUT, ReadContext};

pub(super) async fn receipt(
    client: &VeraClient,
    hash: B256,
    trusted: &ConsensusPublicKey,
) -> ReceiptResponse {
    timeout(REQUEST_TIMEOUT, async {
        loop {
            match client.read_receipt(hash, trusted).await {
                Ok(Some(response)) => {
                    assert!(
                        response
                            .receipts
                            .iter()
                            .find(|receipt| receipt.tx_hash == hash)
                            .unwrap()
                            .success()
                    );
                    return response;
                }
                Ok(None) => {}
                Err(error) if error.is_throttled() => {}
                Err(error) => panic!("certified receipt failed: {error}"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("certified receipt deadline")
}

pub(super) async fn verify(
    clients: &[VeraClient],
    observation: &Observation,
    reads: &ReadContext,
) -> bool {
    let Some(anchor) = observation.measured_anchor() else {
        return false;
    };
    timeout(REQUEST_TIMEOUT, async {
        for client in clients {
            let response = receipt(client, observation.request.hash, &reads.trusted).await;
            assert_eq!(response.revision.height, anchor.height);
            assert_eq!(
                response.revision.block_hash.parse::<B256>().unwrap(),
                anchor.block_hash
            );
            let request = AccessRequest {
                actor: Actor(observation.request.owner.parse().unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "file".into(),
                        id: observation.request.object_id.clone(),
                    },
                    permission: "read".into(),
                }],
            };
            let (_, allowed) = client
                .verify_current_access(
                    &reads.policy,
                    &request,
                    anchor.height,
                    &reads.trusted,
                    PERMISSION_LIMITS,
                )
                .await
                .expect("certified replica permission");
            assert_eq!(allowed, observation.request.expected_access);
        }
        true
    })
    .await
    .unwrap_or(false)
}
