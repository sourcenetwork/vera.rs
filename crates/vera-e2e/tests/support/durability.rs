use std::{collections::BTreeSet, time::Duration};

use alloy_sol_types::SolCall as _;
use vera_client::{ACP_ADDRESS, BlsSigner, ClientError, TransactionReceipt, VeraClient};
use vera_e2e::cluster::TestCluster;
use vera_modules::acp::abi::IAcp;

const POLL: Duration = Duration::from_millis(100);

pub(super) fn deadline() -> Duration {
    let scale = std::env::var("VERA_E2E_DEADLINE_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    Duration::from_secs(30 * u64::from(scale))
}

pub(super) async fn create_policy(
    client: &VeraClient,
    signer: &BlsSigner,
    name: &str,
) -> TransactionReceipt {
    let raw = signer
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: format!("name: {name}\nresources:\n  - name: file\n")
                    .into_bytes()
                    .into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    tokio::time::timeout(deadline(), async {
        let hash = client.send_native_tx(&raw).await.unwrap();
        let receipt = client.wait_for_receipt(hash, POLL, 600).await.unwrap();
        assert_eq!(receipt.status, 1);
        receipt
    })
    .await
    .expect("policy confirmation deadline")
}

pub(super) async fn assert_replicas(
    cluster: &TestCluster,
    signer: &BlsSigner,
    receipts: &[TransactionReceipt],
    replicas: usize,
    trusted: &vera_domain::ConsensusPublicKey,
) {
    tokio::time::timeout(deadline(), async {
        let origin = VeraClient::new(cluster.node(0).rpc_url());
        let expected: BTreeSet<_> = origin.get_policy_ids().await.unwrap().into_iter().collect();
        assert_eq!(expected.len(), signer.nonce() as usize);
        for index in 0..replicas {
            let client = VeraClient::new(cluster.node(index).rpc_url());
            for receipt in receipts {
                let actual = client
                    .wait_for_receipt(receipt.transaction_hash, POLL, 600)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(actual).unwrap(),
                    serde_json::to_value(receipt).unwrap()
                );
                // Receipt publication can precede the marshal certificate callback.
                let pending = format!(
                    "internal error: finalization certificate not found for height {} within retained proof limits",
                    receipt.block_number
                );
                let light = loop {
                    match client
                        .read_finalized_revision(receipt.block_number, trusted)
                        .await
                    {
                        Ok(light) => break light,
                        Err(ClientError::Rpc { code: -32603, message }) if message == pending => {
                            tokio::time::sleep(POLL).await;
                        }
                        Err(error) => panic!("replica {index} finality proof failed: {error}"),
                    }
                };
                assert_eq!(light.height, receipt.block_number);
                assert_eq!(
                    light.block_hash.parse::<alloy_primitives::B256>().unwrap(),
                    receipt.block_hash
                );
            }
            assert_eq!(
                client.get_native_nonce(signer.did()).await.unwrap(),
                signer.nonce()
            );
            let policies: BTreeSet<_> =
                client.get_policy_ids().await.unwrap().into_iter().collect();
            assert_eq!(
                policies, expected,
                "replica {index} lost committed policy state"
            );
        }
    })
    .await
    .expect("replica convergence deadline");
}
