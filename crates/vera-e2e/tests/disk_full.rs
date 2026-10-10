//! Real filesystem exhaustion on one validator; no injected persistence error.
#![cfg(target_os = "linux")]

use std::{collections::BTreeSet, fs, sync::Arc, time::Duration};

use alloy_sol_types::SolCall as _;
use vera_client::{ACP_ADDRESS, BlsSigner, ClientError, TransactionReceipt, VeraClient};
use vera_domain::{SimplexParameters, verify_light_block};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::acp::abi::IAcp;

#[path = "support/quota.rs"]
mod quota;

const POLL: Duration = Duration::from_millis(100);

fn deadline() -> Duration {
    let scale = std::env::var("VERA_E2E_DEADLINE_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    Duration::from_secs(30 * u64::from(scale))
}

async fn create_policy(client: &VeraClient, signer: &BlsSigner, name: &str) -> TransactionReceipt {
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

fn rpc_failure_kind(error: &ClientError) -> &'static str {
    match error {
        ClientError::ClientCapacityExhausted => "client-capacity",
        ClientError::ResourceBusy(_) => "server-capacity",
        ClientError::Rpc {
            code: -32603,
            message,
        } if message.starts_with("finalization certificate not found for height ") => {
            "finality-unavailable"
        }
        ClientError::Rpc { code: -32603, .. } => "rpc-internal",
        ClientError::Rpc { .. } => "rpc-rejected",
        ClientError::Transport(error) if error.is_timeout() => "transport-timeout",
        ClientError::Transport(_) => "transport",
        ClientError::Json(_) => "json",
        ClientError::MissingResult | ClientError::InvalidResponse(_) => "response",
        ClientError::ResponseTooLarge(_) => "response-limit",
        _ => "other",
    }
}

async fn assert_replicas(
    cluster: &TestCluster,
    signer: &BlsSigner,
    receipts: &[TransactionReceipt],
    replicas: usize,
    trusted: &vera_domain::ConsensusPublicKey,
    phase: &str,
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
                let light = client
                    .rpc_call_typed(
                        "vera_getLightBlock",
                        serde_json::json!([format!("0x{:x}", receipt.block_number)]),
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "recovery_rpc_failure phase={phase} kind={} replica={index}",
                            rpc_failure_kind(&error)
                        );
                    });
                verify_light_block(&light, trusted).unwrap();
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

#[tokio::test]
async fn disk_full_validator_recovers_acknowledged_operations() {
    let deployment = 9071;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let volume = Arc::new(quota::Quota::new().expect("mount private bounded tmpfs"));
    let node_volume = volume.clone();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(GenesisBuilder::devnet().simplex(SimplexParameters::default()))
        .preset(ConsensusPreset::Normal)
        .jmt_seeder(move |directory, _| {
            if directory.file_name().is_some_and(|name| name == "node3") {
                node_volume
                    .bind_node(directory)
                    .expect("isolate validator storage");
            }
        })
        .build()
        .await
        .unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    let signer = BlsSigner::random(deployment).expect("construct native signer");
    let origin = VeraClient::new(cluster.node(0).rpc_url());
    let mut receipts = vec![create_policy(&origin, &signer, "before-disk-full").await];
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted, "initial").await;

    assert!(
        volume.fill().unwrap() > 0,
        "filesystem must actually reach ENOSPC"
    );
    receipts.push(create_policy(&origin, &signer, "during-disk-full").await);
    tokio::time::timeout(deadline(), async {
        // Writes can consume existing file allocation before requiring another filesystem block.
        while cluster.node_mut(3).process.is_running() {
            assert!(
                receipts.len() < 128,
                "bounded writes must expose filesystem exhaustion"
            );
            receipts.push(
                create_policy(&origin, &signer, &format!("disk-full-{}", receipts.len())).await,
            );
        }
    })
    .await
    .expect("persistence failure must stop the affected validator");
    let log_dir = &cluster.node(3).log_dir;
    let logs = ["stdout.log", "stderr.log"]
        .into_iter()
        .map(|name| fs::read_to_string(log_dir.join(name)).unwrap())
        .collect::<String>();
    // Commonware's blob-header writes report WriteFailed without the underlying OS error.
    assert!(
        logs.contains("No space left on device")
            || logs.contains("os error 28")
            || logs.contains("unable to append to journal: Runtime(WriteFailed)"),
        "validator exit must report a storage write failure after independently confirmed ENOSPC (log_bytes={}, io_errors={}, panics={})",
        logs.len(),
        logs.matches("I/O error").count() + logs.matches("io error").count(),
        logs.matches("panicked").count()
    );
    assert_replicas(&cluster, &signer, &receipts, 3, &trusted, "survivors").await;

    volume.release_space().unwrap();
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted, "restored").await;
    cluster.kill_node(2);
    let recovered = VeraClient::new(cluster.node(3).rpc_url());
    receipts.push(create_policy(&recovered, &signer, "after-disk-full").await);
    cluster.restart_node(2).unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted, "renewed-quorum").await;
    for index in 0..4 {
        cluster.kill_node(index);
    }
    volume
        .close()
        .expect("unmount fixture volumes after reaping validators");
}

#[test]
fn recovery_rpc_failure_classes_do_not_export_remote_messages() {
    assert_eq!(
        rpc_failure_kind(&ClientError::ResourceBusy("private".into())),
        "server-capacity"
    );
    assert_eq!(
        rpc_failure_kind(&ClientError::Rpc {
            code: -32603,
            message: "finalization certificate not found for height 42".into(),
        }),
        "finality-unavailable"
    );
    assert_eq!(
        rpc_failure_kind(&ClientError::Rpc {
            code: -32603,
            message: "private storage error".into(),
        }),
        "rpc-internal"
    );
    assert_eq!(
        rpc_failure_kind(&ClientError::Rpc {
            code: -32000,
            message: "private request".into(),
        }),
        "rpc-rejected"
    );
}
