//! Sustained-load driver against a deployed (remote) validator network.
//!
//! Drives the same certified-registration workflow as `operation_baseline`
//! (submit native tx, wait for the certified receipt, optionally verify
//! current permission evidence) but targets RPC endpoints of an existing
//! deployment instead of a locally managed cluster. Used for the wide-area
//! release gates: run it from one region against another region's RPC.

use std::{sync::Arc, time::Duration};

use alloy_sol_types::SolCall;
use commonware_codec::DecodeExt as _;
use futures::{StreamExt as _, stream};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};
use vera_client::{ACP_ADDRESS, BlsSigner, VeraClient};
use vera_domain::NativeTx;
use vera_modules::acp::abi::IAcp;

// The workload driver is shared with operation_baseline, which also uses the
// update-workflow and recovery helpers this gate does not drive.
#[path = "operation_baseline/driver.rs"]
#[allow(dead_code)]
mod driver;
#[path = "wan_baseline/qualification.rs"]
mod qualification;
#[path = "operation_baseline/replica_barrier.rs"]
#[allow(dead_code)]
mod replica_barrier;

const DEFAULT_CHAIN_ID: u64 = 9001;

#[tokio::main]
async fn main() {
    run(std::env::args().skip(1).collect()).await;
}

async fn run(args: Vec<String>) {
    assert!(
        args.len() >= 2 && args.len() <= 8,
        "usage: wan_baseline <rpc url> <genesis.json | trusted group key hex> [count] [arrivals/sec] [max outstanding] [permission reads 0/1] [chain id] [extra rpc urls comma-separated]"
    );
    let parse = |index: usize, default: usize| {
        args.get(index).map_or(default, |value| {
            value.parse::<usize>().expect("positive integer")
        })
    };
    let count = parse(2, 5_000);
    let rate = parse(3, 20);
    let outstanding = parse(4, 128);
    assert!((1..=100_000).contains(&count));
    assert!((1..=10_000).contains(&rate));
    assert!((1..=1024).contains(&outstanding));
    let permission_reads = parse(5, 1);
    assert!(permission_reads <= 1);
    let chain_id = parse(6, DEFAULT_CHAIN_ID as usize) as u64;
    let trusted: vera_domain::ConsensusPublicKey = std::fs::read(&args[1]).map_or_else(
        |_| {
            let bytes = hex::decode(args[1].trim_start_matches("0x")).expect("trusted key hex");
            vera_domain::ConsensusPublicKey::decode(commonware_codec::Copying(bytes.as_slice()))
                .expect("trusted group key bytes")
        },
        |bytes| {
            let genesis: vera_genesis::VeraGenesis =
                serde_json::from_slice(&bytes).expect("parse genesis.json");
            *genesis
                .decode_epoch_info()
                .expect("decode epoch info")
                .expect("genesis carries epoch info")
                .output
                .public()
                .public()
        },
    );
    let extra = args
        .get(7)
        .map(|list| list.split(',').map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();

    let client = Arc::new(VeraClient::new(&args[0]));
    let setup = BlsSigner::new(1u64.into(), chain_id).unwrap();
    let raw = setup
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: b"name: wan\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n"
                    .to_vec()
                    .into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let setup_started = Instant::now();
    let hash = client
        .send_native_tx(&raw)
        .await
        .expect("submit setup policy");
    assert_eq!(hash, NativeTx::decode_wire(&raw).unwrap().tx_id().0);
    let receipt = qualification::receipt(&client, hash, &trusted).await;
    let policies = client
        .read_policy_page(None, 2, receipt.revision.height, &trusted)
        .await
        .expect("certified setup policy");
    assert!(
        policies.continuation.is_none(),
        "use an isolated test deployment"
    );
    assert_eq!(policies.records.len(), 1, "use an isolated test deployment");
    let policy = &policies.records[0];
    assert_eq!(policy.metadata.tx_hash.as_slice(), hash.as_slice());
    assert_eq!(policy.metadata.owner_did, setup.did());
    let policy_id = vera_client::parse_policy_id(&policy.policy.id).unwrap();

    let reads = Arc::new(driver::ReadContext {
        trusted,
        policy: policy.policy.id.clone(),
        permissions: permission_reads == 1,
    });
    let requests: Vec<_> = (0..count)
        .map(|index| {
            let signer = BlsSigner::new(((index + 2) as u64).into(), chain_id).unwrap();
            let raw = signer
                .sign_native_tx(
                    ACP_ADDRESS,
                    IAcp::registerObjectCall {
                        policyId: policy_id,
                        resource: "file".into(),
                        objectId: index.to_string(),
                    }
                    .abi_encode()
                    .into(),
                )
                .unwrap();
            driver::Request {
                index,
                object_id: index.to_string(),
                expected_access: true,
                final_registered: None,
                hash: NativeTx::decode_wire(&raw).unwrap().tx_id().0,
                owner: signer.did().to_string(),
                raw,
            }
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "kind": "configuration",
            "workload": "wan_certified_native_registrations",
            "format_version": 1,
            "rpc": args[0],
            "extra_rpcs": extra,
            "count": count,
            "arrivals_per_second": rate,
            "max_outstanding": outstanding,
            "permission_reads_per_write": permission_reads,
            "chain_id": chain_id,
            "setup_policy_ms": setup_started.elapsed().as_millis(),
            "max_operations_per_revision": vera_domain::MAX_BLOCK_TXS,
        })
    );

    let limit = Arc::new(Semaphore::new(outstanding));
    let mut tasks = JoinSet::new();
    let started = Instant::now();
    for request in requests {
        let scheduled = started + Duration::from_secs_f64(request.index as f64 / rate as f64);
        tokio::time::sleep_until(scheduled).await;
        let permit = limit.clone().try_acquire_owned().ok();
        tasks.spawn(driver::observe(
            client.clone(),
            request,
            scheduled,
            permit,
            reads.clone(),
        ));
    }
    let mut observations = Vec::with_capacity(count);
    while let Some(result) = tasks.join_next().await {
        observations.push(result.expect("request task panicked"));
    }
    let elapsed = started.elapsed();
    observations.sort_unstable_by_key(|observation| observation.request.index);
    for observation in &observations {
        println!("{}", observation.json());
    }
    println!("{}", driver::summary(&observations, elapsed));
    driver::assert_no_verification_failures(&observations);
    assert!(observations.iter().all(driver::Observation::completed));

    {
        let replicas: Vec<_> = extra
            .iter()
            .map(VeraClient::new)
            .chain([VeraClient::new(&args[0])])
            .collect();
        let mut checks = stream::iter(observations.iter())
            .map(|observation| qualification::verify(&replicas, observation, &reads))
            .buffer_unordered(8);
        let mut verified = 0;
        let mut unresolved = 0;
        while let Some(resolution) = checks.next().await {
            verified += usize::from(resolution);
            unresolved += usize::from(!resolution);
        }
        println!(
            "{}",
            serde_json::json!({
                "kind": "verification",
                "replicas": replicas.len(),
                "verified": verified,
                "unresolved": unresolved,
            })
        );
        assert_eq!(unresolved, 0, "cross-region verification failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use vera_e2e::cluster::{GenesisBuilder, KeySet, TestCluster};

    #[tokio::test]
    async fn certified_remote_workload_checks_all_replicas() {
        let keys = KeySet::builder().seed(42).build().unwrap();
        let trusted = hex::encode(keys.epoch_info().output.public().public().encode());
        let cluster = TestCluster::builder()
            .nodes(4)
            .seed(42)
            .chain_id(DEFAULT_CHAIN_ID)
            .genesis(
                GenesisBuilder::devnet()
                    .blocks_per_epoch(192)
                    .simplex(Default::default()),
            )
            .build()
            .await
            .unwrap();
        run(vec![
            cluster.node(0).rpc_url(),
            trusted,
            "16".into(),
            "8".into(),
            "16".into(),
            "1".into(),
            DEFAULT_CHAIN_ID.to_string(),
            (1..4)
                .map(|index| cluster.node(index).rpc_url())
                .collect::<Vec<_>>()
                .join(","),
        ])
        .await;
    }
}
