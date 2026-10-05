//! Four-node certified registration workload; see docs/native-workload.md for arguments.
//! Build verad in release mode and set VERAD_BINARY to that binary before running.

#[path = "operation_baseline/driver.rs"]
mod driver;
#[path = "operation_baseline/replica_barrier.rs"]
mod replica_barrier;
#[path = "operation_baseline/resources.rs"]
mod resources;
#[path = "operation_baseline/retention.rs"]
mod retention;
#[path = "operation_baseline/updates.rs"]
mod updates;

#[cfg(test)]
#[path = "operation_baseline/updates_tests.rs"]
mod updates_tests;

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use futures::{StreamExt, stream};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};
use vera_client::{ACP_ADDRESS, BlsSigner, VeraClient};
use vera_domain::NativeTx;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::acp::abi::IAcp;

const CHAIN_ID: u64 = 9001;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        args.len() <= 11,
        "usage: operation_baseline [count] [arrivals/sec] [max outstanding] [permission reads 0/1] [fast|normal|stress] [RPC connections] [epoch revisions] [retention minimum revision] [fixed update objects, 0 for registrations] [retained consensus revisions, 0 disables pruning] [pipelined consensus 0/1]"
    );
    let parse = |index: usize, default: usize| {
        args.get(index).map_or(default, |value| {
            value.parse::<usize>().expect("positive integer")
        })
    };
    let count = parse(0, 200);
    let rate = parse(1, 20);
    let outstanding = parse(2, 128);
    let permission_reads = parse(3, 1);
    assert!(permission_reads <= 1);
    let preset = match args.get(4).map(String::as_str).unwrap_or("normal") {
        "fast" => ConsensusPreset::Fast,
        "normal" => ConsensusPreset::Normal,
        "stress" => ConsensusPreset::Stress,
        _ => panic!("timing preset must be fast, normal or stress"),
    };
    let rpc_connections = u32::try_from(parse(5, 100))
        .ok()
        .and_then(std::num::NonZeroU32::new)
        .expect("positive RPC connection limit within u32");
    let epoch_length = u64::try_from(parse(6, 20))
        .ok()
        .and_then(std::num::NonZeroU64::new)
        .expect("positive epoch length within u64");
    let retention_height = u64::try_from(parse(7, 0)).expect("retention revision within u64");
    let update_objects = parse(8, 0);
    assert!(update_objects <= count && update_objects <= outstanding);
    assert!(
        update_objects == 0 || permission_reads == 1,
        "updates require permission verification"
    );
    let retained_consensus = parse(9, 0);
    let pipelined = parse(10, 0);
    assert!(pipelined <= 1);
    let simplex = (pipelined == 1).then(vera_domain::SimplexParameters::default);
    let term_length =
        std::num::NonZeroU64::new(simplex.map_or(1, |parameters| parameters.term_length)).unwrap();
    assert!(
        vera_domain::max_epoch_participants(epoch_length, term_length) >= 4,
        "epoch is too short for four participants with the configured leader term"
    );
    let mut genesis = GenesisBuilder::devnet().blocks_per_epoch(epoch_length.get());
    if let Some(parameters) = simplex {
        genesis = genesis.simplex(parameters);
    }
    if retained_consensus > 0 {
        let window = retained_consensus
            .checked_add(2)
            .expect("retention window overflow");
        assert!(
            window as u128 >= epoch_length.get() as u128,
            "consensus retention must cover a complete DKG epoch"
        );
    }
    let timing = preset.params();
    let keys = KeySet::builder().seed(42).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    assert!(
        (1..=100_000).contains(&count),
        "count must be within 1..=100000"
    );
    assert!(
        (1..=10_000).contains(&rate),
        "rate must be within 1..=10000"
    );
    assert!((1..=1024).contains(&outstanding));

    let mut cluster = TestCluster::builder()
        .nodes(4)
        .genesis(genesis)
        .seed(42)
        .chain_id(CHAIN_ID)
        .preset(preset)
        .rpc_max_connections(rpc_connections)
        .jmt_seeder(move |dir, _| {
            if retained_consensus > 0 {
                use std::io::Write as _;
                let mut config = std::fs::OpenOptions::new().append(true)
                    .open(dir.join("config.toml")).unwrap();
                writeln!(config, "\n[pruning]\nmaintenance_interval = 64\nretained_consensus_revisions = {retained_consensus}\nretained_state_revisions = 0").unwrap();
            }
        })
        .build()
        .await
        .expect("start cluster");
    cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("ready cluster");
    let client_queue_capacity =
        std::num::NonZeroU32::new(u32::try_from(outstanding).unwrap()).unwrap();
    let client_queue_timeout = Duration::from_secs(1);
    let client = Arc::new(
        VeraClient::new(cluster.node(0).rpc_url())
            .with_request_queue(client_queue_capacity, client_queue_timeout),
    );
    let setup = BlsSigner::new(((count + 1) as u64).into(), CHAIN_ID).unwrap();
    let raw = setup
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: b"name: baseline\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n"
                    .to_vec()
                    .into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let setup_receipt = tokio::time::timeout(Duration::from_secs(30), async {
        let hash = client.send_native_tx(&raw).await.unwrap();
        client
            .wait_for_receipt(hash, driver::POLL_INTERVAL, 600)
            .await
            .unwrap()
    })
    .await
    .expect("policy creation timed out");
    assert_eq!(setup_receipt.status, 1);
    let ids = client.get_policy_ids().await.unwrap();
    assert_eq!(ids.len(), 1);
    let policy_id = FixedBytes::<32>::from_slice(&hex::decode(&ids[0]).unwrap());

    let reads = Arc::new(driver::ReadContext {
        trusted,
        policy: ids[0].clone(),
        permissions: permission_reads == 1,
    });

    let historical = if retention_height > 0 {
        Some(
            retention::Probe::capture(
                &client,
                setup_receipt.transaction_hash,
                setup_receipt.block_number,
                setup_receipt.block_hash,
            )
            .await,
        )
    } else {
        None
    };
    let preparation_start = Instant::now();
    let prepared_updates = if update_objects > 0 {
        Some(
            updates::prepare(
                client.clone(),
                reads.clone(),
                policy_id,
                count,
                update_objects,
                (rpc_connections.get() as usize).min(8),
            )
            .await,
        )
    } else {
        None
    };
    let update_preparation_seconds =
        (update_objects > 0).then(|| preparation_start.elapsed().as_secs_f64());
    let signing_start = Instant::now();
    let requests: Vec<_> = prepared_updates.unwrap_or_else(|| {
        (0..count)
            .map(|index| {
                let signer = BlsSigner::new(((index + 1) as u64).into(), CHAIN_ID).unwrap();
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
            .collect()
    });
    println!(
        "{}",
        serde_json::json!({
            "kind": "configuration", "workload": if update_objects == 0 { "certified_native_registrations" } else { "certified_native_object_updates" },
            "fixed_update_objects": update_objects,
            "pruning": (retained_consensus > 0).then(|| serde_json::json!({
                "maintenance_interval": 64,
                "retained_consensus_revisions": retained_consensus,
                "retained_state_revisions": 0,
            })),
            "arrival_model": if update_objects == 0 { "scheduled_drop_when_full" } else { "scheduled_wait_for_previous_per_object" },
            "format_version": 2, "permission_reads_per_write": permission_reads,
            "runner_debug_assertions": cfg!(debug_assertions),
            "revisions_per_epoch": epoch_length.get(),
            "simplex": simplex,
            "proposal_batch_wait_ms": simplex.map(|_| (timing.leader_timeout / 4).min(Duration::from_millis(100)).as_millis()),
            "retention_minimum_revision": retention_height,
            "max_operations_per_revision": vera_domain::MAX_BLOCK_TXS,
            "max_encoded_operation_bytes_per_revision": vera_domain::MAX_BLOCK_TX_BYTES,
            "max_encoded_revision_bytes": vera_domain::MAX_BLOCK_BYTES,
            "client_max_concurrent_requests": 64,
            "client_queue_capacity": client_queue_capacity.get(),
            "client_queue_timeout_ms": client_queue_timeout.as_millis(),
            "rpc_max_connections": rpc_connections.get(), "nodes": 4, "preset": format!("{preset:?}"),
            "leader_timeout_ms": timing.leader_timeout.as_millis(),
            "notarization_timeout_ms": timing.notarization_timeout.as_millis(),
            "nullify_retry_ms": timing.nullify_retry.as_millis(), "count": count, "arrivals_per_second": rate,
            "max_outstanding": outstanding, "receipt_poll_ms": driver::POLL_INTERVAL.as_millis(),
            "request_timeout_ms": driver::REQUEST_TIMEOUT.as_millis(),
            "signing_seconds": (update_objects == 0).then(|| signing_start.elapsed().as_secs_f64()),
            "update_preparation_seconds": update_preparation_seconds,
            "signed_bytes": requests.iter().map(|r| r.raw.len()).sum::<usize>(),
            "node_data_dirs": (0..4).map(|i| cluster.node(i).data_dir.display().to_string()).collect::<Vec<_>>(),
        })
    );

    resources::storage(&cluster, "before").await;
    let (stop_resources, resource_task) = resources::start(&cluster);
    let limit = Arc::new(Semaphore::new(outstanding));
    let mut tasks = JoinSet::new();
    let started = Instant::now();
    let mut observations = if update_objects > 0 {
        updates::run(
            requests,
            update_objects,
            rate,
            started,
            client.clone(),
            reads.clone(),
        )
        .await
    } else {
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
        observations
    };
    let elapsed = started.elapsed();
    let _ = stop_resources.send(());
    resource_task.await.expect("resource sampler task");
    resources::storage(&cluster, "after").await;
    observations.sort_unstable_by_key(|o| o.request.index);
    for observation in &observations {
        println!("{}", observation.json());
    }
    println!("{}", driver::summary(&observations, elapsed));

    if update_objects > 0 {
        for observation in &observations {
            observation.assert_completed();
        }
    }

    let replica_clients: Vec<_> = (0..cluster.node_count())
        .map(|i| VeraClient::new(cluster.node(i).rpc_url()))
        .collect();
    if let Some(evidence) = replica_barrier::synchronize(
        &replica_clients,
        observations
            .iter()
            .filter_map(driver::Observation::measured_anchor),
    )
    .await
    .expect("replica final-state barrier")
    {
        println!("{evidence}");
    }
    let verification_concurrency = (rpc_connections.get() as usize).min(8);
    let mut checks = stream::iter(observations.iter())
        .map(|observation| driver::verify(&replica_clients, policy_id, observation))
        .buffer_unordered(verification_concurrency);
    let mut reconciled = 0;
    let mut unresolved = 0;
    while let Some(resolution) = checks.next().await {
        match resolution {
            driver::Resolution::Verified => reconciled += 1,
            driver::Resolution::Unresolved => unresolved += 1,
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "verification", "replicas": 4, "verified": reconciled, "unresolved": unresolved,
            "concurrency": verification_concurrency,
        })
    );
    if update_objects > 0 {
        for replica in &replica_clients {
            updates::verify_state(replica, &observations, update_objects, &reads).await;
        }
    }
    cluster
        .wait_ready(Duration::from_secs(10))
        .await
        .expect("cluster health after workload");
    assert_eq!(
        unresolved, 0,
        "unresolved outcomes prevent a complete baseline"
    );

    if let Some(probe) = &historical {
        println!(
            "{}",
            serde_json::json!({"kind": "retention_wait", "minimum_revision": retention_height})
        );
        retention::wait(&replica_clients, retention_height).await;
        for replica in &replica_clients {
            probe.check(replica).await;
            replica
                .read_receipt(setup_receipt.transaction_hash, &trusted)
                .await
                .unwrap()
                .expect("historical certified receipt");
        }
        println!(
            "{}",
            serde_json::json!({"kind": "retention", "replicas": 4,
            "selected_revision": setup_receipt.block_number, "minimum_head": retention_height,
            "queries_per_replica": 6, "certified_receipts": 4})
        );
    }

    cluster.kill_node(3);
    let probe = setup
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::registerObjectCall {
                policyId: policy_id,
                resource: "file".into(),
                objectId: "recovery-probe".into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let probe_receipt = tokio::time::timeout(driver::REQUEST_TIMEOUT, async {
        let hash = client.send_native_tx(&probe).await.unwrap();
        client
            .wait_for_receipt(hash, driver::POLL_INTERVAL, 600)
            .await
            .unwrap()
    })
    .await
    .expect("three-node write timed out");
    assert_eq!(probe_receipt.status, 1);
    let restart = Instant::now();
    cluster.restart_node(3).expect("restart replica");
    cluster
        .wait_ready(driver::REQUEST_TIMEOUT)
        .await
        .expect("restarted RPC ready");
    let rpc_ready_ms = restart.elapsed().as_secs_f64() * 1000.0;
    let recovered = VeraClient::new(cluster.node(3).rpc_url());
    let recovered_receipt = tokio::time::timeout(
        driver::REQUEST_TIMEOUT,
        recovered.wait_for_receipt(probe_receipt.transaction_hash, driver::POLL_INTERVAL, 600),
    )
    .await
    .expect("recovery deadline")
    .expect("recover probe receipt");
    assert_eq!(recovered_receipt.block_hash, probe_receipt.block_hash);
    assert_eq!(recovered_receipt.status, 1);
    let (registered, owner) = recovered
        .get_object_owner(policy_id, "file", "recovery-probe")
        .await
        .unwrap();
    assert!(registered);
    let owner: serde_json::Value = serde_json::from_slice(&owner).unwrap();
    assert_eq!(owner["metadata"]["owner_did"], setup.did());
    if let Some(probe) = &historical {
        probe.check(&recovered).await;
        recovered
            .read_receipt(setup_receipt.transaction_hash, &trusted)
            .await
            .unwrap()
            .expect("recovered historical certified receipt");
        println!(
            "{}",
            serde_json::json!({"kind": "retention_recovery", "queries": 6, "certified_receipts": 1})
        );
    }
    let recovery_ms = restart.elapsed().as_secs_f64() * 1000.0;
    let mut receipt_mismatches = 0;
    let mut state_mismatches = 0;
    let mut checks = stream::iter(observations.iter())
        .map(|observation| driver::check_recovered(&client, &recovered, policy_id, observation))
        .buffer_unordered(verification_concurrency);
    while let Some((receipt_matches, state_matches)) = checks.next().await {
        receipt_mismatches += usize::from(!receipt_matches);
        state_mismatches += usize::from(!state_matches);
    }
    if update_objects > 0 {
        updates::verify_state(&recovered, &observations, update_objects, &reads).await;
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "recovery", "rpc_ready_ms": rpc_ready_ms,
            "restart_to_probe_observed_ms": recovery_ms, "inspected_operations": count,
            "receipt_mismatches": receipt_mismatches, "state_mismatches": state_mismatches,
            "probe_height": probe_receipt.block_number,
        })
    );
    assert_eq!(
        state_mismatches, 0,
        "restarted replica lost application state"
    );
    assert_eq!(
        receipt_mismatches, 0,
        "restarted replica lost receipt history"
    );
    driver::assert_no_verification_failures(&observations);
}
