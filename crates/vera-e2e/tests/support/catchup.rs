//! Shared empty-replica recovery checks for replay and snapshot startup.

use std::{fs, time::Duration};

use commonware_codec::Encode as _;
use serde_json::json;
use vera_client::{
    AccessRequest, Actor, BlsSigner, ModuleId, Object, Operation, PERMISSION_LIMITS,
    RECORD_PROOF_BYTES, VeraClient,
};
use vera_domain::{
    ConsensusPublicKey, DkgPayload, LightBlock, verify_finalized_block, verify_light_block,
};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};

#[path = "epoch_share.rs"]
mod epoch_share;

#[path = "backup.rs"]
mod backup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplicaSource {
    Empty,
    StoppedBackup,
}

const OBJECT: &str = "doc/child";
const POLL: Duration = Duration::from_millis(100);
fn deadline() -> Duration {
    let scale = std::env::var("VERA_E2E_DEADLINE_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    Duration::from_secs(90 * scale as u64)
}
const READER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const POLICY: &[u8] = b"name: replayed
resources:
  - name: file
    relations:
      - name: reader
    permissions:
      - name: read
        expr: reader
";

async fn certified_height(
    client: &VeraClient,
    minimum: u64,
    trusted_key: &ConsensusPublicKey,
) -> LightBlock {
    tokio::time::timeout(deadline(), async {
        loop {
            let height: String = client
                .rpc_call_typed("eth_blockNumber", json!([]))
                .await
                .unwrap();
            let height = u64::from_str_radix(height.trim_start_matches("0x"), 16).unwrap();
            if height >= minimum {
                let result = client
                    .rpc_call_typed::<LightBlock>(
                        "vera_getLightBlock",
                        json!([format!("0x{height:x}")]),
                    )
                    .await;
                match result {
                    Ok(light) => {
                        verify_light_block(&light, trusted_key).unwrap();
                        assert_eq!(light.height, height);
                        return light;
                    }
                    Err(vera_client::ClientError::Rpc { message, .. })
                        if message.contains("finalization certificate not found") => {}
                    Err(error) => panic!("light block fetch failed: {error}"),
                }
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("certified revision deadline")
}

async fn current_access(
    client: &VeraClient,
    policy: &str,
    request: &AccessRequest,
    minimum: u64,
    trusted_key: &ConsensusPublicKey,
) -> (LightBlock, bool) {
    certified_height(client, minimum, trusted_key).await;
    client
        .verify_current_access(policy, request, minimum, trusted_key, PERMISSION_LIMITS)
        .await
        .unwrap()
}

async fn check_pruned_rosters(
    client: &VeraClient,
    minimum: u64,
    trusted: &ConsensusPublicKey,
    expected: &[u8],
) {
    let prefix = b"consensus_roster/";
    let current = client
        .read_current_prefix(ModuleId::Vera, prefix, minimum, trusted, RECORD_PROOF_BYTES)
        .await
        .unwrap();
    let evidence = current
        .verify(ModuleId::Vera, prefix, minimum, trusted, RECORD_PROOF_BYTES)
        .unwrap();
    assert_eq!(evidence.entries.len(), 3);
    let latest = (current.revision.height + 1) / 20 + 2;
    for (offset, entry) in evidence.entries.iter().enumerate() {
        let epoch = u64::from_be_bytes(entry.key[prefix.len()..].try_into().unwrap());
        assert_eq!(epoch, latest - 2 + offset as u64);
        assert!(epoch > 3, "epoch 3 must have left live state");
        assert_eq!(entry.value.as_ref(), expected);
    }
    let historic: LightBlock = client
        .rpc_call_typed("vera_getLightBlock", json!(["0x27"]))
        .await
        .unwrap();
    let boundary = verify_finalized_block(&historic, trusted).unwrap();
    assert_eq!(boundary.height, 39);
    let Some(DkgPayload::EpochInfo(info)) = boundary.payload else {
        panic!("historical boundary is missing the selection artifact");
    };
    assert_eq!(info.epoch.get(), 2);
    let selected: Vec<_> = info
        .next_players
        .iter()
        .flat_map(|key| key.encode().to_vec())
        .collect();
    assert_eq!(selected, expected);
}

pub(super) async fn recover_replica(
    snapshot: bool,
    interrupt: bool,
    pruning: bool,
    source: ReplicaSource,
) {
    match source {
        ReplicaSource::Empty => {
            recover_replica_with_delay(snapshot, interrupt, pruning, false).await
        }
        ReplicaSource::StoppedBackup => {
            recover_replica_from(snapshot, interrupt, pruning, false, source).await;
        }
    }
}

pub(super) async fn recover_replica_with_delay(
    snapshot: bool,
    interrupt: bool,
    pruning: bool,
    stale_floor: bool,
) {
    recover_replica_from(
        snapshot,
        interrupt,
        pruning,
        stale_floor,
        ReplicaSource::Empty,
    )
    .await;
}

async fn recover_replica_from(
    snapshot: bool,
    interrupt: bool,
    pruning: bool,
    stale_floor: bool,
    source: ReplicaSource,
) {
    let from_backup = source == ReplicaSource::StoppedBackup;
    assert!(!from_backup || !(snapshot || interrupt || pruning || stale_floor));
    let epoch_length = if from_backup { 192 } else { 20 };
    let simplex = if from_backup {
        vera_domain::SimplexParameters::default()
    } else {
        // Short epochs still need a leader opportunity for all four dealers.
        vera_domain::SimplexParameters {
            term_length: 2,
            optimistic_views: 1,
            ..vera_domain::SimplexParameters::default()
        }
    };
    simplex.validate().unwrap();
    assert!(
        vera_domain::max_epoch_participants(
            std::num::NonZeroU64::new(epoch_length).unwrap(),
            std::num::NonZeroU64::new(simplex.term_length).unwrap(),
        ) >= 4
    );
    let genesis = GenesisBuilder::devnet()
        .blocks_per_epoch(epoch_length)
        .simplex(simplex);
    let deployment = 9041;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted_key = *keys.epoch_info().output.public().public();
    let expected_roster: Vec<_> = keys
        .epoch_info()
        .output
        .players()
        .iter()
        .flat_map(|key| key.encode().to_vec())
        .collect();
    let mut cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(genesis)
        .preset(ConsensusPreset::Normal)
        .jmt_seeder(move |dir, _| {
            if pruning {
                use std::io::Write as _;
                let mut config = fs::OpenOptions::new()
                    .append(true)
                    .open(dir.join("config.toml"))
                    .unwrap();
                writeln!(config, "\n[pruning]\nmaintenance_interval = 2\nretained_consensus_revisions = 32\nretained_state_revisions = 0").unwrap();
            }
        })
        .build()
        .await
        .unwrap();

    let directory = cluster.node(3).data_dir.clone();
    let backup_root = tempfile::tempdir().unwrap();
    let backup_directory = backup_root.path().join("validator");
    if !from_backup {
        cluster.kill_node(3);
        let archived = directory.with_file_name("node3-before-replay");
        fs::rename(&directory, &archived).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::rename(archived.join("logs"), directory.join("logs")).unwrap();
        for filename in ["config.toml", "genesis.json", "validator.key"] {
            fs::copy(archived.join(filename), directory.join(filename)).unwrap();
        }
        vera_cli::write_private(
            directory.join("secrets.json"),
            &serde_json::to_vec(&json!({
                "shares": {"0": hex::encode(keys.share(3).unwrap().encode())},
                "seeds": {},
                "dealings": {},
            }))
            .unwrap(),
        )
        .unwrap();
    }

    if snapshot {
        let path = directory.join("config.toml");
        let mut config = fs::read_to_string(&path).unwrap();
        config.push_str("\n[snapshot]\n");
        if stale_floor {
            config.push_str("initialization_timeout_ms = 30000\nfloor_stall_seconds = 3\n");
        }
        fs::write(path, config).unwrap();
    }

    let origin = VeraClient::new(cluster.node(0).rpc_url());
    tokio::time::timeout(deadline(), async {
        while origin.chain_id().await.is_err() {
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("origin startup deadline");
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let mut receipts = vec![
        origin
            .native_create_policy(&signer, POLICY, 1)
            .await
            .unwrap(),
    ];
    let policies = origin.get_policy_ids().await.unwrap();
    assert_eq!(policies.len(), 1);
    let policy = policies[0].parse().unwrap();
    receipts.push(
        origin
            .native_register_object(&signer, policy, OBJECT, "file")
            .await
            .unwrap(),
    );
    receipts.push(
        origin
            .native_set_relationship(&signer, policy, "file", OBJECT, "reader", READER)
            .await
            .unwrap(),
    );
    let request = AccessRequest {
        actor: Actor(READER.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "file".into(),
                id: OBJECT.into(),
            },
            permission: "read".into(),
        }],
    };
    let (_, allowed) = current_access(
        &origin,
        &policies[0],
        &request,
        receipts.last().unwrap().block_number,
        &trusted_key,
    )
    .await;
    assert!(allowed);
    if from_backup {
        let replica = VeraClient::new(cluster.node(3).rpc_url());
        let (_, allowed) = current_access(
            &replica,
            &policies[0],
            &request,
            receipts.last().unwrap().block_number,
            &trusted_key,
        )
        .await;
        assert!(
            allowed,
            "the backup must contain the grant before revocation"
        );
        cluster.kill_node(3);
        backup::copy_directory(&directory, &backup_directory).unwrap();
        for name in ["validator.key", "secrets.json", "native-genesis.bin"] {
            assert!(
                fs::read(directory.join(name)).unwrap()
                    == fs::read(backup_directory.join(name)).unwrap(),
                "the backup must preserve identity and deployment material"
            );
        }
    }
    receipts.push(
        origin
            .native_delete_relationship(&signer, policy, "file", OBJECT, "reader", READER)
            .await
            .unwrap(),
    );
    assert!(receipts.iter().all(|receipt| receipt.status == 1));
    let (target, allowed) = current_access(
        &origin,
        &policies[0],
        &request,
        ((if snapshot { 4 } else { 2 }) * epoch_length + 2)
            .max(receipts.last().unwrap().block_number),
        &trusted_key,
    )
    .await;
    assert!(target.epoch >= if snapshot { 4 } else { 2 });
    if snapshot {
        check_pruned_rosters(&origin, target.height, &trusted_key, &expected_roster).await;
    }
    assert!(!allowed);
    eprintln!("cold replica starts at origin height {}", target.height);

    if pruning {
        for index in 0..3 {
            let logs = fs::read_to_string(cluster.node(index).log_dir.join("stdout.log")).unwrap();
            assert!(
                logs.matches("pruned state journals").count() > 10,
                "peers must prune before the empty replica starts"
            );
        }
    }
    let crash_marker = directory.join("snapshot-import-crash");
    if interrupt {
        fs::write(&crash_marker, []).unwrap();
    }
    let pause = directory.join("snapshot-probe-pause");
    if stale_floor {
        fs::write(&pause, []).unwrap();
    }
    if from_backup {
        assert!(!cluster.node_mut(3).process.is_running());
        fs::remove_dir_all(&directory).unwrap();
        backup::copy_directory(&backup_directory, &directory).unwrap();
        for name in ["validator.key", "secrets.json", "native-genesis.bin"] {
            assert!(
                fs::read(directory.join(name)).unwrap()
                    == fs::read(backup_directory.join(name)).unwrap(),
                "restoration must preserve identity and deployment material"
            );
        }
    }
    cluster.restart_node(3).unwrap();
    if stale_floor {
        tokio::time::timeout(deadline(), async {
            while !directory.join("snapshot-probe-ready").exists() {
                assert!(cluster.node_mut(3).process.is_running());
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("snapshot probe pause deadline");
        let paused = certified_height(&origin, target.height, &trusted_key).await;
        // Advance beyond both peer retention and the selected epoch before startup resumes.
        certified_height(&origin, paused.height + 100, &trusted_key).await;
        fs::remove_file(pause).unwrap();
        tokio::time::timeout(deadline(), async {
            while cluster.node_mut(3).process.is_running() {
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("stale snapshot target must finish initialization within its deadline");
        assert!(
            !crash_marker.exists(),
            "stale target must steer into durable history import"
        );
        eprintln!("stale snapshot target reached durable history import");
    }
    if interrupt {
        tokio::time::timeout(deadline(), async {
            while cluster.node_mut(3).process.is_running() {
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("snapshot import crash deadline");
        assert!(
            !crash_marker.exists(),
            "crash must occur after a durable history record"
        );
        assert!(
            VeraClient::new(cluster.node(3).rpc_url())
                .chain_id()
                .await
                .is_err()
        );
        let path = directory.join("config.toml");
        let config = fs::read_to_string(&path).unwrap();
        let (base, _) = config
            .split_once("\n[snapshot]\n")
            .unwrap_or((config.as_str(), ""));
        fs::write(path, base).unwrap();
        cluster.restart_node(3).unwrap();
    }
    cluster.wait_ready(deadline()).await.unwrap();
    let replica = VeraClient::new(cluster.node(3).rpc_url());
    for receipt in receipts {
        let replayed = tokio::time::timeout(
            deadline(),
            replica.wait_for_receipt(receipt.transaction_hash, POLL, 900),
        )
        .await
        .expect("cold replay deadline")
        .unwrap();
        assert_eq!(
            serde_json::to_value(replayed).unwrap(),
            serde_json::to_value(receipt).unwrap()
        );
    }
    let (caught_up, allowed) = current_access(
        &replica,
        &policies[0],
        &request,
        target.height,
        &trusted_key,
    )
    .await;
    assert!(!allowed);
    let restored: LightBlock = replica
        .rpc_call_typed(
            "vera_getLightBlock",
            json!([format!("0x{:x}", target.height)]),
        )
        .await
        .unwrap();
    verify_light_block(&restored, &trusted_key).unwrap();
    assert_eq!(restored, target);
    assert_eq!(replica.get_policy_ids().await.unwrap(), policies);
    assert_eq!(replica.get_native_nonce(signer.did()).await.unwrap(), 4);
    if snapshot {
        let status: serde_json::Value = replica
            .rpc_call_typed("vera_nodeStatus", json!([]))
            .await
            .unwrap();
        let snapshot_revision = status["snapshotRevision"]
            .as_u64()
            .expect("snapshot handoff must run");
        assert!(
            snapshot_revision >= 79,
            "snapshot must include roster pruning"
        );
        check_pruned_rosters(&replica, target.height, &trusted_key, &expected_roster).await;
        cluster.kill_node(3);
        cluster.restart_node(3).unwrap();
        cluster.wait_ready(deadline()).await.unwrap();
        assert_eq!(replica.get_native_nonce(signer.did()).await.unwrap(), 4);
        let (_, allowed) = current_access(
            &replica,
            &policies[0],
            &request,
            target.height,
            &trusted_key,
        )
        .await;
        assert!(!allowed);
        let status: serde_json::Value = replica
            .rpc_call_typed("vera_nodeStatus", json!([]))
            .await
            .unwrap();
        assert!(status["snapshotRevision"].as_u64().unwrap() >= snapshot_revision);
        check_pruned_rosters(&replica, target.height, &trusted_key, &expected_roster).await;
    }

    // Allow a complete resharing ceremony after replay, then require this
    // replica's vote: only three of the four participants remain online.
    // One full epoch of live finalization past the next boundary: the
    // replica can reach any earlier height by replaying history without
    // participating in a resharing ceremony, and killing a peer before the
    // replica's current-epoch share exists drops the online set below quorum.
    let ready = certified_height(
        &replica,
        (caught_up.epoch + 3) * epoch_length + 2,
        &trusted_key,
    )
    .await;
    epoch_share::wait_for_epoch_share(
        &cluster.node(3).data_dir.join("secrets.json"),
        ready.height / epoch_length,
        deadline(),
    )
    .await;
    cluster.kill_node(2);

    let subsequent = replica
        .native_create_policy(
            &signer,
            b"name: after-replay\nresources:\n  - name: file\n",
            1,
        )
        .await
        .unwrap();
    assert_eq!(subsequent.status, 1);
    origin
        .wait_for_receipt(subsequent.transaction_hash, POLL, 900)
        .await
        .unwrap();
    assert_eq!(origin.get_native_nonce(signer.did()).await.unwrap(), 5);
    let (active, allowed) = current_access(
        &replica,
        &policies[0],
        &request,
        (ready.epoch + 1) * epoch_length + 2,
        &trusted_key,
    )
    .await;
    assert!(active.height >= subsequent.block_number);
    assert!(!allowed);
    eprintln!(
        "recovered replica required for quorum through height {}",
        active.height
    );
}
