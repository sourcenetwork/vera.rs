//! Admit a new process through native membership writes and distributed resharing.

#[path = "support/administration.rs"]
mod administration;

#[path = "support/membership_load.rs"]
mod membership_load;

#[path = "support/epoch_share.rs"]
mod epoch_share;

use std::{fs, net::TcpListener, process::Stdio, time::Duration};

use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_sol_types::SolCall;
use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519};
use serde_json::json;
use vera_client::{
    BlsSigner, VALIDATOR_REGISTRY_ADDRESS, VeraClient, administration::AdministrativeCommand,
};
use vera_domain::{ConsensusPublicKey, EpochMaterial, LightBlock, NativeTx, SimplexParameters};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, NodeConfigBuilder, TestCluster};
use vera_modules::validator_registry::abi::IValidatorRegistry;

fn deadline() -> Duration {
    let scale = std::env::var("VERA_E2E_DEADLINE_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    Duration::from_secs(60 * scale as u64)
}

async fn receipt(client: &VeraClient, id: B256, trusted: &ConsensusPublicKey) -> u64 {
    tokio::time::timeout(deadline(), async {
        loop {
            if let Ok(Some(proof)) = client.read_receipt(id, trusted).await {
                assert!(proof.verify(id, trusted).unwrap().success());
                return proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("certified receipt {id} deadline"))
}

async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: Vec<u8>,
) -> u64 {
    let wire = signer
        .sign_native_tx(VALIDATOR_REGISTRY_ADDRESS, Bytes::from(call))
        .unwrap();
    let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    receipt(client, id, trusted).await
}

async fn membership(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    minimum: u64,
    members: usize,
    epoch_deadline: Duration,
) -> LightBlock {
    tokio::time::timeout(epoch_deadline, async {
        loop {
            if let Ok(height) = client.block_number().await
                && height >= minimum
                && let Ok(revision) = client.read_finalized_revision(height, trusted).await
            {
                let material = EpochMaterial::decode_bounded(
                    &hex::decode(revision.epoch_material.trim_start_matches("0x")).unwrap(),
                )
                .unwrap();
                if material.participants.len() == members {
                    return revision;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("new certified membership deadline")
}

#[tokio::test]
async fn native_member_joins_without_bootstrap_share_and_sustains_quorum() {
    admit_member(false, false, false).await;
}

#[tokio::test]
async fn interrupted_member_recovers_after_admission_without_a_share() {
    admit_member(true, false, false).await;
}

#[cfg(feature = "fault-injection")]
#[tokio::test]
async fn native_member_recovers_after_share_persistence_crash() {
    admit_member(false, true, false).await;
}

#[tokio::test]
async fn pipelined_member_joins_without_bootstrap_share_and_sustains_quorum() {
    admit_member(false, false, true).await;
}

async fn admit_member(interrupt: bool, crash_share: bool, pipelined: bool) {
    let deployment = if pipelined {
        9083
    } else if interrupt {
        9080
    } else {
        9079
    };
    let blocks_per_epoch: u64 = if pipelined { 192 } else { 20 };
    let epoch_deadline = deadline() * if pipelined { 4 } else { 1 };
    let mut genesis = GenesisBuilder::devnet()
        .operators(administration::operators())
        .blocks_per_epoch(blocks_per_epoch);
    if pipelined {
        genesis = genesis.simplex(SimplexParameters::default());
    }
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let mut cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(genesis)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let origin = VeraClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let created = origin.native_create_policy(&signer, b"name: native_membership\nresources:\n  - name: registry\n    relations:\n      - name: admin\n    permissions:\n      - name: manage\n        expr: admin\n", 1).await.unwrap();
    receipt(&origin, created.transaction_hash, &trusted).await;
    let policy = origin.get_policy_ids().await.unwrap().pop().unwrap();
    let policy_id = B256::from_slice(&hex::decode(&policy).unwrap());
    let registered = origin
        .native_register_object(&signer, policy_id, "registry", "registry")
        .await
        .unwrap();
    receipt(&origin, registered.transaction_hash, &trusted).await;
    let granted = origin
        .native_set_relationship(
            &signer,
            policy_id,
            "registry",
            "registry",
            "admin",
            signer.did(),
        )
        .await
        .unwrap();
    receipt(&origin, granted.transaction_hash, &trusted).await;
    let approved = administration::approve(
        &origin,
        AdministrativeCommand::InitializeMembershipPolicy(policy_id.0),
        0,
    )
    .await;
    let initialized = origin
        .native_apply_administration(&signer, &approved)
        .await
        .unwrap();
    receipt(&origin, initialized.transaction_hash, &trusted).await;
    let load = if pipelined {
        Some(membership_load::Load::start(cluster.node(0).rpc_url(), deployment, trusted).await)
    } else {
        None
    };

    let local = tempfile::Builder::new()
        .prefix("incoming-")
        .tempdir_in(cluster.node(0).data_dir.parent().unwrap())
        .unwrap();
    let directory_path = local.path().to_owned();
    if std::env::var_os("VERA_E2E_KEEP").is_some() {
        let _ = local.keep();
        eprintln!("incoming member artifacts: {}", directory_path.display());
    }
    let directory = directory_path.as_path();
    let key = ed25519::PrivateKey::from_seed(deployment + 4);
    let public = key.public_key();
    let public_hex = hex::encode(public.encode());
    let p2p = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    let p2p_port = p2p.local_addr().unwrap().port();
    let rpc_port = rpc.local_addr().unwrap().port();
    fs::copy(
        cluster.node(0).data_dir.join("genesis.json"),
        directory.join("genesis.json"),
    )
    .unwrap();
    fs::write(directory.join("validator.key"), key.encode()).unwrap();
    fs::write(
        directory.join("config.toml"),
        NodeConfigBuilder::new()
            .chain_id(deployment)
            .build_config_toml(directory, p2p_port, rpc_port),
    )
    .unwrap();
    let mut peers: serde_json::Value = serde_json::from_slice(
        &fs::read(
            cluster
                .node(0)
                .data_dir
                .parent()
                .unwrap()
                .join("peers.json"),
        )
        .unwrap(),
    )
    .unwrap();
    peers["participants"]
        .as_array_mut()
        .unwrap()
        .push(json!(public_hex));
    peers["bootstrappers"][&public_hex] = json!(format!("127.0.0.1:{p2p_port}"));
    fs::write(
        directory.join("peers.json"),
        serde_json::to_vec(&peers).unwrap(),
    )
    .unwrap();
    assert!(!directory.join("secrets.json").exists());
    let log = fs::File::create(directory.join("node.log")).unwrap();
    drop((p2p, rpc));
    let mut command = tokio::process::Command::new(vera_e2e::resolve_binary().unwrap());
    command
        .arg("--config")
        .arg(directory.join("config.toml"))
        .arg("--data-dir")
        .arg(directory)
        .arg("--chain-id")
        .arg(deployment.to_string())
        .arg("validator")
        .arg("--peers")
        .arg(directory.join("peers.json"))
        .arg("--rpc-port")
        .arg(rpc_port.to_string())
        .args([
            "--leader-timeout-ms",
            "500",
            "--notarization-timeout-ms",
            "1000",
            "--nullify-retry-ms",
            "2000",
        ])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        .kill_on_drop(true);
    let share_crash_marker = directory.join("secrets.share-crash");
    if crash_share {
        fs::write(&share_crash_marker, []).unwrap();
    }
    let mut incoming = command.spawn().unwrap();
    let joining = VeraClient::new(format!("http://127.0.0.1:{rpc_port}"));
    if interrupt {
        tokio::time::timeout(deadline(), async {
            loop {
                assert!(incoming.try_wait().unwrap().is_none());
                if tokio::net::TcpStream::connect(("127.0.0.1", p2p_port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("incoming member starts before interruption");
        incoming.kill().await.unwrap();
        incoming.wait().await.unwrap();
        assert!(!directory.join("secrets.json").exists());
    }
    let member = Address::from_slice(&keccak256(public.encode())[12..]);
    let admitted = submit(
        &origin,
        &signer,
        &trusted,
        IValidatorRegistry::addValidatorCall {
            evmAddr: member,
            consensusPubkey: B256::from_slice(public.encode().as_ref()),
            p2pAddr: format!("127.0.0.1:{p2p_port}"),
        }
        .abi_encode(),
    )
    .await;
    if interrupt {
        membership(&origin, &trusted, admitted + 1, 5, epoch_deadline).await;
        assert!(!directory.join("secrets.json").exists());
    }
    if crash_share {
        let status = tokio::time::timeout(deadline(), incoming.wait())
            .await
            .expect("share persistence crash deadline")
            .unwrap();
        assert_eq!(status.code(), Some(86));
        assert!(!share_crash_marker.exists());
        let secrets: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("secrets.json")).unwrap()).unwrap();
        assert!(secrets["shares"].get("0").is_none());
        assert!(!secrets["shares"].as_object().unwrap().is_empty());
    }
    if interrupt || crash_share {
        let log = fs::OpenOptions::new()
            .append(true)
            .open(directory.join("node.log"))
            .unwrap();
        command
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        incoming = command.spawn().unwrap();
    }
    let active = membership(&joining, &trusted, admitted + 1, 5, epoch_deadline).await;
    let material = EpochMaterial::decode_bounded(
        &hex::decode(active.epoch_material.trim_start_matches("0x")).unwrap(),
    )
    .unwrap();
    assert!(
        material
            .participants
            .iter()
            .any(|participant| participant == &public)
    );
    assert_ne!(material.sharing, *keys.epoch_info().output.public());
    let secrets: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("secrets.json")).unwrap()).unwrap();
    assert!(secrets["shares"].get("0").is_none());
    assert!(!secrets["shares"].as_object().unwrap().is_empty());

    let current = membership(&origin, &trusted, active.height, 5, epoch_deadline).await;
    epoch_share::wait_for_epoch_share(
        &directory.join("secrets.json"),
        current.epoch,
        epoch_deadline,
    )
    .await;
    cluster.kill_node(3);
    let changed = submit(
        &joining,
        &signer,
        &trusted,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: member,
            active: true,
        }
        .abi_encode(),
    )
    .await;
    assert!(changed > active.height);
    assert!(incoming.try_wait().unwrap().is_none());
    incoming.kill().await.unwrap();
    incoming.wait().await.unwrap();
    let log = fs::OpenOptions::new()
        .append(true)
        .open(directory.join("node.log"))
        .unwrap();
    command
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    incoming = command.spawn().unwrap();
    let resumed = membership(&joining, &trusted, changed + 1, 5, epoch_deadline).await;
    assert!(resumed.height > changed);

    let removed_key = &keys.participants()[3];
    let removed = Address::from_slice(&keccak256(removed_key.encode())[12..]);
    let deactivated = submit(
        &joining,
        &signer,
        &trusted,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: removed,
            active: false,
        }
        .abi_encode(),
    )
    .await;
    let reduced = membership(&joining, &trusted, deactivated + 1, 4, epoch_deadline).await;
    let material = EpochMaterial::decode_bounded(
        &hex::decode(reduced.epoch_material.trim_start_matches("0x")).unwrap(),
    )
    .unwrap();
    assert!(!material.participants.iter().any(|key| key == removed_key));
    assert!(material.participants.iter().any(|key| key == &public));
    submit(
        &joining,
        &signer,
        &trusted,
        IValidatorRegistry::removeValidatorCall { evmAddr: removed }.abi_encode(),
    )
    .await;
    let current = membership(&origin, &trusted, reduced.height, 4, epoch_deadline).await;
    epoch_share::wait_for_epoch_share(
        &directory.join("secrets.json"),
        current.epoch,
        epoch_deadline,
    )
    .await;
    cluster.kill_node(2);
    let final_write = submit(
        &joining,
        &signer,
        &trusted,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: member,
            active: true,
        }
        .abi_encode(),
    )
    .await;
    assert!(final_write > reduced.height);
    if let Some(load) = load {
        load.finish(
            admitted,
            final_write,
            &[
                cluster.node(0).rpc_url(),
                cluster.node(1).rpc_url(),
                format!("http://127.0.0.1:{rpc_port}"),
            ],
        )
        .await;
    }
    incoming.kill().await.unwrap();
    incoming.wait().await.unwrap();
}
