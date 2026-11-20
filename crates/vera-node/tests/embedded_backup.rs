//! A backup device following its account's active device.

#[path = "support/backup.rs"]
mod backup;
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use backup::await_height;
use serde_json::json;
use short_epochs::{BLOCKS_PER_EPOCH, deployment, height, run_until, store_in_files};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_config::PruningConfig;
use vera_jsonrpc::NodeStatus;
use vera_modules::acp::abi::IAcp;
use vera_node::{DeviceKey, EmbedError, EmbeddedNode, SoloError};

/// Revisions per section of the consensus archives.
const ARCHIVE_SECTION: u64 = 256;

const fn epoch(height: u64) -> u64 {
    height / BLOCKS_PER_EPOCH
}

#[test]
fn a_backup_catches_up_from_empty_follows_across_epochs_and_serves_proofs() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let chain_id = 9_441;
    let dealt = deployment(chain_id, 81);
    let key = DeviceKey::generate().unwrap();
    let active_settings = backup::active(first.path(), &dealt, &[&key]);
    let active = block_on(EmbeddedNode::start(active_settings.clone())).unwrap();
    let signer = BlsSigner::new(70u64.into(), chain_id).unwrap();
    let early = finalize_a_write(&active, &signer);
    run_until(&active, |height| epoch(height) >= 2);

    let follower = block_on(EmbeddedNode::start(backup::backup(
        second.path(),
        &dealt,
        &active_settings,
        &key,
    )))
    .unwrap();
    assert_eq!(follower.consensus_key(), active.consensus_key());
    assert_eq!(*follower.identity(), key.public_key());
    assert_eq!(*active.identity(), dealt.keys().public_key());
    assert!(matches!(
        follower.export(),
        Err(SoloError::Incomplete("a backup holds no key material"))
    ));
    assert!(
        epoch(height(&follower)) >= 2,
        "a backup starts from the active device's state"
    );
    await_certified_receipt(&follower, early);

    let late = finalize_a_write(&active, &signer);
    await_certified_receipt(&follower, late);
    let joined = epoch(height(&follower));
    let crossed = run_until(&active, |reached| epoch(reached) >= joined + 2);
    await_height(&follower, crossed);
    let last = finalize_a_write(&active, &signer);
    await_certified_receipt(&follower, last);

    let call = IAcp::createPolicyCall {
        policy: b"name: refused".to_vec().into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    };
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let refused = block_on(follower.rpc().request::<B256>(
        "vera_sendNativeTx",
        vec![json!(format!("0x{}", hex::encode(wire)))],
    ))
    .unwrap_err();
    assert!(refused.is_backup_refusal(), "{refused}");
    assert!(refused.is_retryable());

    block_on(follower.stop()).unwrap();
    block_on(active.stop()).unwrap();
    assert!(!second.path().join("validator.key").exists());
    assert!(!second.path().join("secrets.json").exists());
}

/// The identifier of the finalized block at `height`, once `node` serves its certificate.
fn block_id(node: &EmbeddedNode, height: u64) -> B256 {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let proof: Result<vera_domain::LightBlock, _> = block_on(
            node.rpc()
                .request("vera_getLightBlock", vec![json!(format!("0x{height:x}"))]),
        );
        match proof {
            Ok(proof) => {
                return vera_domain::verify_finalized_block(&proof, node.consensus_key())
                    .unwrap()
                    .id()
                    .0;
            }
            Err(error) => assert!(Instant::now() < deadline, "{error}"),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn status(node: &EmbeddedNode) -> NodeStatus {
    block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap()
}

#[test]
fn a_backup_waits_while_the_active_device_is_away_and_follows_it_again() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let chain_id = 9_442;
    let dealt = deployment(chain_id, 82);
    let key = DeviceKey::generate().unwrap();
    let active_settings = backup::active(first.path(), &dealt, &[&key]);
    let active = block_on(EmbeddedNode::start(active_settings.clone())).unwrap();
    let signer = BlsSigner::new(71u64.into(), chain_id).unwrap();
    let mut settings = backup::backup(second.path(), &dealt, &active_settings, &key);
    // The watchdog samples every 30 seconds, so it would trip inside the
    // absence below if it counted it. A loaded machine can keep a catching-up
    // backup on one block for a whole sample interval, so the budget spans two.
    settings.watchdog_stall = Duration::from_secs(60);
    let follower = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    let written = finalize_a_write(&active, &signer);
    await_certified_receipt(&follower, written);

    let stopping_at = height(&active);
    block_on(active.stop()).unwrap();
    // A stop finalizes the views in flight, and the backup receives those
    // blocks. A loaded machine can leave it applying them for a while.
    await_height(&follower, stopping_at);
    std::thread::sleep(Duration::from_secs(95));
    let waiting = status(&follower);
    let left_at = waiting.finalized_height.unwrap();
    assert_eq!(waiting.proposed_count, 0, "a backup proposed a block");
    assert_eq!(waiting.peer_count, Some(0));

    block_on(follower.stop()).unwrap();
    let follower = block_on(EmbeddedNode::start(settings)).unwrap();
    assert!(
        height(&follower) >= left_at,
        "a restarted backup lost blocks"
    );
    await_certified_receipt(&follower, written);

    // The active device finalizes again the blocks it had not stored when
    // it stopped, and every block the backup holds is one it built.
    let active = block_on(EmbeddedNode::start(active_settings)).unwrap();
    await_height(&active, left_at);
    assert_eq!(block_id(&active, left_at), block_id(&follower, left_at));
    let resumed = finalize_a_write(&active, &signer);
    await_certified_receipt(&follower, resumed);
    await_height(&follower, height(&active));
    block_on(follower.stop()).unwrap();
    block_on(active.stop()).unwrap();
}

#[test]
fn a_backup_restarted_behind_the_active_devices_retention_recovers_by_snapshot() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let chain_id = 9_443;
    let dealt = deployment(chain_id, 83);
    let key = DeviceKey::generate().unwrap();
    // Two epochs, pruned at every revision.
    let retention = PruningConfig {
        maintenance_interval: 1.try_into().unwrap(),
        retained_consensus_revisions: 2 * BLOCKS_PER_EPOCH as usize,
        retained_state_revisions: 0,
    };
    let mut active_settings = backup::active(first.path(), &dealt, &[&key]);
    active_settings.pruning = Some(retention.clone());
    let active = block_on(EmbeddedNode::start(active_settings.clone())).unwrap();
    let signer = BlsSigner::new(72u64.into(), chain_id).unwrap();
    let mut settings = backup::backup(second.path(), &dealt, &active_settings, &key);
    settings.pruning = Some(retention);
    let follower = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    let early = finalize_a_write(&active, &signer);
    await_certified_receipt(&follower, early);
    let left_at = height(&follower);
    block_on(follower.stop()).unwrap();

    let missed = finalize_a_write(&active, &signer);
    // A backup's first catch-up can end many epochs on when the active device
    // never pauses, so the section holding its next block is found, not assumed.
    let next_section = first.path().join(format!(
        "commonware/vera-blocks-value/{:016x}",
        (left_at + 1) / ARCHIVE_SECTION * ARCHIVE_SECTION
    ));
    assert!(next_section.exists(), "the backup left at {left_at}");
    let deadline = Instant::now() + Duration::from_secs(300);
    while next_section.exists() {
        assert!(Instant::now() < deadline, "pruning horizon deadline");
        std::thread::sleep(Duration::from_millis(500));
    }

    let follower = block_on(EmbeddedNode::start(settings)).unwrap();
    assert!(
        height(&follower) > left_at + 2 * BLOCKS_PER_EPOCH,
        "the backup restarted where it left"
    );
    await_height(&follower, height(&active));
    let late = finalize_a_write(&active, &signer);
    for written in [late, missed, early] {
        await_certified_receipt(&follower, written);
    }
    block_on(follower.stop()).unwrap();
    block_on(active.stop()).unwrap();
}

#[test]
fn two_backups_follow_one_active_device() {
    let directories: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let chain_id = 9_444;
    let dealt = deployment(chain_id, 84);
    let keys = [
        DeviceKey::generate().unwrap(),
        DeviceKey::load_or_create(directories[2].path()).unwrap(),
    ];
    // This active device keeps its keys in files, as one started without a keystore does.
    store_in_files(directories[0].path(), &dealt);
    let mut active_settings = backup::active(directories[0].path(), &dealt, &[&keys[0], &keys[1]]);
    active_settings.deployment = None;
    let active = block_on(EmbeddedNode::start(active_settings.clone())).unwrap();
    let signer = BlsSigner::new(73u64.into(), chain_id).unwrap();
    let before = finalize_a_write(&active, &signer);

    let mut held = backup::backup(directories[1].path(), &dealt, &active_settings, &keys[0]);
    held.backups = vec![keys[1].public_key()];
    let mut filed = backup::backup(directories[2].path(), &dealt, &active_settings, &keys[1]);
    let vera_node::DeviceRole::Backup(role) = &mut filed.role else {
        unreachable!("a backup configuration has the backup role");
    };
    role.transport_key = None;
    filed.backups = vec![keys[0].public_key()];
    let followers = [held, filed].map(|settings| block_on(EmbeddedNode::start(settings)).unwrap());
    assert_eq!(*followers[1].identity(), keys[1].public_key());
    assert!(!directories[1].path().join("transport.key").exists());

    let after = finalize_a_write(&active, &signer);
    let reached = run_until(&active, |reached| epoch(reached) >= 3);
    for follower in &followers {
        await_height(follower, reached);
        await_certified_receipt(follower, before);
        await_certified_receipt(follower, after);
    }
    for follower in followers {
        block_on(follower.stop()).unwrap();
    }
    block_on(active.stop()).unwrap();
}

#[test]
fn a_device_that_is_not_listed_is_not_admitted() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let dealt = deployment(9_445, 85);
    let listed = DeviceKey::generate().unwrap();
    let active_settings = backup::active(first.path(), &dealt, &[&listed]);
    let active = block_on(EmbeddedNode::start(active_settings.clone())).unwrap();
    let stranger = DeviceKey::generate().unwrap();
    let mut settings = backup::backup(second.path(), &dealt, &active_settings, &stranger);
    settings.catch_up_timeout = Duration::from_secs(5);

    let refused = block_on(EmbeddedNode::start(settings)).unwrap_err();

    assert!(
        matches!(&refused, EmbedError::Stopped(reason) if reason.contains("epoch probe")),
        "{refused}"
    );
    assert!(height(&active) > 0);
    block_on(active.stop()).unwrap();
}

#[test]
fn a_backup_is_configured_without_key_material() {
    let directory = tempfile::tempdir().unwrap();
    let dealt = deployment(9_446, 86);
    let key = DeviceKey::generate().unwrap();
    let active_settings = backup::active(directory.path(), &dealt, &[]);
    let mut settings = backup::backup(directory.path(), &dealt, &active_settings, &key);
    settings.deployment = Some(dealt);

    assert!(matches!(
        block_on(EmbeddedNode::start(settings)),
        Err(EmbedError::Config("a backup takes no key material"))
    ));
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
}
