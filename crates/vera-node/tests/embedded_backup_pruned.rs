//! A backup catching up from an active device whose history is pruned.

#[path = "support/backup.rs"]
mod backup;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

use serde_json::json;
use short_epochs::{BLOCKS_PER_EPOCH, deployment, height};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_domain::ReceiptResponse;
use vera_jsonrpc::LocalRpcError;
use vera_node::{DeviceKey, EmbeddedNode, minimum_history_retention};

/// Whether `node` refuses the light block at `height` as pruned history.
fn refuses_as_pruned(node: &EmbeddedNode, height: u64) -> bool {
    let refused =
        block_on(node.rpc().request::<serde_json::Value>(
            "vera_getLightBlock",
            vec![json!(format!("{height:#x}"))],
        ));
    matches!(refused, Err(LocalRpcError::Call { code: 4444, .. }))
}

fn receipt(node: &EmbeddedNode, submission: alloy_primitives::B256) -> Option<ReceiptResponse> {
    block_on(
        node.rpc()
            .request("vera_getReceiptProof", vec![json!(submission)]),
    )
    .unwrap()
}

#[test]
fn a_backup_catches_up_from_a_pruned_active_device_and_keeps_its_window() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let chain_id = 9_451;
    let dealt = deployment(chain_id, 91);
    let key = DeviceKey::generate().unwrap();
    let retained = minimum_history_retention(NonZeroU64::new(BLOCKS_PER_EPOCH).unwrap());
    let mut active_settings = backup::active(first.path(), &dealt, &[&key]);
    active_settings.history_retention = Some(retained);
    let active = block_on(EmbeddedNode::start(active_settings.clone())).unwrap();
    let signer = BlsSigner::new(90u64.into(), chain_id).unwrap();
    let early = finalize_a_write(&active, &signer);
    let written_at = height(&active);
    let deadline = Instant::now() + Duration::from_secs(1_200);
    while !refuses_as_pruned(&active, written_at) {
        assert!(Instant::now() < deadline, "history retention deadline");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(receipt(&active, early).is_none());
    let late = finalize_a_write(&active, &signer);

    let mut settings = backup::backup(second.path(), &dealt, &active_settings, &key);
    settings.history_retention = Some(retained);
    settings.catch_up_timeout = Duration::from_secs(600);
    let follower = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    backup::await_height(&follower, height(&active));
    await_certified_receipt(&follower, late);
    assert!(receipt(&follower, early).is_none());
    assert!(refuses_as_pruned(&follower, written_at));
    block_on(follower.stop()).unwrap();

    // The adopted window survives a restart and keeps following.
    let follower = block_on(EmbeddedNode::start(settings)).unwrap();
    await_certified_receipt(&follower, late);
    let last = finalize_a_write(&active, &signer);
    await_certified_receipt(&follower, last);
    block_on(follower.stop()).unwrap();
    block_on(active.stop()).unwrap();
}
