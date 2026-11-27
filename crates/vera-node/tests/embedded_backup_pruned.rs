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

/// Asserts what `node` answers about `submission`, sent when its head was
/// `after`, once its revision is pruned: nothing, as for a submission it
/// never saw, and the pruned error to a caller that names `after`.
#[track_caller]
fn assert_receipt_pruned(node: &EmbeddedNode, submission: alloy_primitives::B256, after: u64) {
    let after = json!(format!("{after:#x}"));
    for method in ["vera_getReceiptProof", "vera_getTransactionReceipt"] {
        let unhinted = block_on(
            node.rpc()
                .request::<serde_json::Value>(method, vec![json!(submission)]),
        );
        assert!(
            matches!(&unhinted, Ok(serde_json::Value::Null)),
            "{unhinted:?}"
        );
        let hinted = block_on(
            node.rpc()
                .request::<serde_json::Value>(method, vec![json!(submission), after.clone()]),
        );
        assert!(
            matches!(&hinted, Err(LocalRpcError::Call { code: 4444, .. })),
            "{hinted:?}"
        );
    }
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
    let sent_at = height(&active);
    let early = finalize_a_write(&active, &signer);
    let written_at = height(&active);
    let deadline = Instant::now() + Duration::from_secs(1_200);
    while !refuses_as_pruned(&active, written_at) {
        assert!(Instant::now() < deadline, "history retention deadline");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_receipt_pruned(&active, early, sent_at);
    let late = finalize_a_write(&active, &signer);

    let mut settings = backup::backup(second.path(), &dealt, &active_settings, &key);
    settings.history_retention = Some(retained);
    settings.catch_up_timeout = Duration::from_secs(600);
    let follower = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    backup::await_height(&follower, height(&active));
    await_certified_receipt(&follower, late);
    assert_receipt_pruned(&follower, early, sent_at);
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
