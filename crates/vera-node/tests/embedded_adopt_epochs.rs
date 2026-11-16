//! The consensus share of a lone validator across epoch boundaries.

#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use short_epochs::{BLOCKS_PER_EPOCH, deployment, height, run_until, settings, store_in_files};
use support::{block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::EmbeddedNode;

const fn epoch(height: u64) -> u64 {
    height / BLOCKS_PER_EPOCH
}

#[test]
fn a_node_with_a_held_share_runs_and_restarts_across_epoch_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9_431;
    let settings = settings(directory.path(), &deployment(chain_id, 71), true);

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    run_until(&node, |height| epoch(height) >= 2);
    finalize_a_write(&node, &BlsSigner::new(50u64.into(), chain_id).unwrap());
    // Past the midpoint the epoch's dealing is finalized, and the restart loses its private half.
    let stopped_at = run_until(&node, |height| {
        height % BLOCKS_PER_EPOCH > BLOCKS_PER_EPOCH / 2 + 2
    });
    block_on(node.stop()).unwrap();

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    run_until(&node, |height| epoch(height) >= epoch(stopped_at) + 2);
    finalize_a_write(&node, &BlsSigner::new(51u64.into(), chain_id).unwrap());
    // Before the midpoint the dealing is still open, and the restart loses the dealer's seed.
    let stopped_at = run_until(&node, |height| {
        (2..BLOCKS_PER_EPOCH / 4).contains(&(height % BLOCKS_PER_EPOCH))
    });
    block_on(node.stop()).unwrap();

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    run_until(&node, |height| epoch(height) >= epoch(stopped_at) + 2);
    finalize_a_write(&node, &BlsSigner::new(52u64.into(), chain_id).unwrap());
    block_on(node.stop()).unwrap();
}

#[test]
fn the_share_exported_after_epoch_boundaries_is_the_genesis_share_and_opens_the_deployment() {
    let first = tempfile::tempdir().unwrap();
    let chain_id = 9_432;
    let dealt = deployment(chain_id, 72);
    store_in_files(first.path(), &dealt);
    let settings = settings(first.path(), &dealt, false);

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    run_until(&node, |height| epoch(height) >= 3);
    let exported = node.export().unwrap();
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(first.path().join("secrets.json")).unwrap()).unwrap();
    let consensus_key = *node.consensus_key();
    block_on(node.stop()).unwrap();

    let shares = stored["shares"].as_object().unwrap();
    assert!(
        shares
            .keys()
            .all(|epoch| epoch.parse::<u64>().unwrap() >= 2),
        "the store kept {:?}",
        shares.keys().collect::<Vec<_>>()
    );
    for share in shares.values() {
        assert_eq!(
            hex::decode(share.as_str().unwrap()).unwrap(),
            *dealt.keys().share(),
            "a reshare to a committee of one changed the share"
        );
    }
    assert_eq!(*exported.keys().share(), *dealt.keys().share());
    assert_eq!(exported.record(), dealt.record());

    let second = tempfile::tempdir().unwrap();
    let adopted = short_epochs::settings(second.path(), &exported, true);
    let node = block_on(EmbeddedNode::start(adopted)).unwrap();
    assert_eq!(*node.consensus_key(), consensus_key);
    assert!(
        epoch(height(&node)) == 0,
        "an adopted deployment starts from its genesis"
    );
    run_until(&node, |height| epoch(height) >= 2);
    finalize_a_write(&node, &BlsSigner::new(53u64.into(), chain_id).unwrap());
    block_on(node.stop()).unwrap();
}
