//! How soon a restarted embedded node serves its first write.

#![recursion_limit = "256"]

mod support;

use std::time::Instant;

use support::{block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::EmbeddedNode;

#[test]
fn the_first_write_after_a_start_does_not_wait_out_a_view() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9416;
    let settings = config(directory.path(), chain_id);
    // A write that waits for a view to be abandoned takes the whole leader
    // timeout, which a slow machine does not approach.
    let wasted_view = settings.leader_timeout * 3 / 4;

    for seed in [30u64, 31] {
        let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
        let started = Instant::now();
        finalize_a_write(&node, &BlsSigner::new(seed.into(), chain_id).unwrap());
        let elapsed = started.elapsed();
        assert!(elapsed < wasted_view, "first write took {elapsed:?}");
        block_on(node.stop()).unwrap();
    }
}
