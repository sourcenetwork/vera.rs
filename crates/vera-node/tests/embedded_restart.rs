//! How soon a restarted embedded node serves its first write.

mod support;

use std::time::{Duration, Instant};

use support::{block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::EmbeddedNode;

#[test]
fn the_first_write_after_a_start_does_not_wait_out_a_view() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9416;
    let mut settings = config(directory.path(), chain_id);
    // As long as the genesis stall timeout allows, to tell a write that waits
    // for a view to be abandoned from a slow machine.
    settings.leader_timeout = Duration::from_millis(4_000);
    settings.certification_timeout = Duration::from_millis(4_500);
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
