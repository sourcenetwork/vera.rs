//! Memory budgets and the consensus listener of an embedded single-validator node.

mod support;

use support::{await_certified_receipt, block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{EmbedError, EmbeddedNode, HistoryMemory};

#[test]
fn history_within_tiny_budgets_recovers_after_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9412;
    let mut settings = config(directory.path(), chain_id);
    // Small enough that these writes rotate and flush the write buffer.
    settings.history_memory = HistoryMemory {
        block_cache_bytes: 0,
        write_buffer_bytes: 4096,
    };

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    let submissions: Vec<_> = (10u64..16)
        .map(|seed| finalize_a_write(&node, &BlsSigner::new(seed.into(), chain_id).unwrap()))
        .collect();
    let tables = directory.path().join("history/regolith/sst");
    assert!(
        std::fs::read_dir(tables).unwrap().next().is_some(),
        "the writes must have flushed at least one table"
    );
    block_on(node.stop()).unwrap();

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    for submission in submissions {
        await_certified_receipt(&node, submission);
    }
    finalize_a_write(&node, &BlsSigner::new(16u64.into(), chain_id).unwrap());
    block_on(node.stop()).unwrap();
}

#[test]
fn an_unusable_history_budget_is_rejected_before_the_deployment_exists() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path(), 9413);
    settings.history_memory.write_buffer_bytes = 0;
    assert!(matches!(
        block_on(EmbeddedNode::start(settings)),
        Err(EmbedError::Config("history write buffer must be nonzero"))
    ));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn default_history_budgets_are_the_embedded_ones() {
    let directory = tempfile::tempdir().unwrap();
    let settings = config(directory.path(), 9414);
    assert_eq!(settings.history_memory, HistoryMemory::EMBEDDED);
    assert_eq!(
        HistoryMemory::EMBEDDED,
        HistoryMemory {
            block_cache_bytes: 8 << 20,
            write_buffer_bytes: 4 << 20,
        }
    );
}

#[test]
fn a_loopback_listener_on_a_port_the_system_chooses_serves_and_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9415;
    let mut settings = config(directory.path(), chain_id);
    settings.p2p_listen = "127.0.0.1:0".parse().unwrap();

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    let submission = finalize_a_write(&node, &BlsSigner::new(20u64.into(), chain_id).unwrap());
    block_on(node.stop()).unwrap();

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    await_certified_receipt(&node, submission);
    block_on(node.stop()).unwrap();
}
