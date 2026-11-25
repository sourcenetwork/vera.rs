//! Embedded nodes killed at the steps they persist, and the starts that
//! follow: first start, adoption, proposal, finalization and a backup's
//! catch-up. See `support/crash.rs` for how a test kills a child process.

#[expect(
    dead_code,
    reason = "shared with tests that run an active device beside its backup"
)]
#[path = "support/backup.rs"]
mod backup;
#[expect(
    dead_code,
    reason = "its switching helpers serve the tests of a switch"
)]
#[path = "support/crash.rs"]
mod crash;
#[expect(dead_code, reason = "shared with tests that switch devices")]
#[path = "support/devices.rs"]
mod devices;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::process::Command;

use alloy_primitives::B256;
use crash::{SPEC, Spec, arm, child, finalized_once, nonce, submit, survived};
use short_epochs::{height, run_until};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_node::{EmbeddedConfig, EmbeddedNode};

#[test]
fn a_first_start_killed_before_its_genesis_is_published_starts_again() {
    const TEST: &str = "a_first_start_killed_before_its_genesis_is_published_starts_again";
    if let Some(spec) = child() {
        arm();
        let _ = block_on(EmbeddedNode::start(spec.in_files()));
        survived();
    }
    for (seed, point) in [(1, "solo-dealt"), (2, "native-genesis")] {
        let scratch = tempfile::tempdir().unwrap();
        let spec = Spec::new(scratch.path(), 1, 9_531, seed);
        spec.crash(TEST, &spec.directories[0], point);
        let signer = spec.signer(90 + seed);
        let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
        let written = finalize_a_write(&node, &signer);
        block_on(node.stop()).unwrap();
        let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
        await_certified_receipt(&node, written);
        assert_eq!(nonce(&node, &signer), 1);
        block_on(node.stop()).unwrap();
    }
}

#[test]
fn an_adoption_killed_before_its_record_is_published_starts_again() {
    const TEST: &str = "an_adoption_killed_before_its_record_is_published_starts_again";
    if let Some(spec) = child() {
        arm();
        let _ = block_on(EmbeddedNode::start(spec.adopted()));
        survived();
    }
    let scratch = tempfile::tempdir().unwrap();
    let spec = Spec::new(scratch.path(), 1, 9_532, 3);
    let directory = &spec.directories[0];
    spec.crash(TEST, directory, "solo-record");
    assert!(directory.join("solo-genesis.pending").is_file());
    let node = block_on(EmbeddedNode::start(spec.adopted())).unwrap();
    finalize_a_write(&node, &spec.signer(93));
    block_on(node.stop()).unwrap();
    assert!(!directory.join("validator.key").exists());
    assert!(!directory.join("secrets.json").exists());
}

/// Start the first device, submit a request and wait to be killed.
fn submit_and_wait(spec: &Spec) -> ! {
    let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
    // Startup applies blocks without requests, which no crash point stops at.
    run_until(&node, |reached| reached >= 2);
    arm();
    let submission = submit(&node, spec, &spec.signer(94), "submitted");
    await_certified_receipt(&node, submission);
    survived();
}

#[test]
fn a_node_killed_while_it_commits_a_finalized_block_keeps_the_request_once() {
    const TEST: &str = "a_node_killed_while_it_commits_a_finalized_block_keeps_the_request_once";
    if let Some(spec) = child() {
        submit_and_wait(&spec);
    }
    let scratch = tempfile::tempdir().unwrap();
    let spec = Spec::new(scratch.path(), 1, 9_533, 4);
    let directory = &spec.directories[0];
    spec.crash_module(TEST, directory);
    let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
    finalized_once(&node, &spec.seen("submitted"), &spec.signer(94));
    block_on(node.stop()).unwrap();
}

#[test]
fn a_node_killed_once_it_proposed_finalizes_the_request_once_or_takes_it_again() {
    const TEST: &str =
        "a_node_killed_once_it_proposed_finalizes_the_request_once_or_takes_it_again";
    if let Some(spec) = child() {
        let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
        run_until(&node, |reached| reached >= 2);
        let submission = submit(&node, &spec, &spec.signer(94), "submitted");
        // The next block this node proposes may or may not carry the request:
        // a lone validator can propose it before the point is armed, so the
        // child waits for a block proposed after arming.
        arm();
        await_certified_receipt(&node, submission);
        let armed_at = height(&node);
        run_until(&node, |reached| reached > armed_at);
        survived();
    }
    let scratch = tempfile::tempdir().unwrap();
    let spec = Spec::new(scratch.path(), 1, 9_539, 12);
    spec.crash(TEST, &spec.directories[0], "proposed");
    let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
    let seen = spec.seen("submitted");
    let signer = spec.signer(94);
    // A request that was only proposed is lost with the pool, and taken again unchanged.
    if nonce(&node, &signer) == 0 {
        let again: B256 = block_on(node.rpc().request(
            "vera_sendNativeTx",
            vec![serde_json::json!(seen.request.as_ref().unwrap())],
        ))
        .unwrap();
        assert_eq!(Some(again), seen.submission);
    }
    finalized_once(&node, &seen, &signer);
    block_on(node.stop()).unwrap();
}

#[test]
fn a_node_killed_between_its_history_and_its_index_keeps_the_request_once() {
    const TEST: &str = "a_node_killed_between_its_history_and_its_index_keeps_the_request_once";
    if let Some(spec) = child() {
        submit_and_wait(&spec);
    }
    let scratch = tempfile::tempdir().unwrap();
    let spec = Spec::new(scratch.path(), 1, 9_534, 5);
    spec.crash(TEST, &spec.directories[0], "history-before-index");
    let node = block_on(EmbeddedNode::start(spec.in_files())).unwrap();
    finalized_once(&node, &spec.seen("submitted"), &spec.signer(94));
    block_on(node.stop()).unwrap();
}

#[test]
fn a_backup_killed_while_it_imports_history_catches_up_on_the_next_start() {
    const TEST: &str = "a_backup_killed_while_it_imports_history_catches_up_on_the_next_start";
    let backup_of = |spec: &Spec, active: &EmbeddedConfig| {
        let mut config = backup::backup(
            &spec.directories[1],
            &spec.deployment(),
            active,
            &spec.device_key(1),
        );
        config.p2p_listen = spec.listens[1];
        config
    };
    if let Some(spec) = child() {
        let directory = &spec.directories[1];
        std::fs::write(directory.join("snapshot-import-crash"), []).unwrap();
        let _ = block_on(EmbeddedNode::start(backup_of(&spec, &spec.adopted())));
        survived();
    }
    let scratch = tempfile::tempdir().unwrap();
    let spec = Spec::new(scratch.path(), 2, 9_535, 6);
    let mut active = spec.adopted();
    active.backups = vec![spec.device_key(1).public_key()];
    let node = block_on(EmbeddedNode::start(active.clone())).unwrap();
    let signer = spec.signer(95);
    let written: Vec<B256> = (0..3).map(|_| finalize_a_write(&node, &signer)).collect();

    let path = spec.witness.with_extension("spec");
    std::fs::write(&path, serde_json::to_vec(&spec).unwrap()).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(SPEC, &path)
        .status()
        .unwrap();
    assert!(!status.success());
    assert_ne!(status.code(), Some(3), "the backup was not killed");
    assert!(!spec.directories[1].join("snapshot-import-crash").exists());

    let follower = block_on(EmbeddedNode::start(backup_of(&spec, &active))).unwrap();
    for submission in &written {
        await_certified_receipt(&follower, *submission);
    }
    assert_eq!(nonce(&follower, &signer), 3);
    let reached = height(&node);
    run_until(&follower, |now| now >= reached);
    block_on(follower.stop()).unwrap();
    block_on(node.stop()).unwrap();
}
