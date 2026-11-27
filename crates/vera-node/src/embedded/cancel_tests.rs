//! A switch whose future is dropped midway leaves every node thread joinable.

use std::{path::Path, pin::pin, task::Poll, time::Duration};

use vera_modules::vera::administration::OperatorPolicy;

use super::*;
use crate::SoloGenesis;

const DEADLINE: Duration = Duration::from_secs(60);

fn solo(directory: &Path) -> EmbeddedConfig {
    let genesis = SoloGenesis {
        chain_id: 9_273,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec!["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into()],
        },
        timestamp: 1_800_000_000,
        policies: Vec::new(),
    };
    EmbeddedConfig::new(directory, genesis, "127.0.0.1:0".parse().unwrap())
}

async fn start(config: EmbeddedConfig) -> EmbeddedNode {
    tokio::time::timeout(DEADLINE, EmbeddedNode::start(config))
        .await
        .expect("start deadline")
        .unwrap()
}

/// Drop `future` once it has been pending `polls` times.
async fn dropped_after<F: Future>(future: F, polls: usize) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut left = polls;
    std::future::poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Ready(output) => Poll::Ready(Some(output)),
        Poll::Pending if left <= 1 => Poll::Ready(None),
        Poll::Pending => {
            left -= 1;
            Poll::Pending
        }
    })
    .await
}

/// The first poll of a restart waits for the old node, the second for the new one.
async fn stop_after_a_dropped_restart(polls: usize) {
    let directory = tempfile::tempdir().unwrap();
    let config = solo(directory.path());
    let mut node = start(config.clone()).await;
    let old = node.node.thread.id();

    let dropped =
        tokio::time::timeout(DEADLINE, dropped_after(node.restart(config.clone()), polls))
            .await
            .expect("restart deadline");
    assert!(
        dropped.is_none(),
        "the restart completed before it was dropped"
    );

    // The node owns the old thread while it stops and the new one once it is spawned.
    assert!(node.node.thread.id().is_some());
    assert_eq!(node.node.thread.id() == old, polls == 1);
    assert!(matches!(
        node.hand_over(node.identity()).await,
        Err(EmbedError::Interrupted)
    ));
    assert!(matches!(node.failed().await, EmbedError::Interrupted));

    tokio::time::timeout(DEADLINE, node.stop())
        .await
        .expect("stop deadline")
        .unwrap();
    drop(directory::claim(directory.path()).expect("a stopped node's directory is free"));
    start(config).await.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_dropped_while_the_old_node_stops_is_joined_by_stop() {
    stop_after_a_dropped_restart(1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_dropped_before_the_new_node_is_ready_is_joined_by_stop() {
    stop_after_a_dropped_restart(2).await;
}
