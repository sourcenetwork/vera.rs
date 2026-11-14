//! The host's thread setup and the thread counts an embedded node reports.

mod support;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use support::{block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{EmbedError, EmbeddedConfig, EmbeddedNode, ThreadBudget, ThreadSetup};

#[derive(Debug, PartialEq, Eq)]
struct Observed {
    thread: std::thread::ThreadId,
    name: Option<String>,
    inside_a_runtime: bool,
}

#[test]
fn thread_setup_runs_once_per_start_on_the_node_thread_before_its_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9408;
    let runs = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut settings = config(directory.path(), chain_id);
    settings.thread_setup = Some(ThreadSetup::new({
        let (runs, observed) = (Arc::clone(&runs), Arc::clone(&observed));
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
            let current = std::thread::current();
            observed.lock().unwrap().push(Observed {
                thread: current.id(),
                name: current.name().map(str::to_owned),
                inside_a_runtime: tokio::runtime::Handle::try_current().is_ok(),
            });
            Ok(())
        }
    }));

    let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
    // `start` returns once the node serves requests, so the setup preceded readiness.
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    finalize_a_write(&node, &BlsSigner::new(5u64.into(), chain_id).unwrap());
    let status: vera_jsonrpc::NodeStatus =
        block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap();
    assert!(status.finalized_height.is_some());
    block_on(node.stop()).unwrap();
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    block_on(node.stop()).unwrap();
    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 2);
    assert_ne!(observed[0].thread, observed[1].thread);
    for run in observed.iter() {
        assert_ne!(run.thread, std::thread::current().id());
        assert_eq!(run.name.as_deref(), Some("vera-node"));
        assert!(!run.inside_a_runtime);
    }
}

#[test]
fn failed_thread_setup_fails_the_start() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path(), 9409);
    settings.thread_setup = Some(ThreadSetup::new(|| {
        Err(std::io::Error::other("no such processor"))
    }));
    match block_on(EmbeddedNode::start(settings)) {
        Err(EmbedError::ThreadSetup(error)) => {
            assert_eq!(error.to_string(), "no such processor");
        }
        other => panic!("unexpected start result: {other:?}"),
    }
}

#[test]
fn thread_budget_reports_the_configured_counts() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path(), 9410);
    let budget = settings.thread_budget();
    assert_eq!(
        budget,
        ThreadBudget {
            node: 1,
            workers: 1,
            max_blocking: 16,
            verification: 2,
            history: 1,
        }
    );
    assert_eq!(budget.persistent(), 5);
    assert_eq!(budget.max(), 21);

    let defaults = EmbeddedConfig::new(
        settings.data_dir.clone(),
        settings.genesis.clone(),
        settings.p2p_listen,
    )
    .thread_budget();
    let runtime = commonware_runtime::tokio::Config::default();
    assert_eq!(defaults.workers, runtime.worker_threads());
    assert_eq!(defaults.max_blocking, runtime.max_blocking_threads());
    assert!((1..=4).contains(&defaults.verification));

    settings.verification_threads = 0;
    assert!(matches!(
        block_on(EmbeddedNode::start(settings)),
        Err(EmbedError::Config(_))
    ));
}
