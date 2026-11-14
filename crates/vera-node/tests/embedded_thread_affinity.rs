//! Every thread of an embedded node carries the CPU affinity its host set on the node thread.
//!
//! This is the only test in its binary: another test's threads would count as gained.

#![cfg(target_os = "linux")]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::{block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{EmbeddedNode, ThreadSetup};

type Cpus = BTreeSet<usize>;

fn threads() -> BTreeSet<u32> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect()
}

/// CPUs the kernel lets a thread run on. `None` once the thread has exited.
fn allowed(status_path: &str) -> Option<Cpus> {
    let status = std::fs::read_to_string(status_path).ok()?;
    let list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))?;
    let mut cpus = Cpus::new();
    for range in list.trim().split(',') {
        let (first, last) = range.split_once('-').unwrap_or((range, range));
        cpus.extend(first.parse::<usize>().unwrap()..=last.parse().unwrap());
    }
    Some(cpus)
}

fn name(thread: u32) -> String {
    std::fs::read_to_string(format!("/proc/self/task/{thread}/comm"))
        .map_or_else(|_| "exited".into(), |name| name.trim().to_owned())
}

fn restrict_calling_thread(cpus: &Cpus) -> std::io::Result<()> {
    const WORD_BITS: usize = usize::BITS as usize;
    let mut mask = [0usize; 1024 / WORD_BITS];
    for &cpu in cpus {
        *mask
            .get_mut(cpu / WORD_BITS)
            .ok_or_else(|| std::io::Error::other("processor index beyond the mask"))? |=
            1 << (cpu % WORD_BITS);
    }
    // SAFETY: the kernel reads `size_of_val(&mask)` bytes from a live array of that size.
    let status = unsafe { libc::sched_setaffinity(0, size_of_val(&mask), mask.as_ptr().cast()) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Records the affinity of every thread gained since `before`, keyed by thread id.
fn observe(before: &BTreeSet<u32>, gained: &mut BTreeMap<u32, (String, Cpus)>) {
    for thread in threads().difference(before) {
        if let Some(cpus) = allowed(&format!("/proc/self/task/{thread}/status")) {
            gained.insert(*thread, (name(*thread), cpus));
        }
    }
}

#[test]
fn every_node_thread_inherits_the_affinity_set_on_the_node_thread() {
    let host = allowed("/proc/thread-self/status").unwrap();
    // A strict subset of the host's CPUs wherever the machine has more than one.
    let take = host.len().saturating_sub(1).clamp(1, 2);
    let placement: Cpus = host.iter().copied().take(take).collect();

    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9411;
    let signer = BlsSigner::new(6u64.into(), chain_id).unwrap();
    let mut settings = config(directory.path(), chain_id);
    settings.thread_setup = Some(ThreadSetup::new({
        let placement = placement.clone();
        move || restrict_calling_thread(&placement)
    }));
    let budget = settings.thread_budget();

    let before = threads();
    let mut gained = BTreeMap::new();
    let node = block_on(EmbeddedNode::start(settings)).unwrap();
    observe(&before, &mut gained);
    finalize_a_write(&node, &signer);
    observe(&before, &mut gained);
    let status: vera_jsonrpc::NodeStatus =
        block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap();
    assert!(status.finalized_height.is_some());
    observe(&before, &mut gained);
    let running = threads().difference(&before).count();

    for (thread, (name, cpus)) in &gained {
        assert_eq!(
            cpus, &placement,
            "thread {thread} ({name}) escaped the placement; gained threads: {gained:?}"
        );
    }
    assert!(
        (budget.persistent()..=budget.max()).contains(&running),
        "{running} threads are outside the budget {budget:?}; gained threads: {gained:?}"
    );
    // The calling thread made every in-process call and keeps its own placement.
    assert_eq!(allowed("/proc/thread-self/status").unwrap(), host);

    block_on(node.stop()).unwrap();
}
