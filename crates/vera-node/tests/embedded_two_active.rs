//! Two devices that both run a deployment as its validator.

#[expect(dead_code, reason = "shared with tests that hand over")]
#[path = "support/devices.rs"]
mod devices;
#[path = "support/proxy.rs"]
mod proxy;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use devices::{Paired, block, certify, pair, reach_at, takeover_change};
use proxy::Relay;
use short_epochs::{height, run_until};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_domain::{LightBlock, verify_finalized_block};
use vera_node::{Contest, EmbeddedNode, TermRefusal};

const SHORT: Duration = Duration::from_secs(2);
/// Longer than any gap in the blocks of a device that proposes at the
/// daemon's cadence, so only a check made while proposing finds the other device.
const AWAKE: Duration = Duration::from_secs(10);

fn light_block(node: &EmbeddedNode, height: u64) -> LightBlock {
    block_on(node.rpc().request(
        "vera_getLightBlock",
        vec![serde_json::json!(format!("0x{height:x}"))],
    ))
    .unwrap()
}

fn proposed(node: &EmbeddedNode) -> u64 {
    let status: vera_jsonrpc::NodeStatus =
        block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap();
    status.proposed_count
}

fn receipt(node: &EmbeddedNode, submission: B256) -> bool {
    let proof: Option<vera_domain::ReceiptResponse> = block_on(
        node.rpc()
            .request("vera_getReceiptProof", vec![serde_json::json!(submission)]),
    )
    .unwrap();
    proof.is_some()
}

/// The device's contest, if one is reported already.
fn contest(node: &EmbeddedNode) -> Option<Contest> {
    let mut future = std::pin::pin!(node.contested());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(contest) => Some(contest),
        std::task::Poll::Pending => None,
    }
}

/// Whether `node` finalizes nothing more for `quiet`.
fn stays_at(node: &EmbeddedNode, quiet: Duration) -> bool {
    let reached = height(node);
    std::thread::sleep(quiet);
    height(node) == reached
}

/// A loopback address no node listens on yet.
fn fresh_listen() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// `backup` on an address of its own for a first run. The active device
/// learns the address a backup announces and dials it again; a backup that
/// later listens elsewhere is reached only through its relay.
fn on_first_address(backup: &vera_node::EmbeddedConfig) -> vera_node::EmbeddedConfig {
    let mut first = backup.clone();
    first.p2p_listen = fresh_listen();
    first
}

/// Relay each device's view of the other through a relay of its own.
fn relayed(devices: &mut [Paired; 2]) -> [Relay; 2] {
    let relays = [
        Relay::new(devices[0].active.p2p_listen),
        Relay::new(devices[1].active.p2p_listen),
    ];
    let keys = [devices[0].key.clone(), devices[1].key.clone()];
    reach_at(&mut devices[0], &keys[1], relays[1].address());
    reach_at(&mut devices[1], &keys[0], relays[0].address());
    relays
}

#[test]
fn devices_that_adopt_one_export_without_switching_fork_unnoticed() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_521;
    let dealt = short_epochs::deployment(chain_id, 121);
    let configs = directories
        .each_ref()
        .map(|directory| short_epochs::settings(directory.path(), &dealt, true));
    let nodes = configs.map(|config| block_on(EmbeddedNode::start(config)).unwrap());
    // Idle devices can build identical blocks; a write only one of them holds
    // makes their blocks at its height differ.
    let signer = BlsSigner::new(79u64.into(), chain_id).unwrap();
    let written = finalize_a_write(&nodes[0], &signer);
    let proof: vera_domain::ReceiptResponse = block_on(
        nodes[0]
            .rpc()
            .request("vera_getReceiptProof", vec![serde_json::json!(written)]),
    )
    .unwrap();
    let first = verify_finalized_block(&proof.revision, nodes[0].consensus_key()).unwrap();
    run_until(&nodes[1], |reached| reached >= first.height);
    let second = verify_finalized_block(
        &light_block(&nodes[1], first.height),
        nodes[0].consensus_key(),
    )
    .unwrap();
    assert_ne!(
        first.id(),
        second.id(),
        "two certified blocks at one height"
    );
    assert!(!receipt(&nodes[1], written));
    // Neither device notices: both go on.
    for node in &nodes {
        let reached = height(node);
        run_until(node, |now| now > reached + 2);
        assert_eq!(contest(node), None);
        assert_eq!(node.term(), 0);
    }
    for node in nodes {
        block_on(node.stop()).unwrap();
    }
}

#[test]
fn devices_started_together_as_active_leave_one_proposing() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let dealt = short_epochs::deployment(9_522, 122);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        SHORT,
    );
    let nodes = std::thread::scope(|scope| {
        let started = [first.active.clone(), second.active.clone()]
            .map(|config| scope.spawn(move || block_on(EmbeddedNode::start(config)).unwrap()));
        started.map(|thread| thread.join().unwrap())
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while nodes.iter().all(|node| height(node) == 0) {
        assert!(Instant::now() < deadline, "neither device proposes");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(8));
    let heights = nodes.each_ref().map(height);
    assert!(
        heights.contains(&0),
        "both devices finalized blocks: {heights:?}"
    );
    let (going, held) = if heights[0] > 0 { (0, 1) } else { (1, 0) };
    assert_eq!(proposed(&nodes[held]), 0);
    let contested = contest(&nodes[held]).expect("the held device reports a contest");
    assert_eq!(
        contested.device,
        [&first, &second][going].key.public_key(),
        "the device that goes on answered"
    );
    run_until(&nodes[going], |reached| reached > heights[going]);
    assert_eq!(height(&nodes[held]), 0);
    for node in nodes {
        block_on(node.stop()).unwrap();
    }
}

#[test]
fn active_devices_cut_off_from_each_other_contest_once_reconnected() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_523;
    let dealt = short_epochs::deployment(chain_id, 123);
    let mut devices = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        AWAKE,
    );
    let relays = relayed(&mut devices);
    let [first, second] = &devices;
    let signers = [80u64, 81].map(|seed| BlsSigner::new(seed.into(), chain_id).unwrap());

    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let written_on_laptop = finalize_a_write(&laptop, &signers[0]);
    for relay in &relays {
        relay.close();
    }
    // The phone opens the deployment while it cannot reach the laptop.
    let phone = block_on(EmbeddedNode::start(second.active.clone())).unwrap();
    let written_on_phone = finalize_a_write(&phone, &signers[1]);
    let mut nodes = [laptop, phone];
    let written = [written_on_laptop, written_on_phone];

    // Both forks verify against the deployment's consensus key. A client
    // tells them apart only by comparing blocks it already accepted.
    let forked = nodes
        .each_ref()
        .map(|node| verify_finalized_block(&light_block(node, 1), node.consensus_key()).unwrap());
    assert_ne!(forked[0].id(), forked[1].id());
    for (node, submission) in nodes.iter().zip(written) {
        await_certified_receipt(node, submission);
    }

    for relay in &relays {
        relay.open();
    }
    // A device stops when the other answers its question. Which one asks
    // first is a matter of timing, so either may be the one that goes on; the
    // lower key decides only when both hold back at once.
    let deadline = Instant::now() + Duration::from_secs(120);
    let held = loop {
        assert!(
            Instant::now() < deadline,
            "the devices never noticed each other, or never settled"
        );
        let contested = nodes.each_ref().map(contest);
        if let [Some(_), None] | [None, Some(_)] = &contested {
            let held = usize::from(contested[1].is_some());
            let before = nodes.each_ref().map(height);
            std::thread::sleep(Duration::from_secs(4));
            let after = nodes.each_ref().map(height);
            if after[held] == before[held] && after[1 - held] > before[1 - held] + 2 {
                break held;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let going = 1 - held;

    // The host keeps the device that goes on. It renews that device's term,
    // and the other device follows it and reports what it finalized alone.
    let keys = [&devices[0], &devices[1]].map(|device| device.key.public_key());
    let change = block_on(nodes[going].hand_over(&keys[going])).unwrap();
    assert_eq!((change.term, change.cut.height), (1, height(&nodes[going])));
    let certificate = certify(change);
    // Before it is told, a client holding the held device's block cannot
    // judge it from the certificate: the block is below the cut.
    let lost_block = forked[held].id().0;
    assert!(certificate.keeps(1, &lost_block));
    block_on(nodes[going].take_over(dealt.keys().clone(), certificate.clone())).unwrap();
    assert_eq!(nodes[going].term(), 1);
    let discarded = block_on(nodes[held].follow(certificate)).unwrap();
    assert_eq!(
        discarded
            .iter()
            .map(|discarded| discarded.submission)
            .collect::<Vec<_>>(),
        vec![written[held]],
    );
    assert!(!receipt(&nodes[held], written[held]));
    await_certified_receipt(&nodes[held], written[going]);
    let after = finalize_a_write(&nodes[going], &signers[going]);
    await_certified_receipt(&nodes[held], after);
    assert_eq!(block(&nodes[held], 1), block(&nodes[going], 1));
    assert_eq!(block(&nodes[going], change.cut.height + 1).term, 1);
    for node in nodes {
        block_on(node.stop()).unwrap();
    }
}

#[test]
fn an_active_device_cut_off_during_a_takeover_learns_of_the_term_when_it_reconnects() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_524;
    let dealt = short_epochs::deployment(chain_id, 124);
    let mut devices = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        AWAKE,
    );
    let relays = relayed(&mut devices);
    let [first, second] = &devices;
    let signer = BlsSigner::new(82u64.into(), chain_id).unwrap();

    let mut laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let phone = block_on(EmbeddedNode::start(on_first_address(&second.backup))).unwrap();
    let kept = finalize_a_write(&laptop, &signer);
    await_certified_receipt(&phone, kept);
    block_on(phone.stop()).unwrap();
    for relay in &relays {
        relay.close();
    }

    // The laptop stays awake and keeps validating; the phone, cut off from
    // it, takes the deployment over.
    let lost = finalize_a_write(&laptop, &signer);
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    assert!(!receipt(&phone, lost));
    let certificate = certify(takeover_change(&phone));
    block_on(phone.take_over(dealt.keys().clone(), certificate.clone())).unwrap();
    let other = BlsSigner::new(83u64.into(), chain_id).unwrap();
    let after = finalize_a_write(&phone, &other);
    let third = BlsSigner::new(84u64.into(), chain_id).unwrap();
    let also_lost = finalize_a_write(&laptop, &third);
    assert!(height(&laptop) > certificate.change.cut.height);

    for relay in &relays {
        relay.open();
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while laptop.term() < 1 {
        assert!(
            Instant::now() < deadline,
            "the laptop never learned of term 1"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(block_on(laptop.demoted()), certificate);
    // Blocks it proposed before it learned still finalize; nothing follows them.
    std::thread::sleep(Duration::from_secs(2));
    assert!(stays_at(&laptop, Duration::from_secs(3)));
    let discarded = block_on(laptop.follow(certificate)).unwrap();
    let mut voided: Vec<_> = discarded.iter().map(|entry| entry.submission).collect();
    voided.sort();
    let mut expected = vec![lost, also_lost];
    expected.sort();
    assert_eq!(voided, expected);
    for written in [kept, after] {
        await_certified_receipt(&laptop, written);
    }
    assert!(!receipt(&laptop, lost));
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

#[test]
fn the_holder_of_a_later_term_tells_the_device_it_replaced_and_goes_on() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_525;
    let dealt = short_epochs::deployment(chain_id, 125);
    let mut devices = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        AWAKE,
    );
    let relays = relayed(&mut devices);
    let [first, second] = &devices;
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let phone = block_on(EmbeddedNode::start(on_first_address(&second.backup))).unwrap();
    run_until(&phone, |reached| reached >= 3);
    block_on(phone.stop()).unwrap();
    relays[0].close();
    relays[1].close();
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let certificate = certify(takeover_change(&phone));
    block_on(phone.take_over(dealt.keys().clone(), certificate)).unwrap();
    // Only the phone's way to the laptop opens. The laptop answers the
    // phone's question in the old term, which does not hold the phone
    // back, and learns of the term from the question.
    relays[0].open();
    let reached = height(&phone);
    run_until(&phone, |now| now > reached + 5);
    assert_eq!(contest(&phone), None);
    let deadline = Instant::now() + Duration::from_secs(60);
    while laptop.term() < 1 {
        assert!(
            Instant::now() < deadline,
            "the laptop never learned of term 1"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(matches!(
        block_on(laptop.resume()),
        Err(vera_node::EmbedError::Term(TermRefusal::Superseded(_)))
    ));
    // The replaced device now answers with the phone's own certificate,
    // which does not hold the phone back either.
    let reached = height(&phone);
    run_until(&phone, |now| {
        now > reached + 2 * short_epochs::BLOCKS_PER_EPOCH
    });
    assert_eq!(contest(&phone), None);
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}
