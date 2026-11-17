//! Switching the account's active device between two devices.

#[path = "support/devices.rs"]
mod devices;
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::time::Duration;

use devices::{block, certify, hand_over, pair, takeover_change};
use short_epochs::{BLOCKS_PER_EPOCH, height, run_until, store_in_files};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{EmbedError, EmbeddedNode, TermRefusal};

const WINDOW: Duration = Duration::from_secs(30);

/// Let `backup` reach the active device's newest block, then stop the active device.
fn stop_followed(active: EmbeddedNode, backup: &EmbeddedNode) {
    let reached = height(&active);
    run_until(backup, |height| height >= reached);
    block_on(active.stop()).unwrap();
    // A stop finalizes the views in flight, and those blocks are still arriving.
    std::thread::sleep(Duration::from_secs(1));
}

#[test]
fn an_announced_handover_loses_no_block_and_the_successor_crosses_the_epoch() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_501;
    let dealt = short_epochs::deployment(chain_id, 91);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let mut laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    assert_eq!((laptop.term(), phone.term()), (0, 0));
    assert!(laptop.term_certificate().is_none());
    let signer = BlsSigner::new(74u64.into(), chain_id).unwrap();
    let before = finalize_a_write(&laptop, &signer);

    // Only a backup takes over, only the active device hands over, and only to a device it knows.
    assert!(matches!(
        block_on(phone.hand_over(&first.key.public_key())),
        Err(EmbedError::Term(TermRefusal::Backup))
    ));
    assert!(matches!(
        block_on(laptop.takeover_change()),
        Err(EmbedError::Term(TermRefusal::Active))
    ));
    assert!(matches!(
        block_on(laptop.hand_over(&dealt.keys().public_key())),
        Err(EmbedError::Term(TermRefusal::UnknownDevice(_)))
    ));

    // After the epoch's midpoint the successor has no record of the dealing it is owed.
    run_until(&laptop, |reached| {
        reached > BLOCKS_PER_EPOCH && reached % BLOCKS_PER_EPOCH >= BLOCKS_PER_EPOCH - 8
    });
    let change = hand_over(&laptop, &second.key.public_key());
    let cut = change.cut.height;
    assert_eq!(change.term, 1);
    assert_eq!(height(&laptop), cut, "the final block is the cut");
    // A second announcement is refused and does not let the device propose again.
    assert!(matches!(
        block_on(laptop.hand_over(&second.key.public_key())),
        Err(EmbedError::Term(TermRefusal::HandedOver(announced))) if *announced == change
    ));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        height(&laptop),
        cut,
        "a device that handed over proposes nothing"
    );
    let certificate = certify(change);

    // A certificate for another device, or one nobody approved, is refused and the backup keeps following.
    let mut unsigned = certificate.clone();
    unsigned.approvals.clear();
    assert!(matches!(
        block_on(phone.take_over(dealt.keys().clone(), unsigned)),
        Err(EmbedError::Term(TermRefusal::Certificate(_)))
    ));
    block_on(phone.take_over(dealt.keys().clone(), certificate.clone())).unwrap();
    assert_eq!(phone.term(), 1);
    assert_eq!(phone.term_certificate(), Some(certificate.clone()));
    assert_eq!(*phone.identity(), dealt.keys().public_key());
    block_on(laptop.follow(certificate.clone())).unwrap();
    assert_eq!(*laptop.identity(), first.key.public_key());
    assert_eq!(laptop.term_certificate(), Some(certificate.clone()));

    let after = finalize_a_write(&phone, &signer);
    for written in [before, after] {
        await_certified_receipt(&phone, written);
        await_certified_receipt(&laptop, written);
    }
    let last = block(&phone, cut);
    let next = block(&phone, cut + 1);
    assert_eq!((last.term, next.term), (0, 1));
    assert_eq!(last.id().0, certificate.change.cut.block);
    assert_eq!(next.parent, last.id(), "the new term builds on the cut");
    assert_eq!(block(&laptop, cut + 1), next);

    let crossed = run_until(&phone, |reached| reached >= cut + 2 * BLOCKS_PER_EPOCH);
    run_until(&laptop, |reached| reached >= crossed);
    let served: Option<vera_domain::TermCertificate> =
        block_on(laptop.rpc().call_empty("vera_getTermCertificate")).unwrap();
    assert_eq!(served, Some(certificate));
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();

    // The device that handed over may not validate again, and the successor may.
    assert!(matches!(
        block_on(EmbeddedNode::start(first.active)),
        Err(EmbedError::Term(TermRefusal::Superseded(_)))
    ));
    let phone = block_on(EmbeddedNode::start(
        second.backup.activated(dealt.keys().clone()).unwrap(),
    ))
    .unwrap();
    assert_eq!(phone.term(), 1);
    assert!(height(&phone) >= crossed);
    block_on(phone.stop()).unwrap();
}

#[test]
fn a_backup_takes_over_on_confirmation_while_the_active_device_is_down() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_502;
    let dealt = short_epochs::deployment(chain_id, 92);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    // A backup's directory does not open as the validator without a certificate.
    assert!(matches!(
        block_on(EmbeddedNode::start(
            second.backup.activated(dealt.keys().clone()).unwrap()
        )),
        Err(EmbedError::Term(TermRefusal::NotCertified))
    ));
    let signer = BlsSigner::new(75u64.into(), chain_id).unwrap();
    let before = finalize_a_write(&laptop, &signer);
    stop_followed(laptop, &phone);

    let change = takeover_change(&phone);
    assert_eq!(change.term, 1);
    assert_eq!(change.cut.height, height(&phone));
    assert_eq!(change.cut.block, block(&phone, change.cut.height).id().0);

    // A certificate whose cut is not this device's newest block is refused.
    let mut behind = change;
    behind.cut.height -= 1;
    behind.cut.block = block(&phone, behind.cut.height).id().0;
    assert!(matches!(
        block_on(phone.take_over(dealt.keys().clone(), certify(behind))),
        Err(EmbedError::Term(TermRefusal::NotAtCut { .. }))
    ));
    let mut other = change;
    other.holder = change.genesis_id;
    assert!(matches!(
        block_on(phone.take_over(dealt.keys().clone(), certify(other))),
        Err(EmbedError::Term(TermRefusal::Holder))
    ));

    block_on(phone.take_over(dealt.keys().clone(), certify(change))).unwrap();
    assert_eq!(phone.term(), 1);
    let after = finalize_a_write(&phone, &signer);
    await_certified_receipt(&phone, before);
    await_certified_receipt(&phone, after);
    assert_eq!(block(&phone, change.cut.height + 1).term, 1);
    // A certificate that does not raise the term is refused by the device that holds it.
    assert!(matches!(
        block_on(phone.follow(certify(change))),
        Err(EmbedError::Term(TermRefusal::Holder))
    ));
    block_on(phone.stop()).unwrap();
}

#[test]
fn a_handover_needs_a_current_successor_and_is_undone_by_resuming() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let dealt = short_epochs::deployment(9_503, 93);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    // A device that keeps its keys in files cannot become a backup, so it does not switch.
    let filed = tempfile::tempdir().unwrap();
    store_in_files(filed.path(), &dealt);
    let mut in_files = first.active.clone();
    in_files.data_dir = filed.path().into();
    in_files.deployment = None;
    assert!(matches!(
        block_on(EmbeddedNode::start(in_files)),
        Err(EmbedError::Term(TermRefusal::KeysInFiles))
    ));

    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    run_until(&laptop, |reached| reached >= 3);
    assert!(matches!(
        block_on(laptop.hand_over(&second.key.public_key())),
        Err(EmbedError::Term(
            TermRefusal::SuccessorNotCurrent { .. } | TermRefusal::Unsettled
        ))
    ));
    let resumed = height(&laptop);
    run_until(&laptop, |reached| reached > resumed + 2);

    let phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    let undone = hand_over(&laptop, &second.key.public_key());
    block_on(laptop.resume()).unwrap();
    run_until(&laptop, |reached| reached > undone.cut.height + 2);
    let change = hand_over(&laptop, &second.key.public_key());
    assert!(change.cut.height > undone.cut.height);
    assert_eq!(change.term, undone.term);
    block_on(laptop.stop()).unwrap();
    // The announcement outlives the process: the device does not validate until it resumes.
    assert!(matches!(
        block_on(EmbeddedNode::start(first.active.clone())),
        Err(EmbedError::Term(TermRefusal::HandedOver(announced))) if *announced == change
    ));
    // No certificate was issued. The stopped device takes the handover back and validates again.
    EmbeddedNode::resume_stopped(&first.active).unwrap();
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    run_until(&laptop, |reached| reached > change.cut.height + 2);
    assert_eq!(laptop.term(), 0);

    // A device that announced a handover may follow the successor before
    // the certificate reaches it.
    let change = hand_over(&laptop, &second.key.public_key());
    block_on(laptop.stop()).unwrap();
    let following = first.active.following(&second.key.public_key()).unwrap();
    let laptop = block_on(EmbeddedNode::start(following)).unwrap();
    assert_eq!(height(&laptop), change.cut.height);
    block_on(laptop.stop()).unwrap();
    assert_eq!(height(&phone), change.cut.height);
    // Nobody produced a block meanwhile. The device takes the handover back
    // and validates again on its newest block.
    EmbeddedNode::resume_stopped(&first.active).unwrap();
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    run_until(&laptop, |reached| reached > change.cut.height + 2);
    run_until(&phone, |reached| reached > change.cut.height + 2);
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

/// Wait until `node` reports that another device holds a later term.
fn await_demotion(node: &EmbeddedNode, term: u64) -> vera_domain::TermCertificate {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while node.term() < term {
        assert!(
            std::time::Instant::now() < deadline,
            "the device did not learn of term {term}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    block_on(node.demoted())
}

#[test]
fn a_device_that_wakes_asks_for_the_term_before_it_proposes() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_504;
    let dealt = short_epochs::deployment(chain_id, 94);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        Duration::from_secs(2),
    );
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    let signer = BlsSigner::new(76u64.into(), chain_id).unwrap();
    let before = finalize_a_write(&laptop, &signer);
    let slept_at = height(&laptop);
    stop_followed(laptop, &phone);

    // Nobody answers a device that wakes alone, and it goes on as the active device.
    std::thread::sleep(Duration::from_secs(3));
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    run_until(&laptop, |reached| reached > slept_at + 2);
    stop_followed(laptop, &phone);

    let certificate = certify(takeover_change(&phone));
    block_on(phone.take_over(dealt.keys().clone(), certificate.clone())).unwrap();
    let after = finalize_a_write(&phone, &signer);

    // The device that was replaced wakes with nothing above the cut. It
    // learns of the term before it proposes, and proposes nothing.
    std::thread::sleep(Duration::from_secs(3));
    let mut laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    assert_eq!(await_demotion(&laptop, 1), certificate);
    assert_eq!(height(&laptop), certificate.change.cut.height);
    let status: vera_jsonrpc::NodeStatus =
        block_on(laptop.rpc().call_empty("vera_nodeStatus")).unwrap();
    assert_eq!(status.proposed_count, 0);
    assert!(matches!(
        block_on(laptop.resume()),
        Err(EmbedError::Term(TermRefusal::Superseded(_)))
    ));
    // A handover by a device that was replaced is refused and leaves it held.
    assert!(matches!(
        block_on(laptop.hand_over(&second.key.public_key())),
        Err(EmbedError::Term(TermRefusal::Superseded(_)))
    ));
    std::thread::sleep(Duration::from_secs(4));
    let status: vera_jsonrpc::NodeStatus =
        block_on(laptop.rpc().call_empty("vera_nodeStatus")).unwrap();
    assert_eq!(status.proposed_count, 0);
    assert_eq!(height(&laptop), certificate.change.cut.height);

    block_on(laptop.follow(certificate)).unwrap();
    for written in [before, after] {
        await_certified_receipt(&laptop, written);
    }
    run_until(&laptop, |reached| reached >= height(&phone));
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

fn receipt(node: &EmbeddedNode, submission: alloy_primitives::B256) -> bool {
    let proof: Option<vera_domain::ReceiptResponse> = block_on(
        node.rpc()
            .request("vera_getReceiptProof", vec![serde_json::json!(submission)]),
    )
    .unwrap();
    proof.is_some()
}

#[test]
fn a_device_replaced_while_it_was_down_rewinds_above_the_cut_and_follows() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_505;
    let dealt = short_epochs::deployment(chain_id, 95);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        Duration::from_secs(2),
    );
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let signer = BlsSigner::new(77u64.into(), chain_id).unwrap();
    let kept = finalize_a_write(&laptop, &signer);
    await_certified_receipt(&phone, kept);

    // The backup is away while the active device finalizes a request, and
    // the active device goes down before the backup is back.
    // The backup stops while the active device holds its proposals back, so
    // no block is on its way to it.
    hand_over(&laptop, &second.key.public_key());
    block_on(phone.stop()).unwrap();
    block_on(laptop.resume()).unwrap();
    let lost = finalize_a_write(&laptop, &signer);
    let laptop_head = height(&laptop);
    block_on(laptop.stop()).unwrap();

    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    assert!(!receipt(&phone, lost));
    let certificate = certify(takeover_change(&phone));
    let cut = certificate.change.cut.height;
    assert!(cut < laptop_head);
    block_on(phone.take_over(dealt.keys().clone(), certificate.clone())).unwrap();
    let other = BlsSigner::new(78u64.into(), chain_id).unwrap();
    let after = finalize_a_write(&phone, &other);

    // The device that was replaced wakes, learns of the term, and follows.
    // What it finalized above the cut is void, and it reports the request.
    std::thread::sleep(Duration::from_secs(3));
    let mut laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    assert!(receipt(&laptop, lost));
    assert_eq!(await_demotion(&laptop, 1), certificate);
    let status: vera_jsonrpc::NodeStatus =
        block_on(laptop.rpc().call_empty("vera_nodeStatus")).unwrap();
    assert_eq!(
        status.proposed_count, 0,
        "a demoted device proposes nothing"
    );
    // A stop finalizes the views in flight, so the device may hold a block more.
    let laptop_head = height(&laptop).max(laptop_head);
    let discarded = block_on(laptop.follow(certificate)).unwrap();
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    assert_eq!(discarded[0].submission, lost);
    assert!(discarded[0].success);
    assert!(discarded[0].height > cut && discarded[0].height <= laptop_head);

    for written in [kept, after] {
        await_certified_receipt(&laptop, written);
    }
    assert!(
        !receipt(&laptop, lost),
        "a voided request is no longer served"
    );
    let reached = run_until(&laptop, |reached| reached >= height(&phone));
    assert_eq!(block(&laptop, cut + 1), block(&phone, cut + 1));
    assert_eq!(block(&laptop, cut + 1).term, 1);
    assert_eq!(block(&laptop, cut).term, 0);
    assert!(reached > cut);

    // The report outlives a restart until the host acknowledges it. The host
    // sends the request again, and the active device finalizes it in the new term.
    assert_eq!(laptop.discarded().unwrap(), discarded);
    let again: alloy_primitives::B256 = block_on(phone.rpc().request(
        "vera_sendNativeTx",
        vec![serde_json::json!(discarded[0].request)],
    ))
    .unwrap();
    assert_eq!(again, lost);
    await_certified_receipt(&phone, lost);
    await_certified_receipt(&laptop, lost);
    block_on(laptop.stop()).unwrap();
    let laptop = block_on(EmbeddedNode::start(
        first.active.following(&second.key.public_key()).unwrap(),
    ))
    .unwrap();
    assert_eq!(laptop.discarded().unwrap(), discarded);
    laptop.acknowledge_discarded().unwrap();
    assert!(laptop.discarded().unwrap().is_empty());
    // A start never prepares a directory another node runs on.
    assert!(matches!(
        block_on(EmbeddedNode::start(
            first.active.following(&second.key.public_key()).unwrap()
        )),
        Err(EmbedError::DirectoryInUse(_))
    ));
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

#[test]
fn a_backup_that_holds_a_term_refuses_a_block_of_a_lower_one() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let dealt = short_epochs::deployment(9_506, 96);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    run_until(&phone, |reached| reached >= 3);

    // The operators certify a term for the laptop, and the backup accepts
    // it. The device at the laptop's address goes on in the old term: it
    // never took the term up.
    let mut change = takeover_change(&phone);
    change.holder = alloy_primitives::B256::from_slice(
        commonware_codec::Encode::encode(&first.key.public_key()).as_ref(),
    );
    let certificate = certify(change);
    let refused = match block_on(phone.follow(certificate.clone())) {
        Ok(_) => block_on(phone.failed()),
        Err(error) => error,
    };
    assert!(
        matches!(
            refused,
            EmbedError::Term(TermRefusal::LowerTerm { height, term: 0, held: 1 })
                if height > certificate.change.cut.height
        ),
        "{refused}"
    );
    // The refused block stays behind in the stores, and the device refuses its source again.
    assert!(matches!(
        block_on(EmbeddedNode::start(second.backup)),
        Err(EmbedError::Term(TermRefusal::LowerTerm {
            term: 0,
            held: 1,
            ..
        }))
    ));
    assert!(height(&laptop) > certificate.change.cut.height);
    block_on(laptop.stop()).unwrap();
}

#[test]
fn a_second_device_that_validates_is_answered_and_does_not_propose() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let dealt = short_epochs::deployment(9_507, 97);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    run_until(&laptop, |reached| reached >= 3);

    // The phone opens the deployment as its validator in an empty directory,
    // with no certificate: the laptop answers it as the validator.
    let phone = block_on(EmbeddedNode::start(second.active)).unwrap();
    let contest = block_on(phone.contested());
    assert_eq!(contest.device, first.key.public_key());
    assert!(contest.height >= 3);
    assert_eq!(contest.certificate, None);
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(height(&phone), 0, "a contested device finalized a block");
    let status: vera_jsonrpc::NodeStatus =
        block_on(phone.rpc().call_empty("vera_nodeStatus")).unwrap();
    assert_eq!(status.proposed_count, 0);
    block_on(phone.stop()).unwrap();
    block_on(laptop.stop()).unwrap();
}

#[test]
fn a_term_handed_back_to_the_device_it_came_from_goes_on() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_509;
    let dealt = short_epochs::deployment(chain_id, 99);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let mut laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    run_until(&laptop, |reached| reached >= 3);

    let out = certify(hand_over(&laptop, &second.key.public_key()));
    block_on(phone.take_over(dealt.keys().clone(), out.clone())).unwrap();
    block_on(laptop.follow(out.clone())).unwrap();
    // The phone builds blocks of its term before it hands back.
    let signer = BlsSigner::new(79u64.into(), chain_id).unwrap();
    let between = finalize_a_write(&phone, &signer);
    run_until(&phone, |reached| reached >= out.change.cut.height + 4);
    let back = certify(hand_over(&phone, &first.key.public_key()));
    assert_eq!(back.change.term, 2);
    assert!(back.change.cut.height >= out.change.cut.height + 4);
    block_on(laptop.take_over(dealt.keys().clone(), back.clone())).unwrap();
    block_on(phone.follow(back.clone())).unwrap();

    let written = finalize_a_write(&laptop, &signer);
    await_certified_receipt(&laptop, between);
    await_certified_receipt(&phone, written);
    assert_eq!(block(&laptop, out.change.cut.height + 1).term, 1);
    assert_eq!(block(&laptop, back.change.cut.height + 1).term, 2);
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

#[test]
fn a_device_that_followed_nobody_validates_again_under_a_certificate() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let dealt = short_epochs::deployment(9_508, 98);
    let [first, _second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    run_until(&laptop, |reached| reached >= 5);
    block_on(laptop.stop()).unwrap();

    let mut laptop = block_on(EmbeddedNode::start(first.backup)).unwrap();
    let change = block_on(laptop.takeover_change()).unwrap();
    block_on(laptop.take_over(dealt.keys().clone(), certify(change))).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while height(&laptop) <= change.cut.height + 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "stalled at height {}",
            height(&laptop)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    block_on(laptop.stop()).unwrap();
}

#[test]
fn a_backup_that_synchronized_by_snapshot_takes_over_before_another_block() {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_510;
    let dealt = short_epochs::deployment(chain_id, 100);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    // The backup joins in the second epoch, so the block that opened the
    // epoch is one it never received from consensus.
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    run_until(&laptop, |reached| reached >= BLOCKS_PER_EPOCH + 4);
    block_on(laptop.stop()).unwrap();
    // The active device then builds a block only for a request.
    let mut quiet = first.active;
    quiet.pacing = Some(vera_node::SoloPacing {
        idle: vera_node::EmbeddedConfig::HEARTBEAT,
        batch: vera_node::SoloPacing::BATCH,
    });
    let laptop = block_on(EmbeddedNode::start(quiet)).unwrap();
    let signer = BlsSigner::new(80u64.into(), chain_id).unwrap();
    let mut before = finalize_a_write(&laptop, &signer);
    // The backup joins away from the end of an epoch, where the next epoch
    // would start from the block without a certificate.
    while height(&laptop) % BLOCKS_PER_EPOCH >= BLOCKS_PER_EPOCH - 2 {
        before = finalize_a_write(&laptop, &signer);
    }

    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    await_certified_receipt(&phone, before);
    let joined = height(&phone);
    assert_eq!(joined, height(&laptop), "the active device built a block");
    block_on(laptop.stop()).unwrap();

    let change = takeover_change(&phone);
    assert_eq!(change.cut.height, joined);
    block_on(phone.take_over(dealt.keys().clone(), certify(change))).unwrap();
    let after = finalize_a_write(&phone, &signer);
    await_certified_receipt(&phone, after);
    assert_eq!(block(&phone, joined + 1).term, 1);
    run_until(&phone, |reached| reached >= joined + 3);
    block_on(phone.stop()).unwrap();
}
