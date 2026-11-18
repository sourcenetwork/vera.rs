//! Devices killed at each step a switch of the active device persists:
//! an announced handover, an accepted takeover and a rewind. See
//! `support/crash.rs` for how a test kills a child process.

#[expect(
    dead_code,
    reason = "its single-device helpers serve the tests of one device"
)]
#[path = "support/crash.rs"]
mod crash;
#[expect(
    dead_code,
    reason = "shared with tests that switch without being killed"
)]
#[path = "support/devices.rs"]
mod devices;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::time::Duration;

use crash::{Seen, Spec, arm, child, nonce, note_written, survived};
use devices::{certify, takeover_change};
use short_epochs::{height, run_until};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_node::{EmbedError, EmbeddedNode, TermRefusal};

#[test]
fn a_handover_killed_once_announced_is_certified_on_the_next_start() {
    const TEST: &str = "a_handover_killed_once_announced_is_certified_on_the_next_start";
    if let Some(spec) = child() {
        let [first, second] = spec.pair();
        let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
        let phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
        let kept = finalize_a_write(&laptop, &spec.signer(96));
        await_certified_receipt(&phone, kept);
        note_written(&spec, "kept", kept);
        arm();
        // A loaded machine can leave the handover unsettled; it is asked again.
        devices::hand_over(&laptop, &second.key.public_key());
        survived();
    }
    let scratch = tempfile::tempdir().unwrap();
    let spec = Spec::new(scratch.path(), 2, 9_536, 7);
    spec.crash(TEST, &spec.directories[0], "handover-announced");
    let [first, second] = spec.pair();
    let change = match block_on(EmbeddedNode::start(first.active.clone())) {
        Err(EmbedError::Term(TermRefusal::HandedOver(change))) => *change,
        other => panic!("{other:?}"),
    };
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let certificate = certify(change);
    let keys = spec.deployment().keys().clone();
    block_on(phone.take_over(keys, certificate)).unwrap();
    let laptop = block_on(EmbeddedNode::start(
        first.active.following(&second.key.public_key()).unwrap(),
    ))
    .unwrap();
    let signer = spec.signer(96);
    signer.set_next_sequence(1);
    let after = finalize_a_write(&phone, &signer);
    for node in [&laptop, &phone] {
        for written in [spec.seen("kept").submission.unwrap(), after] {
            await_certified_receipt(node, written);
        }
    }
    assert_eq!(nonce(&phone, &signer), 2);
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

/// Run the laptop and its backup, stop the laptop, and have the phone take
/// the deployment over until it is killed.
fn take_over_and_wait(spec: &Spec) -> ! {
    let [first, second] = spec.pair();
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    let kept = finalize_a_write(&laptop, &spec.signer(97));
    await_certified_receipt(&phone, kept);
    note_written(spec, "kept", kept);
    let reached = height(&laptop);
    run_until(&phone, |now| now >= reached);
    block_on(laptop.stop()).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let certificate = certify(takeover_change(&phone));
    spec.note(&Seen {
        label: "certificate".into(),
        submission: None,
        request: None,
        certificate: Some(certificate.clone()),
    });
    arm();
    let _ = block_on(phone.take_over(spec.deployment().keys().clone(), certificate));
    survived();
}

#[test]
fn a_takeover_killed_at_each_step_completes_on_the_next_start() {
    const TEST: &str = "a_takeover_killed_at_each_step_completes_on_the_next_start";
    if let Some(spec) = child() {
        take_over_and_wait(&spec);
    }
    for (seed, point) in [(8, "takeover-accepted"), (9, "seating-decided")] {
        let scratch = tempfile::tempdir().unwrap();
        let spec = Spec::new(scratch.path(), 2, 9_537, seed);
        spec.crash(TEST, &spec.directories[1], point);
        let [first, second] = spec.pair();
        let certificate = spec.seen("certificate").certificate.unwrap();
        let keys = spec.deployment().keys().clone();
        let phone = block_on(EmbeddedNode::start(second.backup.activated(keys).unwrap())).unwrap();
        assert_eq!(phone.term_certificate(), Some(certificate.clone()));
        let signer = spec.signer(97);
        signer.set_next_sequence(1);
        let after = finalize_a_write(&phone, &signer);
        assert_eq!(
            devices::block(&phone, certificate.change.cut.height + 1).term,
            1
        );
        // The laptop wakes, learns of the term and follows.
        let mut laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
        assert_eq!(block_on(laptop.demoted()), certificate);
        assert!(block_on(laptop.follow(certificate)).unwrap().is_empty());
        for node in [&laptop, &phone] {
            for written in [spec.seen("kept").submission.unwrap(), after] {
                await_certified_receipt(node, written);
            }
        }
        assert_eq!(nonce(&laptop, &signer), 2);
        block_on(laptop.stop()).unwrap();
        block_on(phone.stop()).unwrap();
    }
}

/// Replace the laptop while it is down after it finalized a request alone,
/// and have it follow until it is killed during its rewind.
fn rewind_and_wait(spec: &Spec) -> ! {
    let [first, second] = spec.pair();
    let laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let signer = spec.signer(98);
    let kept = finalize_a_write(&laptop, &signer);
    await_certified_receipt(&phone, kept);
    note_written(spec, "kept", kept);
    devices::hand_over(&laptop, &second.key.public_key());
    block_on(phone.stop()).unwrap();
    block_on(laptop.resume()).unwrap();
    let lost = finalize_a_write(&laptop, &signer);
    note_written(spec, "lost", lost);
    block_on(laptop.stop()).unwrap();

    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    let certificate = certify(takeover_change(&phone));
    block_on(phone.take_over(spec.deployment().keys().clone(), certificate.clone())).unwrap();
    let after = finalize_a_write(&phone, &spec.signer(99));
    note_written(spec, "after", after);
    std::thread::sleep(Duration::from_secs(3));
    let mut laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    assert_eq!(block_on(laptop.demoted()), certificate);
    arm();
    let _ = block_on(laptop.follow(certificate));
    survived();
}

#[test]
fn a_rewind_killed_at_each_step_reports_the_discarded_request_once() {
    const TEST: &str = "a_rewind_killed_at_each_step_reports_the_discarded_request_once";
    if let Some(spec) = child() {
        rewind_and_wait(&spec);
    }
    for (seed, point) in [(10, "rewind-reported"), (11, "rewind-cut")] {
        let scratch = tempfile::tempdir().unwrap();
        let spec = Spec::new(scratch.path(), 2, 9_538, seed);
        spec.crash(TEST, &spec.directories[0], point);
        let [first, second] = spec.pair();
        let keys = spec.deployment().keys().clone();
        let phone = block_on(EmbeddedNode::start(second.backup.activated(keys).unwrap())).unwrap();
        let laptop = block_on(EmbeddedNode::start(
            first.active.following(&second.key.public_key()).unwrap(),
        ))
        .unwrap();
        let lost = spec.seen("lost").submission.unwrap();
        let discarded = laptop.discarded().unwrap();
        assert_eq!(discarded.len(), 1, "{discarded:?}");
        assert_eq!(discarded[0].submission, lost);
        for written in ["kept", "after"] {
            await_certified_receipt(&laptop, spec.seen(written).submission.unwrap());
        }
        let proof: Option<vera_domain::ReceiptResponse> = block_on(
            laptop
                .rpc()
                .request("vera_getReceiptProof", vec![serde_json::json!(lost)]),
        )
        .unwrap();
        assert!(proof.is_none(), "a voided request is served");
        assert_eq!(nonce(&laptop, &spec.signer(98)), 1);
        block_on(laptop.stop()).unwrap();
        block_on(phone.stop()).unwrap();
    }
}
