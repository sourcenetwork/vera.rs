//! A switch its host drops midway: `stop` joins the node, and a start completes the switch.

#[allow(
    dead_code,
    reason = "shared with tests that switch devices in other ways"
)]
#[path = "support/devices.rs"]
mod devices;
#[allow(dead_code, reason = "shared with tests that cross epochs")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::{pin::pin, task::Poll, time::Duration};

use devices::{certify, hand_over, pair};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{EmbedError, EmbeddedNode};

const WINDOW: Duration = Duration::from_secs(30);

/// Drop `future` once it has been pending `polls` times.
fn dropped_after<F: Future>(future: F, polls: usize) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut left = polls;
    block_on(std::future::poll_fn(|context| {
        match future.as_mut().poll(context) {
            Poll::Ready(output) => Poll::Ready(Some(output)),
            Poll::Pending if left <= 1 => Poll::Ready(None),
            Poll::Pending => {
                left -= 1;
                Poll::Pending
            }
        }
    }))
}

/// A switch waits for the certificate to be accepted, then for the old node
/// to stop, then for the new one to serve: `polls` picks where it is dropped.
fn switch_dropped_after(polls: usize, chain_id: u64, seed: u64) {
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let dealt = short_epochs::deployment(chain_id, seed);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let mut laptop = block_on(EmbeddedNode::start(first.active.clone())).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let signer = BlsSigner::new(75u64.into(), chain_id).unwrap();
    let before = finalize_a_write(&laptop, &signer);
    let certificate = certify(hand_over(&laptop, &second.key.public_key()));
    let keys = dealt.keys().clone();

    let taken = dropped_after(phone.take_over(keys.clone(), certificate.clone()), polls);
    let phone = if let Some(result) = taken {
        result.unwrap();
        phone
    } else {
        assert!(matches!(
            block_on(phone.take_over(keys.clone(), certificate.clone())),
            Err(EmbedError::Interrupted)
        ));
        assert!(matches!(
            block_on(phone.takeover_change()),
            Err(EmbedError::Interrupted)
        ));
        block_on(phone.stop()).unwrap();
        block_on(EmbeddedNode::start(second.backup.activated(keys).unwrap())).unwrap()
    };
    assert_eq!(phone.term(), 1);
    assert_eq!(*phone.identity(), dealt.keys().public_key());

    let followed = dropped_after(laptop.follow(certificate.clone()), polls);
    let laptop = if let Some(result) = followed {
        result.unwrap();
        laptop
    } else {
        assert!(matches!(
            block_on(laptop.follow(certificate.clone())),
            Err(EmbedError::Interrupted)
        ));
        assert!(matches!(block_on(laptop.failed()), EmbedError::Interrupted));
        block_on(laptop.stop()).unwrap();
        // The stored certificate rules the device out as the validator.
        assert!(matches!(
            block_on(EmbeddedNode::start(first.active.clone())),
            Err(EmbedError::Term(vera_node::TermRefusal::Superseded(_)))
        ));
        block_on(EmbeddedNode::start(first.backup.clone())).unwrap()
    };
    assert_eq!(laptop.term_certificate(), Some(certificate));
    assert_eq!(*laptop.identity(), first.key.public_key());

    let after = finalize_a_write(&phone, &signer);
    for written in [before, after] {
        await_certified_receipt(&phone, written);
        await_certified_receipt(&laptop, written);
    }
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
}

#[test]
fn a_switch_dropped_while_the_old_node_stops_completes_at_the_next_start() {
    switch_dropped_after(2, 9_531, 131);
}

#[test]
fn a_switch_dropped_while_the_new_node_starts_completes_at_the_next_start() {
    switch_dropped_after(3, 9_532, 132);
}
