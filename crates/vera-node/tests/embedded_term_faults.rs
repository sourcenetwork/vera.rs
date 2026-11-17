//! Taking the deployment over from storage states a running node does not
//! reach on demand: a finalization certificate stored without its block, and
//! a start interrupted while consensus storage is cleared.

#[path = "support/devices.rs"]
mod devices;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::{path::Path, time::Duration};

use devices::{Paired, block, certify, devices, hand_over, pair, takeover_change};
use short_epochs::{height, run_until};

use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::BlsSigner;
use vera_node::{EmbedError, EmbeddedNode, TermRefusal};

const WINDOW: Duration = Duration::from_secs(30);

/// Have the node that next starts in `directory` find the certificate of the
/// block above its newest one, which the stopped node in `source` finalized.
fn orphan(directory: &Path, source: &Path) {
    std::fs::write(
        directory.join("orphan-finalization"),
        source.to_str().unwrap(),
    )
    .unwrap();
}

/// Stop `backups` on the active device's newest block, let the active device
/// finalize a request they never see, and stop it. Returns the height the
/// backups stopped at and the request.
fn leave_behind(
    active: EmbeddedNode,
    successor: &Paired,
    backups: Vec<EmbeddedNode>,
    signer: &BlsSigner,
) -> (u64, alloy_primitives::B256) {
    // No block is on its way to a backup while the active device holds its proposals back.
    let cut = hand_over(&active, &successor.key.public_key()).cut.height;
    for backup in backups {
        run_until(&backup, |reached| reached >= cut);
        assert_eq!(height(&backup), cut);
        block_on(backup.stop()).unwrap();
    }
    block_on(active.resume()).unwrap();
    let lost = finalize_a_write(&active, signer);
    assert!(height(&active) > cut);
    block_on(active.stop()).unwrap();
    (cut, lost)
}

#[test]
fn a_backup_takes_over_past_the_certificate_of_a_block_it_never_received() {
    let directories = [(); 3].map(|()| tempfile::tempdir().unwrap());
    let chain_id = 9_511;
    let dealt = short_epochs::deployment(chain_id, 101);
    let [first, second, third] = devices(
        [
            directories[0].path(),
            directories[1].path(),
            directories[2].path(),
        ],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let tablet = block_on(EmbeddedNode::start(third.backup.clone())).unwrap();
    let signer = BlsSigner::new(81u64.into(), chain_id).unwrap();
    let kept = finalize_a_write(&laptop, &signer);
    let (cut, _) = leave_behind(laptop, &second, vec![phone, tablet], &signer);
    // Both backups hold the certificate of the laptop's next block alone.
    orphan(directories[1].path(), directories[0].path());
    orphan(directories[2].path(), directories[0].path());

    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    assert_eq!(height(&phone), cut);
    let certificate = certify(takeover_change(&phone));
    assert_eq!(certificate.change.cut.height, cut);
    block_on(phone.take_over(dealt.keys().clone(), certificate.clone())).unwrap();
    let other = BlsSigner::new(82u64.into(), chain_id).unwrap();
    let after = finalize_a_write(&phone, &other);
    // The first block of the term is certified as the phone built it.
    let opened = block(&phone, cut + 1);
    assert_eq!(opened.term, 1);
    for written in [kept, after] {
        await_certified_receipt(&phone, written);
    }

    // The second backup holds the same certificate and follows the phone.
    let mut tablet = block_on(EmbeddedNode::start(third.backup)).unwrap();
    assert_eq!(height(&tablet), cut);
    assert!(block_on(tablet.follow(certificate)).unwrap().is_empty());
    for written in [kept, after] {
        await_certified_receipt(&tablet, written);
    }
    assert_eq!(block(&tablet, cut + 1), opened);
    run_until(&tablet, |reached| reached >= height(&phone));

    // The phone restarts on the journal it began at the cut, and from here
    // builds a block only for a request.
    block_on(phone.stop()).unwrap();
    let mut quiet = second.backup.activated(dealt.keys().clone()).unwrap();
    quiet.pacing = Some(vera_node::SoloPacing {
        idle: vera_node::EmbeddedConfig::HEARTBEAT,
        batch: vera_node::SoloPacing::BATCH,
    });
    let phone = block_on(EmbeddedNode::start(quiet)).unwrap();
    let again = finalize_a_write(&phone, &other);
    await_certified_receipt(&tablet, again);
    for node in [tablet, phone] {
        block_on(node.stop()).unwrap();
    }
}

#[test]
fn a_takeover_interrupted_while_it_clears_consensus_storage_is_finished_by_the_next_start() {
    let directories = [(); 2].map(|()| tempfile::tempdir().unwrap());
    let chain_id = 9_512;
    let dealt = short_epochs::deployment(chain_id, 102);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let signer = BlsSigner::new(83u64.into(), chain_id).unwrap();
    let kept = finalize_a_write(&laptop, &signer);
    let (cut, _) = leave_behind(laptop, &second, vec![phone], &signer);
    orphan(directories[1].path(), directories[0].path());

    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let certificate = certify(takeover_change(&phone));
    assert_eq!(certificate.change.cut.height, cut);
    // The start under the certificate fails after the certificates it keeps
    // are copied and before the archive is rebuilt.
    let interrupt = directories[1].path().join("seating-interrupt");
    std::fs::write(&interrupt, []).unwrap();
    assert!(matches!(
        block_on(phone.take_over(dealt.keys().clone(), certificate)),
        Err(EmbedError::Term(TermRefusal::Io { .. }))
    ));
    assert!(!interrupt.exists());
    assert!(directories[1].path().join("kept-finalizations").is_file());

    let phone = block_on(EmbeddedNode::start(
        second.backup.activated(dealt.keys().clone()).unwrap(),
    ))
    .unwrap();
    assert!(!directories[1].path().join("kept-finalizations").exists());
    assert_eq!(phone.term(), 1);
    let other = BlsSigner::new(84u64.into(), chain_id).unwrap();
    let after = finalize_a_write(&phone, &other);
    assert_eq!(block(&phone, cut + 1).term, 1);
    for written in [kept, after] {
        await_certified_receipt(&phone, written);
    }
    // The certificates up to the cut were kept.
    assert_eq!(block(&phone, cut).term, 0);
    block_on(phone.stop()).unwrap();
}
