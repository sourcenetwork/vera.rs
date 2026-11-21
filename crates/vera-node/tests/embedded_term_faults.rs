//! Switching from storage states a running node does not reach on demand: a
//! finalization certificate stored without its block, and a start
//! interrupted while consensus storage is cleared.

#[path = "support/devices.rs"]
mod devices;
#[expect(dead_code, reason = "shared with tests that keep keys in files")]
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::{collections::BTreeMap, path::Path, time::Duration};

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

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Replace the partitions in `target` whose names start with one of
/// `prefixes` by those of the stopped node in `source`.
fn transplant(source: &Path, target: &Path, prefixes: &[&str]) {
    let partitions = |directory: &Path| {
        std::fs::read_dir(directory.join("commonware"))
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                let name = entry.file_name();
                prefixes
                    .iter()
                    .any(|prefix| name.to_string_lossy().starts_with(prefix))
            })
            .collect::<Vec<_>>()
    };
    for partition in partitions(target) {
        std::fs::remove_dir_all(partition.path()).unwrap();
    }
    for partition in partitions(source) {
        copy_tree(
            &partition.path(),
            &target.join("commonware").join(partition.file_name()),
        );
    }
}

/// Stop `backups` while the active device holds its proposals back, let the
/// active device finalize blocks they never see, and stop it.
fn leave_behind(
    active: EmbeddedNode,
    successor: &Paired,
    backups: Vec<EmbeddedNode>,
    signer: &BlsSigner,
) {
    let held = hand_over(&active, &successor.key.public_key()).cut.height;
    for backup in backups {
        run_until(&backup, |reached| reached >= held);
        block_on(backup.stop()).unwrap();
    }
    block_on(active.resume()).unwrap();
    finalize_a_write(&active, signer);
    run_until(&active, |reached| reached > held + 3);
    block_on(active.stop()).unwrap();
}

#[test]
fn a_block_built_ahead_of_its_turn_does_not_finalize_above_the_cut_of_a_handover() {
    let directories = [(); 2].map(|()| tempfile::tempdir().unwrap());
    let dealt = short_epochs::deployment(9_514, 104);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    run_until(&laptop, |reached| reached >= 3);
    // The next block built ahead of its turn waits for the announcement
    // before it reaches consensus.
    let stall = directories[0].path().join("stall-staged-block");
    std::fs::write(&stall, []).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while stall.exists() {
        assert!(std::time::Instant::now() < deadline, "no block was staged");
        std::thread::sleep(Duration::from_millis(10));
    }

    let cut = hand_over(&laptop, &second.key.public_key()).cut.height;
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(height(&laptop), cut, "a block finalized above the cut");
    assert_eq!(height(&phone), cut);
    block_on(laptop.stop()).unwrap();
    block_on(phone.stop()).unwrap();
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
    leave_behind(laptop, &second, vec![phone, tablet], &signer);
    // Each backup holds the certificate of the block above its newest one alone.
    orphan(directories[1].path(), directories[0].path());
    orphan(directories[2].path(), directories[0].path());

    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let cut = height(&phone);
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

    // The second backup holds such a certificate too, and follows the phone.
    let mut tablet = block_on(EmbeddedNode::start(third.backup)).unwrap();
    block_on(tablet.follow(certificate)).unwrap();
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
        settled: vera_node::SoloPacing::SETTLED,
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
    leave_behind(laptop, &second, vec![phone], &signer);
    orphan(directories[1].path(), directories[0].path());

    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let cut = height(&phone);
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

#[test]
fn a_holder_stopped_between_marshals_writes_keeps_its_first_block_across_a_spell_as_a_backup() {
    let directories = [(); 3].map(|()| tempfile::tempdir().unwrap());
    let chain_id = 9_513;
    let dealt = short_epochs::deployment(chain_id, 103);
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        WINDOW,
    );
    let mut laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    run_until(&laptop, |reached| reached >= 3);
    let change = hand_over(&laptop, &second.key.public_key());
    let cut = change.cut.height;
    assert_eq!(run_until(&phone, |reached| reached >= cut), cut);
    block_on(phone.stop()).unwrap();
    // The copy is the phone at the cut, before it takes over.
    let copy = directories[2].path();
    copy_tree(directories[1].path(), copy);

    let mut phone = block_on(EmbeddedNode::start(second.backup.clone())).unwrap();
    let out = certify(change);
    block_on(phone.take_over(dealt.keys().clone(), out.clone())).unwrap();
    block_on(laptop.follow(out.clone())).unwrap();
    block_on(laptop.stop()).unwrap();
    let signer = BlsSigner::new(85u64.into(), chain_id).unwrap();
    let written = finalize_a_write(&phone, &signer);
    let built: BTreeMap<u64, _> = (cut + 1..=height(&phone))
        .map(|reached| (reached, block(&phone, reached)))
        .collect();
    block_on(phone.stop()).unwrap();

    // The copy becomes the phone as it was had it stopped after it
    // finalized its first block, between marshal's two writes: the term it
    // took over, the votes and cached blocks of its term, and the
    // certificate of block cut + 1 without the block.
    std::fs::copy(
        directories[1].path().join("term.json"),
        copy.join("term.json"),
    )
    .unwrap();
    transplant(
        directories[1].path(),
        copy,
        &["vera-orchestrator_consensus_", "vera-cache"],
    );
    orphan(copy, directories[1].path());

    // The host starts it as a backup while nobody else runs, and then
    // resumes it as the holder of its term.
    let mut backup = second.backup;
    backup.data_dir = copy.into();
    let follower = block_on(EmbeddedNode::start(backup.clone())).unwrap();
    assert!(height(&follower) >= cut);
    block_on(follower.stop()).unwrap();
    let active = backup.activated(dealt.keys().clone()).unwrap();
    EmbeddedNode::resume_stopped(&active).unwrap();
    let resumed = block_on(EmbeddedNode::start(active)).unwrap();

    // It finalizes the blocks the phone built, not new ones at their heights.
    await_certified_receipt(&resumed, written);
    for (reached, expected) in &built {
        assert_eq!(&block(&resumed, *reached), expected, "block {reached}");
    }
    let last = *built.keys().last().unwrap();
    run_until(&resumed, |reached| reached > last + 1);
    assert_eq!(block(&resumed, last + 1).term, out.change.term);
    block_on(resumed.stop()).unwrap();
}
