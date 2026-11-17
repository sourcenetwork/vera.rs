use std::path::Path;

use alloy_primitives::B256;
use commonware_consensus::{
    simplex::types::{Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, tokio as runtime};
use commonware_utils::{NZU16, NZUsize, non_empty};
use vera_domain::{EpochMaterial, TermCertificate, TermChange, TermCut};

use super::*;

/// A certificate for an invented block at each height.
fn certificates(heights: std::ops::RangeInclusive<u64>) -> Vec<(u64, Certificate)> {
    let public = ed25519::PrivateKey::from_seed(7).public_key();
    let (info, shares) = crate::trusted_setup(7, [public.clone()]).unwrap();
    let material = EpochMaterial::new(info.output.players().clone(), info.output.public().clone());
    let signer = ConsensusScheme::signer(
        crate::NAMESPACE,
        material.participants.clone(),
        material.sharing,
        shares.get_value(&public).unwrap().clone(),
    )
    .unwrap();
    heights
        .map(|height| {
            let proposal = Proposal::new(
                Round::new(Epoch::zero(), View::new(height)),
                View::new(height - 1),
                Sha256::hash(&[&height.to_be_bytes()]),
            );
            let vote = Finalize::sign(&signer, proposal).unwrap();
            let certificate =
                Certificate::from_finalizes(&signer, non_empty![&vote], &Sequential).unwrap();
            (height, certificate)
        })
        .collect()
}

fn config() -> prunable::Config<TwoCap, ()> {
    crate::node::archive_config(
        "finalizations",
        CacheRef::new(NZU16!(4084), NZUsize!(64)),
        (),
    )
}

/// The identifier of the device the tests run as.
const THIS: B256 = B256::repeat_byte(2);
/// The identifier of another device of the account.
const OTHER: B256 = B256::repeat_byte(4);

fn taking_over(cut: u64) -> TermCertificate {
    held(cut, THIS)
}

fn held(cut: u64, holder: B256) -> TermCertificate {
    TermCertificate {
        change: TermChange {
            genesis_id: B256::repeat_byte(1),
            term: 1,
            holder,
            cut: TermCut {
                height: cut,
                block: B256::repeat_byte(3),
            },
        },
        approvals: Vec::new(),
    }
}

const VOTES: &str = "vera-orchestrator_consensus_0";
const OBSERVED: &str = "vera-observer_consensus_0";

/// A backup's directory whose archive holds the certificates of blocks 1 to
/// 5, with each role's journal, a marshal cache and partitions of other kinds.
fn backup(directory: &Path) -> std::path::PathBuf {
    let storage = directory.join("commonware");
    for partition in [
        VOTES,
        OBSERVED,
        "vera-cache-0-finalizations-key",
        "vera-reshare_events",
    ] {
        std::fs::create_dir_all(storage.join(partition)).unwrap();
    }
    TermRecord {
        ran: Some(Role::Backup),
        ..TermRecord::default()
    }
    .store(directory)
    .unwrap();
    storage
}

/// A start of this device whose newest block in history is its newest in
/// marshal's archive.
fn start(backup: bool, newest_block: Option<u64>) -> Start {
    Start {
        this: Some(THIS),
        backup,
        newest_block,
        executed: newest_block.unwrap_or(0),
    }
}

/// Run `settle` in `directory` on an archive that first receives `stored`,
/// and return the heights the archive holds afterwards.
fn settled(
    directory: &Path,
    stored: Vec<(u64, Certificate)>,
    as_backup: bool,
    newest_block: Option<u64>,
) -> Result<Vec<u64>, TermRefusal> {
    settled_as(directory, stored, start(as_backup, newest_block))
}

fn settled_as(
    directory: &Path,
    stored: Vec<(u64, Certificate)>,
    start: Start,
) -> Result<Vec<u64>, TermRefusal> {
    let directory = directory.to_path_buf();
    let storage = directory.join("commonware");
    runtime::Runner::new(runtime::Config::new().with_storage_directory(storage)).start(
        |context| async move {
            let mut archive: Finalizations =
                prunable::Archive::init(context.child("stored"), config())
                    .await
                    .unwrap();
            for (height, certificate) in stored {
                archive = archive
                    .put(height, certificate.proposal.payload, &certificate)
                    .await
                    .unwrap();
            }
            let archive = archive.sync().await.unwrap();
            let archive = settle(
                context.child("seating"),
                &directory,
                start,
                archive,
                config(),
            )
            .await?;
            let mut held = Vec::new();
            for (first, last) in archive.ranges() {
                for height in first..=last {
                    let certificate = archive.get(Identifier::Index(height)).await.unwrap();
                    assert_eq!(
                        certificate.unwrap().proposal.payload,
                        Sha256::hash(&[&height.to_be_bytes()])
                    );
                    held.push(height);
                }
            }
            Ok(held)
        },
    )
}

#[test]
fn a_takeover_removes_the_certificates_above_its_cut_with_the_journals_and_the_cache() {
    let directory = tempfile::tempdir().unwrap();
    let storage = backup(directory.path());
    let mut record = TermRecord::load(directory.path()).unwrap();
    record.taking_over = Some(taking_over(3));
    record.store(directory.path()).unwrap();

    let held = settled(directory.path(), certificates(1..=5), false, Some(3)).unwrap();
    assert_eq!(held, [1, 2, 3]);
    assert!(!storage.join(VOTES).exists() && !storage.join(OBSERVED).exists());
    assert!(!storage.join("vera-cache-0-finalizations-key").exists());
    assert!(storage.join("vera-reshare_events").exists());
    assert!(!kept::stored(directory.path()));
    let record = TermRecord::load(directory.path()).unwrap();
    assert_eq!((record.ran, record.seating), (Some(Role::Validator), None));

    // The rebuilt archive is the one a later start opens.
    assert_eq!(
        settled(directory.path(), Vec::new(), false, Some(3)).unwrap(),
        [1, 2, 3]
    );
}

#[test]
fn a_takeover_away_from_its_cut_is_abandoned_before_anything_is_removed() {
    for (start, head) in [
        // A block above the cut.
        (start(false, Some(4)), 4),
        // Behind the cut.
        (start(false, Some(2)), 2),
        // Marshal holds the cut, history does not yet.
        (
            Start {
                executed: 2,
                ..start(false, Some(3))
            },
            2,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let storage = backup(directory.path());
        let mut record = TermRecord::load(directory.path()).unwrap();
        record.taking_over = Some(taking_over(3));
        record.store(directory.path()).unwrap();

        assert!(matches!(
            settled_as(directory.path(), certificates(1..=5), start),
            Err(TermRefusal::NotAtCut { head: refused, cut: 3 }) if refused == head
        ));
        assert!(storage.join(VOTES).exists() && storage.join(OBSERVED).exists());
        assert!(storage.join("vera-cache-0-finalizations-key").exists());
        let record = TermRecord::load(directory.path()).unwrap();
        assert_eq!((record.taking_over, record.seating), (None, None));
        assert_eq!(
            settled(directory.path(), Vec::new(), false, Some(4)).unwrap(),
            [1, 2, 3, 4, 5]
        );
    }
}

#[test]
fn a_backup_drops_a_certificate_above_the_cut_of_the_term_it_follows() {
    let directory = tempfile::tempdir().unwrap();
    let storage = backup(directory.path());
    let mut record = TermRecord::load(directory.path()).unwrap();
    record.certificate = Some(held(4, OTHER));
    record.store(directory.path()).unwrap();

    let held = settled(directory.path(), certificates(1..=5), true, Some(4)).unwrap();
    assert_eq!(held, [1, 2, 3, 4]);
    assert!(!storage.join("vera-cache-0-finalizations-key").exists());

    // With a block of the term above the cut, its certificate stays.
    let held = settled(directory.path(), certificates(5..=6), true, Some(6)).unwrap();
    assert_eq!(held, [1, 2, 3, 4, 5, 6]);
}

#[test]
fn a_backup_that_holds_its_own_term_keeps_the_certificates_and_votes_above_the_cut() {
    let directory = tempfile::tempdir().unwrap();
    let storage = backup(directory.path());
    let mut record = TermRecord::load(directory.path()).unwrap();
    record.ran = Some(Role::Validator);
    record.certificate = Some(held(4, THIS));
    record.store(directory.path()).unwrap();

    let held = settled(directory.path(), certificates(1..=5), true, Some(4)).unwrap();
    assert_eq!(held, [1, 2, 3, 4, 5]);
    assert!(storage.join(VOTES).exists());
    assert!(storage.join("vera-cache-0-finalizations-key").exists());
}

#[test]
fn an_interrupted_clearing_is_finished_from_the_kept_certificates_in_either_role() {
    let directory = tempfile::tempdir().unwrap();
    let storage = backup(directory.path());
    let mut record = TermRecord::load(directory.path()).unwrap();
    record.seating = Some(Seating {
        role: Role::Validator,
        cut: Some(2),
    });
    record.store(directory.path()).unwrap();
    // The interruption came after the file was complete: the archive may be
    // whole, destroyed or half filled, and the file decides.
    let mut writer = kept::Writer::create(directory.path()).unwrap();
    for (height, certificate) in certificates(1..=2) {
        writer.push(height, certificate.encode().as_ref()).unwrap();
    }
    writer.finish().unwrap();

    let held = settled(directory.path(), certificates(1..=5), true, Some(2)).unwrap();
    assert_eq!(held, [1, 2]);
    assert!(!kept::stored(directory.path()));
    assert!(!storage.join(VOTES).exists() && !storage.join(OBSERVED).exists());
    let record = TermRecord::load(directory.path()).unwrap();
    assert_eq!((record.ran, record.seating), (Some(Role::Backup), None));
}

#[test]
fn a_start_in_the_same_role_clears_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let storage = backup(directory.path());
    let held = settled(directory.path(), certificates(1..=5), true, Some(4)).unwrap();
    assert_eq!(held, [1, 2, 3, 4, 5]);
    assert!(storage.join(VOTES).exists() && storage.join(OBSERVED).exists());
    assert!(storage.join("vera-cache-0-finalizations-key").exists());
}

#[test]
fn a_backup_after_the_validator_removes_only_its_own_journal() {
    let directory = tempfile::tempdir().unwrap();
    let storage = backup(directory.path());
    let mut record = TermRecord::load(directory.path()).unwrap();
    record.ran = Some(Role::Validator);
    record.store(directory.path()).unwrap();

    let held = settled(directory.path(), certificates(1..=5), true, Some(5)).unwrap();
    assert_eq!(held, [1, 2, 3, 4, 5]);
    assert!(storage.join(VOTES).exists() && !storage.join(OBSERVED).exists());
    assert!(storage.join("vera-cache-0-finalizations-key").exists());
    let record = TermRecord::load(directory.path()).unwrap();
    assert_eq!((record.ran, record.seating), (Some(Role::Backup), None));
}

#[test]
fn only_the_partitions_of_one_kind_are_removed() {
    let directory = tempfile::tempdir().unwrap();
    let storage = directory.path().join("commonware");
    for partition in [
        "vera-orchestrator_consensus_0",
        "vera-orchestrator_consensus_12",
        "vera-observer_consensus_0",
        "vera-cache-metadata",
        "vera-cache-3-notarized-key",
        "vera-blocks-value",
        "vera-reshare_events",
    ] {
        std::fs::create_dir_all(storage.join(partition)).unwrap();
    }
    remove(&storage, &journals(Role::Validator)).unwrap();
    let left = |name: &str| storage.join(name).exists();
    assert!(!left("vera-orchestrator_consensus_0"));
    assert!(!left("vera-orchestrator_consensus_12"));
    assert!(left("vera-observer_consensus_0"));
    assert!(left("vera-cache-metadata") && left("vera-blocks-value"));
    remove(&storage, CACHE).unwrap();
    assert!(!left("vera-cache-metadata") && !left("vera-cache-3-notarized-key"));
    assert!(left("vera-blocks-value") && left("vera-reshare_events"));
    remove(&directory.path().join("absent"), CACHE).unwrap();
}
