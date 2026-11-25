//! Starts that rely on the validated head, and the writes that keep it truthful.

use super::compaction_tests::{Phase, faulty};
use super::start_cost_tests::{Heartbeats, heartbeats};
use super::*;
use vera_indexer::{IndexQuery, MAX_CACHED_EPOCHS};

const REVISIONS: u64 = 3_000;
/// Short enough that more epochs precede the resident window than the cache holds.
const EPOCH: u64 = 8;
/// Reads of a start that rereads only the resident window: its records and
/// certificates, the epoch boundaries before it and a few metadata keys.
const BOUNDED_READS: u64 = 2 * MAX_CACHED_REVISIONS as u64 + 2 * MAX_CACHED_EPOCHS as u64 + 16;

struct Recovered {
    index: BlockIndex,
    epochs: LightBlockIndex,
    reads: u64,
}

async fn recover(fixture: &Heartbeats) -> Result<Recovered> {
    let index = BlockIndex::new();
    let epochs = fixture.epochs();
    let before = fixture.history.db.reads();
    fixture.recover(&index, &epochs).await?;
    Ok(Recovered {
        index,
        epochs,
        reads: fixture.history.db.reads() - before,
    })
}

fn validated(history: &FinalizedHistory) -> Option<Vec<u8>> {
    history.db.get(VALIDATED).unwrap()
}

fn stored_head(history: &FinalizedHistory) -> Vec<u8> {
    history.db.get(HEAD).unwrap().unwrap()
}

fn marker(height: u64, hash: B256) -> Vec<u8> {
    borsh::to_vec(&(height, hash.0)).unwrap()
}

#[tokio::test]
async fn a_validated_start_reads_a_bounded_suffix_and_restores_what_a_full_walk_does() {
    let fixture = heartbeats(REVISIONS, EPOCH).reopen();
    assert_eq!(
        validated(&fixture.history),
        Some(stored_head(&fixture.history)),
        "appends extend the validated head"
    );
    let short = recover(&fixture).await.unwrap();
    assert!(short.reads <= BOUNDED_READS, "{} reads", short.reads);

    fixture.history.db.delete(VALIDATED).unwrap();
    let fixture = fixture.reopen();
    let full = recover(&fixture).await.unwrap();
    assert!(full.reads >= REVISIONS, "{} reads", full.reads);
    assert_eq!(
        validated(&fixture.history),
        Some(stored_head(&fixture.history)),
        "a full walk records what it checked"
    );

    assert_eq!(short.index.stats(), full.index.stats());
    assert_eq!(short.epochs.stats(), full.epochs.stats());
    for epoch in 0..=REVISIONS / EPOCH + 1 {
        assert_eq!(
            short.epochs.get_epoch_material(epoch),
            full.epochs.get_epoch_material(epoch),
            "epoch {epoch}"
        );
    }
    assert_eq!(full.epochs.stats().epochs, MAX_CACHED_EPOCHS);
    for height in REVISIONS - MAX_CACHED_REVISIONS as u64..=REVISIONS {
        let block = fixture.history.stored_block(height).unwrap().unwrap();
        let resident = |recovered: &Recovered| {
            (
                recovered
                    .index
                    .get_block_by_number(height)
                    .map(|block| block.hash),
                recovered.epochs.get_finalization(&block.digest().0),
            )
        };
        assert_eq!(resident(&short), resident(&full), "height {height}");
    }

    let fixture = fixture.reopen();
    assert!(recover(&fixture).await.unwrap().reads <= BOUNDED_READS);
}

#[tokio::test]
async fn a_start_without_a_matching_validated_head_checks_every_record() {
    let fixture = heartbeats(REVISIONS, EPOCH).reopen();
    let original = fixture.history.db.get(key(RECORD, 1)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&original).unwrap();
    let (mut first, _) = record.decode().unwrap();
    let first_id = first.id();
    first.parent = BlockId(B256::repeat_byte(99));
    record.block = first.encode().to_vec();
    fixture
        .history
        .db
        .put(key(RECORD, 1), borsh::to_vec(&record).unwrap())
        .unwrap();
    let head = fixture.head.id().0;
    let below = fixture
        .history
        .stored_block(REVISIONS - 1)
        .unwrap()
        .unwrap()
        .id()
        .0;
    for (case, stored) in [
        ("absent", None),
        ("malformed", Some(vec![1, 2, 3])),
        ("other block", Some(marker(REVISIONS, B256::repeat_byte(7)))),
        ("behind the head", Some(marker(REVISIONS - 1, below))),
        ("above the head", Some(marker(REVISIONS + 1, head))),
    ] {
        match stored {
            Some(bytes) => fixture.history.db.put(VALIDATED, bytes).unwrap(),
            None => fixture.history.db.delete(VALIDATED).unwrap(),
        }
        let error = recover(&fixture).await.err().expect(case);
        assert!(
            error
                .to_string()
                .contains("finalized history ancestry mismatch"),
            "{case}: {error}"
        );
    }

    fixture
        .history
        .db
        .put(VALIDATED, marker(REVISIONS, head))
        .unwrap();
    fixture
        .history
        .db
        .put(HEAD, marker(REVISIONS, B256::repeat_byte(7)))
        .unwrap();
    let fixture = fixture.reopen();
    let error = recover(&fixture).await.err().expect("durable head");
    assert!(error.to_string().contains("ancestry mismatch"), "{error}");
    fixture
        .history
        .db
        .put(HEAD, marker(REVISIONS, head))
        .unwrap();
    let fixture = fixture.reopen();

    // A matching validated head does not reread the damaged record at start;
    // a lookup that reads it still refuses it.
    let short = recover(&fixture).await.unwrap();
    assert!(short.reads <= BOUNDED_READS);
    let error = fixture.history.execution_by_hash(first_id.0).unwrap_err();
    assert!(error.to_string().contains("differs from its query key"));
    let mut changed: Record =
        borsh::from_slice(&fixture.history.db.get(key(RECORD, 2)).unwrap().unwrap()).unwrap();
    changed.gas_limit += 1;
    fixture
        .history
        .db
        .put(key(RECORD, 2), borsh::to_vec(&changed).unwrap())
        .unwrap();
    let mut budget = usize::MAX;
    let error = fixture
        .history
        .execution_bounded(IndexQuery::Revision(2), &mut budget)
        .unwrap_err();
    assert!(error.to_string().contains("receipt commitment mismatch"));

    // Query mappings that need a rebuild read every record.
    fixture
        .history
        .db
        .put(QUERY_HEAD, marker(REVISIONS - 1, below))
        .unwrap();
    let error = recover(&fixture).await.err().expect("query head");
    assert!(error.to_string().contains("ancestry mismatch"), "{error}");
}

#[tokio::test]
async fn a_damaged_epoch_boundary_is_refused_before_its_material_is_restored() {
    // An epoch boundary below the resident window, which a validated start
    // reads for its material without rereading the chain around it.
    let boundary = EPOCH * 200 - 1;
    let rewrite = |fixture: &Heartbeats, height: u64, change: &dyn Fn(&mut Block)| {
        let stored = fixture
            .history
            .db
            .get(key(RECORD, height))
            .unwrap()
            .unwrap();
        let mut record: Record = borsh::from_slice(&stored).unwrap();
        let (mut block, _) = record.decode().unwrap();
        change(&mut block);
        record.block = block.encode().to_vec();
        fixture
            .history
            .db
            .put(key(RECORD, height), borsh::to_vec(&record).unwrap())
            .unwrap();
        block.id()
    };
    let other_epoch = |block: &mut Block| {
        let Some(Payload::EpochInfo(info)) = &mut block.payload else {
            panic!("the boundary carries its epoch");
        };
        info.epoch = commonware_consensus::types::Epoch::new(info.epoch.get() + 1);
    };

    // The record changed under the chain: the next record no longer names it.
    let fixture = heartbeats(REVISIONS, EPOCH);
    rewrite(&fixture, boundary, &other_epoch);
    let fixture = fixture.reopen();
    assert_eq!(
        validated(&fixture.history),
        Some(stored_head(&fixture.history))
    );
    let error = recover(&fixture).await.err().expect("boundary");
    assert!(error.to_string().contains("ancestry mismatch"), "{error}");

    // Even a boundary its next record names is refused when it carries
    // another epoch than the one its height ends.
    let fixture = heartbeats(REVISIONS, EPOCH);
    let renamed = rewrite(&fixture, boundary, &other_epoch);
    rewrite(&fixture, boundary + 1, &|block: &mut Block| {
        block.parent = renamed
    });
    let fixture = fixture.reopen();
    let error = recover(&fixture).await.err().expect("epoch");
    assert!(error.to_string().contains("names another epoch"), "{error}");
}

fn next_heartbeat(parent: &Block) -> Block {
    let mut next = block(parent.height + 1, parent.id());
    next.native_targets = [vera_domain::DbTarget::default(); 4];
    next.receipt_commitment = vera_executor::receipt_commitment(100, &[]);
    next
}

#[tokio::test]
async fn an_interrupted_append_never_leaves_the_validated_head_ahead_of_the_records() {
    for visible in [false, true] {
        let fixture = heartbeats(20, EPOCH);
        let next = next_heartbeat(&fixture.head);
        assert!(
            fixture
                .history
                .append_batch_with_write(
                    &next,
                    &[],
                    100,
                    FinalizedHistory::finalization_batch(21, None).unwrap(),
                    |db, batch| {
                        if visible {
                            write(db, batch)?;
                        }
                        anyhow::bail!("injected history write failure")
                    }
                )
                .is_err()
        );
        let mut fixture = fixture.reopen();
        assert_eq!(fixture.history.head_height(), 20 + u64::from(visible));
        assert_eq!(
            validated(&fixture.history),
            Some(stored_head(&fixture.history))
        );
        if visible {
            fixture.head = next;
        }
        assert!(
            fixture
                .history
                .validated_through(&fixture.genesis, fixture.head.height)
                .unwrap()
        );
        recover(&fixture).await.unwrap();
    }

    // Half of the append's log write reaches the file.
    let fixture = heartbeats(20, EPOCH);
    let Heartbeats {
        history,
        genesis,
        head,
        epoch_length,
        directory,
    } = fixture;
    drop(history);
    let (fault, env) = faulty(Phase::WalWrite);
    let history = FinalizedHistory {
        db: DB::open_for_test(directory.path(), env).unwrap(),
        head: Mutex::new((head.height, head.id())),
        metrics: None,
    };
    let next = next_heartbeat(&head);
    fault.armed.store(true, Ordering::SeqCst);
    assert!(history.append_finalized(&next, &[], 100, None).is_err());
    assert_eq!(fault.hits.load(Ordering::SeqCst), 1, "missing torn write");
    let fixture = Heartbeats {
        history,
        genesis,
        head,
        epoch_length,
        directory,
    }
    .reopen();
    assert_eq!(fixture.history.head_height(), 20);
    assert!(fixture.history.db.get(key(RECORD, 21)).unwrap().is_none());
    assert_eq!(
        validated(&fixture.history),
        Some(stored_head(&fixture.history))
    );
    assert!(
        fixture
            .history
            .validated_through(&fixture.genesis, 20)
            .unwrap()
    );
    recover(&fixture).await.unwrap();
    fixture.history.append(&next, &[], 100).unwrap();
    assert_eq!(validated(&fixture.history), Some(marker(21, next.id().0)));
}

#[tokio::test]
async fn cuts_and_recoveries_below_the_head_keep_the_validated_head_on_checked_records() {
    let fixture = heartbeats(40, EPOCH);
    let no_lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
    let block_at = |height| fixture.history.stored_block(height).unwrap().unwrap();
    let thirtieth = block_at(30);
    fixture
        .history
        .recover(
            &fixture.genesis,
            &thirtieth,
            &BlockIndex::new(),
            &fixture.epochs(),
            &no_lookup,
        )
        .await
        .unwrap();
    assert_eq!(
        validated(&fixture.history),
        Some(marker(30, thirtieth.id().0))
    );
    assert_eq!(stored_head(&fixture.history), marker(30, thirtieth.id().0));

    fixture.history.rewind_to(20).unwrap();
    let twentieth = block_at(20);
    assert_eq!(
        validated(&fixture.history),
        Some(marker(20, twentieth.id().0))
    );
    assert_eq!(stored_head(&fixture.history), marker(20, twentieth.id().0));

    // A validated head below the cut stays there.
    let tenth = block_at(10);
    fixture
        .history
        .db
        .put(VALIDATED, marker(10, tenth.id().0))
        .unwrap();
    fixture.history.rewind_to(15).unwrap();
    assert_eq!(validated(&fixture.history), Some(marker(10, tenth.id().0)));
    let fifteenth = block_at(15);
    assert!(
        !fixture
            .history
            .validated_through(&fixture.genesis, 15)
            .unwrap()
    );
    fixture
        .history
        .recover(
            &fixture.genesis,
            &fifteenth,
            &BlockIndex::new(),
            &fixture.epochs(),
            &no_lookup,
        )
        .await
        .unwrap();
    assert_eq!(
        validated(&fixture.history),
        Some(marker(15, fifteenth.id().0))
    );
}
