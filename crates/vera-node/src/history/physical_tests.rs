use super::*;
use std::{fs, io::Write as _, path::PathBuf};

#[derive(Clone, Copy)]
enum Damage {
    FooterBitFlip,
    TruncatedFooter,
}

fn table_path(directory: &Path) -> PathBuf {
    let directory = &directory.join("regolith/sst");
    let mut tables = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|suffix| suffix == "sst")
        })
        .map(|entry| {
            assert!(entry.file_type().unwrap().is_file());
            entry.path()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tables.len(),
        1,
        "compacted fixture must have one history table"
    );
    tables.pop().unwrap()
}

fn replace_table(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    assert_eq!(
        fs::read(path).unwrap(),
        bytes,
        "damage must reach the actual file"
    );
}

async fn physical_damage_is_rejected(damage: Damage) {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let mut first = block(1, genesis.id());
    first.native_targets = Some([vera_domain::DbTarget::default(); 4]);
    first.receipt_commitment = Some(vera_executor::receipt_commitment(100, &[]));
    let mut second = block(2, first.id());
    second.native_targets = first.native_targets;
    second.receipt_commitment = first.receipt_commitment;
    let originals;
    {
        let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        history
            .append_finalized(&first, &[], 100, Some(&artifacts(1)))
            .unwrap();
        history
            .append_finalized(&second, &[], 100, Some(&artifacts(2)))
            .unwrap();
        originals = [1, 2].map(|height| history.db.get(key(RECORD, height)).unwrap().unwrap());
        history.db.compact_for_test().unwrap();
    }
    let path = table_path(directory.path());
    let pristine = fs::read(&path).unwrap();
    assert!(
        pristine.len() >= 72,
        "fixture must contain a complete table footer"
    );
    let mut damaged = pristine.clone();
    match damage {
        Damage::FooterBitFlip => *damaged.last_mut().unwrap() ^= 1,
        Damage::TruncatedFooter => damaged.truncate(damaged.len() - 8),
    }
    assert_ne!(damaged, pristine);
    replace_table(&path, &damaged);

    let index = BlockIndex::new();
    let light = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
    let lookup: FinalizationLookup =
        Arc::new(|_| panic!("damaged history must not reach certificate lookup"));
    let error = match FinalizedHistory::open(directory.path(), &genesis) {
        Ok(history) => history
            .recover(&genesis, &second, &index, &light, &lookup)
            .await
            .unwrap_err(),
        Err(error) => error,
    };
    let message = format!("{error:#}").to_ascii_lowercase();
    assert!(
        message.contains("corrupt") || message.contains("sstable") || message.contains("magic"),
        "recovery failure must identify physical table damage"
    );
    assert_eq!(index.head_block_number(), 0);
    for block in [&first, &second] {
        assert!(index.get_block_by_number(block.height).is_none());
        assert!(light.get_finalization(&block.digest().0).is_none());
    }

    replace_table(&path, &pristine);
    let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
    history
        .recover(&genesis, &second, &index, &light, &lookup)
        .await
        .unwrap();
    assert_eq!(history.head_height(), 2);
    assert_eq!(index.head_block_number(), 2);
    for (block, original) in [&first, &second].into_iter().zip(originals) {
        assert_eq!(
            history.db.get(key(RECORD, block.height)).unwrap().unwrap(),
            original
        );
        assert_eq!(
            index.get_block_by_number(block.height).unwrap().hash,
            block.id().0
        );
        assert_eq!(
            light.get_finalization(&block.digest().0).unwrap().bytes,
            artifacts(block.height).finalization
        );
    }
    let third = block(3, second.id());
    history
        .append_finalized(&third, &[], 100, Some(&artifacts(3)))
        .unwrap();
    assert_eq!(history.head_height(), 3);
}

#[tokio::test]
async fn physical_table_bit_flip_is_rejected_before_history_publication() {
    physical_damage_is_rejected(Damage::FooterBitFlip).await;
}

#[tokio::test]
async fn physical_table_truncation_is_rejected_before_history_publication() {
    physical_damage_is_rejected(Damage::TruncatedFooter).await;
}
