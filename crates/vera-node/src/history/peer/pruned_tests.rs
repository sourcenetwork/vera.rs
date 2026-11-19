//! A peer's answer for history below its floor.

use super::*;
use crate::history::transfer::tests::revision;
use alloy_primitives::B256;
use vera_domain::BlockId;

#[test]
fn a_refusal_names_the_floor_and_is_never_a_chunk() {
    let refusal = encode_pruned(9);
    assert_eq!(
        decode_pruned(&refusal, 3),
        Some(HistoryPruned {
            height: 3,
            floor: 9
        })
    );
    assert!(decode_chunk(&refusal, 0).is_err());
    let chunk = [3u64.to_be_bytes(), 0u64.to_be_bytes()].concat();
    assert_eq!(
        decode_pruned(&[chunk.as_slice(), &[1, 2, 3]].concat(), 3),
        None
    );
    assert_eq!(decode_pruned(&refusal[..15], 3), None);
}

#[test]
fn records_and_proofs_below_the_floor_are_refused_as_pruned() {
    let directory = tempfile::tempdir().unwrap();
    let (genesis, _) = revision(0, BlockId(B256::ZERO));
    let history = Arc::new(FinalizedHistory::open(directory.path(), &genesis).unwrap());
    let mut parent = genesis.id();
    for height in 1..=6 {
        let (next, receipts) = revision(height, parent);
        history.append(&next, &receipts, 100).unwrap();
        parent = next.id();
    }
    let epoch_length = std::num::NonZeroU64::new(4).unwrap();
    history.prune_below(4, epoch_length).unwrap();
    let producer = HistoryProducer::new(history, Arc::new(LightBlockIndex::new(epoch_length)));
    for kind in [0, 1] {
        let error = producer.chunk(kind, 2, 0).unwrap_err();
        assert_eq!(
            error.downcast_ref::<HistoryPruned>(),
            Some(&HistoryPruned {
                height: 2,
                floor: 4
            }),
            "resource {kind}"
        );
    }
    // The floor's parent is served, so that an importer can adopt the floor.
    assert!(producer.chunk(0, 3, 0).is_ok());
    assert!(producer.chunk(0, 4, 0).is_ok());
}
