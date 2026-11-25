//! What a proof over the longest ancestry span costs on a populated history.

use super::super::ancestry::MAX_ANCESTRY_SPAN;
use super::*;
use std::time::Instant;

/// Bytes of the one submission every revision carries.
const SUBMISSION_BYTES: usize = 16 << 10;

/// `ANCESTRY_COST_SUBMISSION_BYTES` sets the submission size, 16 KiB by default.
#[test]
#[ignore = "ancestry proof cost is measured on demand with a release build"]
fn ancestry_proof_cost_over_the_longest_span() {
    let bytes = std::env::var("ANCESTRY_COST_SUBMISSION_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(SUBMISSION_BYTES);
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
    history.db.skip_sync_for_test();
    let mut parent = genesis.clone();
    for height in 1..=MAX_ANCESTRY_SPAN {
        let mut next = block(height, parent.id());
        next.ancestry = parent
            .ancestry
            .extended(parent.height, &parent.id())
            .unwrap();
        // Pseudo-random bytes, so that the store cannot compress them away.
        let mut state = height.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let payload: Vec<u8> = (0..bytes)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        next.txs.push(vera_domain::Tx::new(payload.into()));
        let receipt = ExecutionReceipt::new(
            B256::left_padding_from(&height.to_be_bytes()),
            true,
            3,
            3,
            vec![],
        );
        next.receipt_commitment =
            vera_executor::receipt_commitment(100, std::slice::from_ref(&receipt));
        history
            .append_finalized(&next, std::slice::from_ref(&receipt), 100, None)
            .unwrap();
        parent = next;
    }
    drop(history);
    let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
    for pass in ["cold", "warm"] {
        let started = Instant::now();
        let proof = history.ancestry_proof(0, MAX_ANCESTRY_SPAN).unwrap();
        let seconds = started.elapsed().as_secs_f64();
        assert!(parent.has_ancestor(0, &genesis.id(), &proof));
        println!(
            "{pass}: span {MAX_ANCESTRY_SPAN}, submission {bytes} B, {seconds:.3} s, store {} MiB",
            super::start_cost_tests::directory_bytes(directory.path()) >> 20,
        );
    }
}
