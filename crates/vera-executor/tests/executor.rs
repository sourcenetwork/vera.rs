//! Integration tests for vera-executor.

use alloy_primitives::{Address, B256, Bytes};
use rstest::rstest;
use vera_executor::{BlockContext, VeraExecutor};

#[rstest]
#[case(1)]
#[case(137)]
#[case(42161)]
fn an_empty_block_has_an_empty_outcome(#[case] chain_id: u64) {
    let executor = VeraExecutor::new(chain_id);
    let (outcome, _) = executor
        .execute_with_modules(&BlockContext::new(0, 0, 0), &[], executor.snapshot())
        .expect("execution should succeed");
    assert!(outcome.receipts.is_empty());
    assert_eq!(outcome.gas_used, 0);
}

#[path = "executor/native_call.rs"]
mod native_call;

#[path = "executor/registry.rs"]
mod registry;

#[path = "executor/block_gas.rs"]
mod block_gas;

#[path = "executor/record_limits.rs"]
mod record_limits;

#[path = "executor/native_refusals.rs"]
mod native_refusals;

#[path = "executor/anchors.rs"]
mod anchors;
