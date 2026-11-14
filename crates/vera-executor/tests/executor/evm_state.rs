//! EVM state changes as the backend stores and reloads them.

use alloy_primitives::{Address, Bytes, TxKind, U256, keccak256};
use vera_traits::StateDbRead as _;

use super::{
    MockStateDb,
    rollback::{execute, install},
};

/// PUSH1 42, PUSH1 0, SSTORE: runtime code that does not end in STOP.
const RUNTIME: [u8; 5] = [0x60, 0x2a, 0x60, 0x00, 0x55];

fn initcode() -> Bytes {
    let mut code = vec![0x64];
    code.extend_from_slice(&RUNTIME);
    // MSTORE(0, runtime) right-aligns the five bytes at offset 27; RETURN(27, 5).
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x05, 0x60, 0x1b, 0xf3]);
    code.into()
}

/// SSTORE(0, EXTCODESIZE(target)).
fn measure(target: Address) -> Bytes {
    let mut code = vec![0x73];
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[0x3b, 0x60, 0x00, 0x55, 0x00]);
    code.into()
}

#[test]
fn deployed_code_is_stored_as_deployed_and_keeps_its_size_after_reload() {
    let state = MockStateDb::new();
    let (outcome, _) = execute(&state, TxKind::Create, initcode());
    assert!(outcome.receipts[0].success());
    let contract = outcome.receipts[0].contract_address.expect("contract");
    state.commit(outcome.changes);

    let code_hash = futures::executor::block_on(state.code_hash(&contract)).unwrap();
    let stored = futures::executor::block_on(state.code(&code_hash)).unwrap();
    assert_eq!(stored.as_ref(), RUNTIME);
    assert_eq!(keccak256(&stored), code_hash);

    let probe = Address::repeat_byte(0x77);
    install(&state, probe, measure(contract));
    let (outcome, _) = execute(&state, TxKind::Call(probe), Bytes::new());
    assert!(outcome.receipts[0].success());
    assert_eq!(
        outcome.changes.accounts[&probe].storage.get(&U256::ZERO),
        Some(&U256::from(RUNTIME.len()))
    );
}

#[test]
fn a_slot_that_is_only_read_is_not_written_back() {
    let state = MockStateDb::new();
    let reader = Address::repeat_byte(0x78);
    // SLOAD(0), POP, STOP.
    install(
        &state,
        reader,
        Bytes::from_static(&[0x60, 0x00, 0x54, 0x50, 0x00]),
    );
    let (outcome, _) = execute(&state, TxKind::Call(reader), Bytes::new());
    assert!(outcome.receipts[0].success());
    assert!(outcome.changes.accounts[&reader].storage.is_empty());
}
