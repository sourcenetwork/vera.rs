use alloy_primitives::{B256, Bytes, Log, keccak256};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::{Block, BlockId, NativeTx, Tx};
use vera_executor::ExecutionReceipt;
use vera_indexer::BlockIndex;

use super::index_finalized_block;

const GAS_LIMIT: u64 = 30_000_000;

fn log(marker: u8) -> Log {
    Log::new_unchecked(
        ACP_ADDRESS,
        vec![B256::repeat_byte(marker)],
        Bytes::from(vec![marker]),
    )
}

struct Fixture {
    block: Block,
    receipts: Vec<ExecutionReceipt>,
    hashes: Vec<B256>,
    signer_did: String,
}

/// Two signed requests followed by bytes that carry the native tag but do not decode.
fn fixture() -> Fixture {
    let signer = BlsSigner::from_secret_bytes(&[7; 32], 1, 0).unwrap();
    let wires: Vec<Vec<u8>> = (0..2)
        .map(|_| {
            signer
                .sign_native_tx(ACP_ADDRESS, vec![0xab; 64].into())
                .unwrap()
        })
        .collect();
    let undecodable = vec![wires[0][0], 0xff];
    let mut hashes: Vec<B256> = wires
        .iter()
        .map(|wire| NativeTx::decode_wire(wire).unwrap().tx_id().0)
        .collect();
    hashes.push(keccak256(&undecodable));
    let block = Block {
        context: Block::genesis_context(),
        parent: BlockId(B256::ZERO),
        height: 1,
        timestamp: 1_800_000_000,
        term: 0,
        module_state_root: B256::ZERO,
        txs: wires
            .into_iter()
            .chain([undecodable])
            .map(|bytes| Tx::new(bytes.into()))
            .collect(),
        payload: None,
        native_targets: Default::default(),
        receipt_commitment: alloy_primitives::B256::ZERO,
    };
    // Receipts follow execution order, which need not be block order.
    let receipts = vec![
        ExecutionReceipt::new(hashes[1], true, 1, 1, vec![log(3)], None),
        ExecutionReceipt::new(hashes[0], true, 1, 2, vec![log(1), log(2)], None),
    ];
    Fixture {
        block,
        receipts,
        hashes,
        signer_did: signer.did().to_owned(),
    }
}

#[test]
fn indexing_returns_the_hashes_it_stored_and_names_each_signer() {
    let fixture = fixture();
    let index = BlockIndex::new();

    let hashes = index_finalized_block(
        &index,
        &fixture.block,
        fixture.block.id().0,
        GAS_LIMIT,
        &fixture.receipts,
        2,
    );

    assert_eq!(hashes, fixture.hashes);
    let indexed = index.get_block_by_number(1).unwrap();
    assert_eq!(indexed.transaction_hashes, fixture.hashes);
    assert_eq!(indexed.timestamp, fixture.block.timestamp);
    assert_eq!(indexed.gas_limit, GAS_LIMIT);
    for hash in &fixture.hashes[..2] {
        let transaction = index.get_transaction(hash).unwrap();
        assert_eq!(transaction.signer_did, fixture.signer_did);
        assert_eq!(transaction.target, ACP_ADDRESS);
        let receipt = index.get_receipt(hash).unwrap();
        assert_eq!(receipt.signer_did, fixture.signer_did);
        assert_eq!(receipt.target, ACP_ADDRESS);
        assert_eq!(receipt.nonce, transaction.nonce);
    }
    assert!(index.get_transaction(&fixture.hashes[2]).is_none());
}

#[test]
fn indexing_keeps_why_a_native_request_was_refused() {
    let mut fixture = fixture();
    let refusal = vera_domain::Refusal::new(
        vera_domain::RefusingModule::Acp,
        vera_domain::RefusalKind::InvalidPolicy,
        "invalid policy",
    );
    fixture.receipts[0] =
        ExecutionReceipt::new(fixture.hashes[1], false, 5_000, 5_000, vec![], None)
            .with_refusal(Some(refusal.clone()));
    let index = BlockIndex::new();
    index_finalized_block(
        &index,
        &fixture.block,
        fixture.block.id().0,
        GAS_LIMIT,
        &fixture.receipts,
        5_001,
    );
    let refused = index.get_receipt(&fixture.hashes[1]).unwrap();
    assert!(!refused.status);
    assert_eq!(refused.refusal, Some(refusal));
    assert_eq!(index.get_receipt(&fixture.hashes[0]).unwrap().refusal, None);
}

#[test]
fn logs_are_numbered_by_block_position() {
    let fixture = fixture();
    let index = BlockIndex::new();
    index_finalized_block(
        &index,
        &fixture.block,
        fixture.block.id().0,
        GAS_LIMIT,
        &fixture.receipts,
        2,
    );
    let summary: Vec<_> = fixture.hashes[..2]
        .iter()
        .flat_map(|hash| index.get_receipt(hash).unwrap().logs)
        .map(|log| (log.log_index, log.transaction_index, log.data[0]))
        .collect();
    assert_eq!(summary, vec![(0, 0, 1), (1, 0, 2), (2, 1, 3)]);
}
