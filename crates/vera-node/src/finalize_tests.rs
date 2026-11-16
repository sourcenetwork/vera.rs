use alloy_primitives::{Address, B256, Bytes, Log, U64, U256, keccak256};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::{Block, BlockId, DbTargets, NativeTx, StateRoot, Tx};
use vera_executor::ExecutionReceipt;
use vera_indexer::BlockIndex;
use vera_jsonrpc::BlockTransactions;

use super::{index_finalized_block, subscription_data};

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
        prevrandao: B256::repeat_byte(3),
        randomness: None,
        state_root: StateRoot(B256::ZERO),
        module_state_root: B256::ZERO,
        txs: wires
            .into_iter()
            .chain([undecodable])
            .map(|bytes| Tx::new(bytes.into()))
            .collect(),
        payload: None,
        native_targets: None,
        receipt_commitment: None,
        db_targets: DbTargets::default(),
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
    assert_eq!(indexed.base_fee_per_gas, Some(0));
    for hash in &fixture.hashes[..2] {
        let transaction = index.get_transaction(hash).unwrap();
        assert_eq!(
            transaction.signer_did.as_deref(),
            Some(fixture.signer_did.as_str())
        );
        assert_eq!(transaction.from, Address::ZERO);
        assert_eq!(
            index.get_receipt(hash).unwrap().signer_did.as_deref(),
            Some(fixture.signer_did.as_str())
        );
    }
    assert!(index.get_transaction(&fixture.hashes[2]).is_none());
}

#[test]
fn subscription_data_orders_logs_by_block_position_from_the_given_hashes() {
    let fixture = fixture();

    let (head, logs) = subscription_data(
        &fixture.block,
        fixture.block.id().0,
        GAS_LIMIT,
        &fixture.receipts,
        2,
        &fixture.hashes,
    );

    assert!(matches!(
        &head.transactions,
        BlockTransactions::Hashes(hashes) if *hashes == fixture.hashes
    ));
    assert_eq!(head.hash, fixture.block.id().0);
    assert_eq!(head.timestamp, U64::from(fixture.block.timestamp));
    assert_eq!(head.gas_limit, U64::from(GAS_LIMIT));
    assert_eq!(head.base_fee_per_gas, Some(U256::ZERO));
    let summary: Vec<_> = logs
        .iter()
        .map(|log| {
            (
                log.log_index,
                log.transaction_index,
                log.transaction_hash,
                log.data[0],
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (U64::from(0), U64::from(0), fixture.hashes[0], 1),
            (U64::from(1), U64::from(0), fixture.hashes[0], 2),
            (U64::from(2), U64::from(1), fixture.hashes[1], 3),
        ]
    );
}
