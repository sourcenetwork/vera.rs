use super::*;
use vera_domain::{Refusal, RefusalKind, RefusingModule};
use vera_indexer::{IndexQuery, IndexedBlock, IndexedReceipt};

fn refused_revision(submission: B256, refusal: &Refusal) -> Arc<BlockIndex> {
    let index = Arc::new(BlockIndex::new());
    let hash = B256::repeat_byte(2);
    index.insert_block(
        IndexedBlock {
            hash,
            number: 1,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: 1,
            gas_limit: 1_000_000,
            gas_used: 5_000,
            base_fee_per_gas: None,
            transaction_hashes: vec![submission],
        },
        vec![],
        vec![IndexedReceipt {
            transaction_hash: submission,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            from: alloy_primitives::Address::ZERO,
            to: None,
            cumulative_gas_used: 5_000,
            gas_used: 5_000,
            contract_address: None,
            logs: vec![],
            status: false,
            signer_did: Some("did:key:signer".into()),
            refusal: Some(refusal.clone()),
        }],
    );
    index
}

#[tokio::test]
async fn recent_and_archived_receipts_name_the_same_refusal() {
    let submission = B256::repeat_byte(1);
    let refusal = Refusal::new(
        RefusingModule::Acp,
        RefusalKind::InvalidPolicy,
        "invalid policy: unknown relation 'reader'",
    );
    let state = Arc::new(NodeState::new(1, 0, 1));

    let mut recent = VeraApiImpl::new(state.clone(), None);
    recent.index = Some(refused_revision(submission, &refusal));
    let recent = recent
        .get_transaction_receipt(submission)
        .await
        .unwrap()
        .unwrap();

    let archived_index = refused_revision(submission, &refusal);
    let mut archived =
        VeraApiImpl::new(state.clone(), None).with_archive(crate::ArchiveReader::new(
            (*state).clone(),
            Arc::new(move |query, _| {
                Ok(
                    matches!(query, IndexQuery::Submission(hash) if hash == submission)
                        .then(|| archived_index.clone()),
                )
            }),
        ));
    archived.index = Some(Arc::new(BlockIndex::new()));
    let archived = archived
        .get_transaction_receipt(submission)
        .await
        .unwrap()
        .unwrap();

    for receipt in [&recent, &archived] {
        assert_eq!(receipt.status, U64::ZERO);
        assert_eq!(receipt.gas_used, U64::from(5_000));
        assert_eq!(receipt.refusal.as_ref(), Some(&refusal));
    }
    let json = serde_json::to_value(&archived).unwrap();
    assert_eq!(
        json["refusal"],
        serde_json::json!({
            "module": "acp",
            "kind": "invalid_policy",
            "message": "invalid policy: unknown relation 'reader'",
        })
    );
}
