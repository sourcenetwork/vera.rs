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
            transaction_hashes: vec![submission],
        },
        vec![],
        vec![IndexedReceipt {
            transaction_hash: submission,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            target: alloy_primitives::Address::ZERO,
            nonce: 0,
            cumulative_gas_used: 5_000,
            gas_used: 5_000,
            logs: vec![],
            status: false,
            signer_did: "did:key:signer".into(),
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
        assert!(!receipt.success);
        assert_eq!(receipt.signer_did, "did:key:signer");
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

#[tokio::test]
async fn node_status_reports_the_execution_index_head_apart_from_finality() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let mut api = VeraApiImpl::new(state.clone(), None);
    assert_eq!(api.node_status().await.unwrap().head_height, None);

    api.index = Some(refused_revision(
        B256::repeat_byte(1),
        &Refusal::new(RefusingModule::Acp, RefusalKind::InvalidPolicy, "refused"),
    ));
    let status = api.node_status().await.unwrap();
    assert_eq!(status.head_height, Some(1));
    assert_eq!(status.finalized_height, None);
}

#[tokio::test]
async fn an_archived_receipt_matches_the_resident_one_and_archive_failures_propagate() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let submission = B256::repeat_byte(8);
    let refusal = Refusal::new(
        RefusingModule::Acp,
        RefusalKind::Unauthorized,
        "not the owner",
    );
    let state = Arc::new(NodeState::new(1, 0, 1));
    let retained = refused_revision(submission, &refusal);

    let mut resident = VeraApiImpl::new(state.clone(), None);
    resident.index = Some(retained.clone());
    let expected = resident
        .get_transaction_receipt(submission)
        .await
        .unwrap()
        .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let reader = |state: &NodeState| {
        let (calls, retained) = (calls.clone(), retained.clone());
        crate::ArchiveReader::new(
            state.clone(),
            Arc::new(move |query, remaining_bytes| {
                calls.fetch_add(1, Ordering::Relaxed);
                assert_eq!(*remaining_bytes, 64 << 20);
                Ok(
                    matches!(query, IndexQuery::Submission(hash) if hash == submission)
                        .then(|| retained.clone()),
                )
            }),
        )
    };
    let mut evicted = VeraApiImpl::new(state.clone(), None).with_archive(reader(&state));
    evicted.index = Some(Arc::new(BlockIndex::new()));
    let actual = evicted
        .get_transaction_receipt(submission)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert!(
        evicted
            .get_transaction_receipt(B256::ZERO)
            .await
            .unwrap()
            .is_none()
    );

    let held: Vec<_> = (0..8)
        .map(|_| state.light_lookup_permit().unwrap())
        .collect();
    let busy = evicted
        .get_transaction_receipt(submission)
        .await
        .unwrap_err();
    assert_eq!(busy.code(), crate::error::codes::RESOURCE_UNAVAILABLE);
    assert_eq!(busy.data().unwrap().get(), r#"{"retryable":true}"#);
    drop(held);

    let mut broken = VeraApiImpl::new(state.clone(), None).with_archive(crate::ArchiveReader::new(
        (*state).clone(),
        Arc::new(|_, _| Err(RpcError::StateError("unready archive".into()))),
    ));
    broken.index = Some(Arc::new(BlockIndex::new()));
    assert!(
        broken
            .get_transaction_receipt(submission)
            .await
            .unwrap_err()
            .message()
            .contains("unready archive")
    );
}
