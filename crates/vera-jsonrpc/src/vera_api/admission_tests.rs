use super::*;
use crate::error::codes;
use std::time::Duration;

#[tokio::test]
async fn proof_admission_is_shared_and_released_on_errors() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let api = VeraApiImpl::new(Arc::new(state.as_ref().clone()), None);
    let mut permits: Vec<_> = (0..8).map(|_| state.proof_permit().unwrap()).collect();
    let error = api
        .get_current_record_proof(ModuleId::Acp, Bytes::new(), U64::ZERO)
        .await
        .unwrap_err();
    assert_eq!(error.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(error.data().unwrap().get(), r#"{"retryable":true}"#);
    assert_eq!(
        api.get_receipt_proof(B256::ZERO).await.unwrap_err().code(),
        codes::RESOURCE_UNAVAILABLE
    );
    drop(permits.pop());
    for _ in 0..2 {
        let error = api
            .get_current_record_proof(ModuleId::Acp, Bytes::new(), U64::ZERO)
            .await
            .unwrap_err();
        assert_eq!(error.code(), codes::RESOURCE_UNAVAILABLE);
    }
    assert!(state.proof_permit().is_ok());
}

#[tokio::test]
async fn cancelled_lookup_keeps_its_permit_until_blocking_work_finishes() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let _held: Vec<_> = (0..7)
        .map(|_| state.light_lookup_permit().unwrap())
        .collect();
    let (release, receiver) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(receiver);
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let api = Arc::new(
        VeraApiImpl::new(state.clone(), None).with_light_block_lookup(Arc::new(move |_| {
            signal.notify_one();
            receiver
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Err("finished".into())
        })),
    );
    let running = api.clone();
    let task = tokio::spawn(async move { running.get_light_block(U64::from(1)).await });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        api.get_light_block(U64::from(1)).await.unwrap_err().code(),
        codes::RESOURCE_UNAVAILABLE
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.light_lookup_permit().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn receipt_poll_does_not_wait_for_a_missing_certificate() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vera_indexer::{IndexedBlock, IndexedReceipt};

    let hash = B256::repeat_byte(1);
    let index = Arc::new(BlockIndex::new());
    index.insert_block(
        IndexedBlock {
            hash,
            number: 1,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: 1,
            gas_limit: 100,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: B256::ZERO,
            transaction_hashes: vec![hash],
        },
        vec![],
        vec![IndexedReceipt {
            transaction_hash: hash,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            from: alloy_primitives::Address::ZERO,
            to: None,
            cumulative_gas_used: 0,
            gas_used: 0,
            contract_address: None,
            logs: vec![],
            status: true,
            signer_did: None,
        }],
    );
    let lookups = Arc::new(AtomicUsize::new(0));
    let calls = lookups.clone();
    let state = Arc::new(NodeState::new(1, 0, 1));
    let mut api =
        VeraApiImpl::new(state.clone(), None).with_light_block_lookup(Arc::new(move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            Err("finalization certificate not found".into())
        }));
    api.index = Some(index);
    let _waiting: Vec<_> = (0..8)
        .map(|_| state.permission_read_permit().unwrap())
        .collect();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), api.get_receipt_proof(hash))
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(lookups.load(Ordering::Relaxed), 1);
    let permits: Vec<_> = (0..8).map(|_| state.proof_permit().unwrap()).collect();
    assert!(api.get_receipt_proof(B256::ZERO).await.unwrap().is_none());
    let busy = api.get_receipt_proof(hash).await.unwrap_err();
    assert_eq!(busy.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(busy.data().unwrap().get(), r#"{"retryable":true}"#);
    assert_eq!(lookups.load(Ordering::Relaxed), 1);
    drop(permits);
    api.light_block_lookup = Some(Arc::new(|_| Err("corrupt certificate".into())));
    assert!(
        api.get_receipt_proof(hash)
            .await
            .unwrap_err()
            .message()
            .contains("corrupt certificate")
    );
}

#[tokio::test]
async fn archived_receipt_waits_for_published_revision() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let index = Arc::new(BlockIndex::new());
    let mut api = VeraApiImpl::new(state, None).with_receipt_proof_lookup(Arc::new(|_| {
        Ok(Some(vera_domain::ReceiptResponse {
            revision: vera_domain::LightBlock {
                block_hash: String::new(),
                parent_hash: String::new(),
                height: 1,
                timestamp: 1,
                state_root: String::new(),
                module_state_root: String::new(),
                epoch: 0,
                view: 0,
                parent_view: 0,
                block: String::new(),
                descendants: vec![],
                finalization: String::new(),
                epoch_material: String::new(),
            },
            gas_limit: 100,
            receipts: vec![],
        }))
    }));
    api.index = Some(index.clone());
    assert!(api.get_receipt_proof(B256::ZERO).await.unwrap().is_none());
    index.insert_block(
        vera_indexer::IndexedBlock {
            hash: B256::repeat_byte(1),
            number: 1,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: 1,
            gas_limit: 100,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: B256::ZERO,
            transaction_hashes: vec![],
        },
        vec![],
        vec![],
    );
    assert_eq!(
        api.get_receipt_proof(B256::ZERO)
            .await
            .unwrap()
            .unwrap()
            .revision
            .height,
        1
    );
}

#[tokio::test]
async fn cancelled_archive_receipt_keeps_blocking_lookup_bounded() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let _held: Vec<_> = (0..7)
        .map(|_| state.light_lookup_permit().unwrap())
        .collect();
    let (release, receiver) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(receiver);
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let mut api =
        VeraApiImpl::new(state.clone(), None).with_receipt_proof_lookup(Arc::new(move |_| {
            signal.notify_one();
            receiver
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Ok(None)
        }));
    api.index = Some(Arc::new(BlockIndex::new()));
    let api = Arc::new(api);
    let running = api.clone();
    let task = tokio::spawn(async move { running.get_receipt_proof(B256::ZERO).await });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        api.get_receipt_proof(B256::ZERO).await.unwrap_err().code(),
        codes::RESOURCE_UNAVAILABLE
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.light_lookup_permit().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn evidence_deadline_is_a_retryable_error() {
    use vera_indexer::{IndexedBlock, IndexedReceipt};

    let hash = B256::repeat_byte(3);
    let index = Arc::new(BlockIndex::new());
    index.insert_block(
        IndexedBlock {
            hash,
            number: 1,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: 1,
            gas_limit: 100,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: B256::ZERO,
            transaction_hashes: vec![hash],
        },
        vec![],
        vec![IndexedReceipt {
            transaction_hash: hash,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            from: alloy_primitives::Address::ZERO,
            to: None,
            cumulative_gas_used: 0,
            gas_used: 0,
            contract_address: None,
            logs: vec![],
            status: true,
            signer_did: None,
        }],
    );
    let (release, receiver) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(receiver);
    let state = Arc::new(NodeState::new(1, 0, 1));
    let mut api = VeraApiImpl::new(state, None).with_light_block_lookup(Arc::new(move |_| {
        receiver
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        Err("finished".into())
    }));
    api.index = Some(index);
    let started = std::time::Instant::now();
    let error = api.get_receipt_proof(hash).await.unwrap_err();
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(error.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(error.data().unwrap().get(), r#"{"retryable":true}"#);
    assert_eq!(error.message(), "receipt finality deadline exceeded");
    release.send(()).unwrap();
}

#[tokio::test]
async fn current_permission_admission_is_bounded_and_released_on_validation_error() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let api = VeraApiImpl::new(state.clone(), None);
    let request = || AccessRequest {
        actor: vera_permission::Actor(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                .parse()
                .unwrap(),
        ),
        operations: vec![],
    };
    let mut waiting: Vec<_> = (0..8)
        .map(|_| state.permission_read_permit().unwrap())
        .collect();
    let busy = api
        .get_current_permission_proof("policy".into(), request(), U64::ZERO)
        .await
        .unwrap_err();
    assert_eq!(busy.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(busy.data().unwrap().get(), r#"{"retryable":true}"#);
    let _proofs: Vec<_> = (0..8).map(|_| state.proof_permit().unwrap()).collect();
    drop(waiting.pop());
    for _ in 0..2 {
        let invalid = api
            .get_current_permission_proof("policy".into(), request(), U64::ZERO)
            .await
            .unwrap_err();
        assert_eq!(invalid.code(), codes::INVALID_PARAMS);
    }
    assert!(state.permission_read_permit().is_ok());
}
