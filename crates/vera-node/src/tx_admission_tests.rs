use super::*;
use alloy_primitives::FixedBytes;
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::{Signer as _, ed25519};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_p2p::{CheckedSender, LimitedSender};
use commonware_runtime::{
    IoBufs, Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio as runtime,
};
use commonware_utils::{NZU16, NZUsize};
use futures::FutureExt as _;
use std::time::{Duration, SystemTime};
use vera_backend::{VeraStateSet, state_set_config};
use vera_crypto::bls;
use vera_executor::{ExecutionConfig, precompiles::ACP_ADDRESS};

const CHAIN_ID: u64 = 9001;

#[derive(Clone, Default)]
struct RecordingSender(Arc<parking_lot::Mutex<Vec<Vec<u8>>>>);

impl LimitedSender for RecordingSender {
    type PublicKey = ed25519::PublicKey;
    type Checked<'a> = Self;

    fn check(&mut self, recipients: Recipients<Self::PublicKey>) -> Result<Self, SystemTime> {
        assert!(matches!(recipients, Recipients::All));
        Ok(self.clone())
    }
}

impl CheckedSender for RecordingSender {
    type PublicKey = ed25519::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        vec![ed25519::PrivateKey::from_seed(1).public_key()]
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        assert!(!priority);
        self.0
            .lock()
            .push(message.into().coalesce().as_ref().to_vec());
        Unreliable::new(Feedback::Ok)
    }
}

fn signed_request(nonce: u64) -> Bytes {
    let mut request = NativeTx {
        chain_id: CHAIN_ID,
        nonce,
        // The compressed G1 generator is the public key for scalar one.
        bls_pubkey: alloy_primitives::hex!(
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        )
        .into(),
        target: ACP_ADDRESS,
        calldata: Bytes::new(),
        signature: FixedBytes::ZERO,
    };
    request.signature =
        FixedBytes::from_slice(&bls::sign(&1u64.into(), &request.signing_data()).unwrap());
    request.encode_wire().into()
}

#[test]
fn concurrent_duplicate_submissions_preserve_nonces_and_local_retry_tracking() {
    let directory = tempfile::tempdir().unwrap();
    runtime::Runner::new(runtime::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                let cache = CacheRef::new(NZU16!(4084), NZUsize!(64));
                let databases = VeraStateSet::init(
                    context.child("admission_state"),
                    state_set_config("admission", cache),
                    None,
                )
                .await;
                let state = CommittedState::new(databases);
                let validator: SharedValidator = Arc::new(OnceLock::new());
                validator
                    .set(Mutex::new(Admission::new(
                        MempoolValidator::new(state.clone(), ExecutionConfig::new(CHAIN_ID), 0)
                            .with_native_only(true),
                    )))
                    .unwrap();
                let pool = InMemoryMempool::new();
                let sender = RecordingSender::default();
                let gossip = TxGossip::new(
                    context.child("tx_clock"),
                    pool.clone(),
                    validator.clone(),
                    CHAIN_ID,
                    sender.clone(),
                );
                let first = signed_request(0);
                let first_tx = Tx::new(first.clone());
                let signer =
                    MempoolValidator::<CommittedState>::pre_validate_native(CHAIN_ID, &first)
                        .unwrap()
                        .signer_did;

                // Both submissions pass the unlocked duplicate check before either inserts.
                let admission = validator.get().unwrap().lock().await;
                let mut submitting = Box::pin(gossip.submit(first.clone()));
                let mut duplicate = Box::pin(gossip.submit(first.clone()));
                assert!(submitting.as_mut().now_or_never().is_none());
                assert!(duplicate.as_mut().now_or_never().is_none());
                drop(admission);
                let (inserted, repeated) = futures::join!(submitting, duplicate);
                assert!(inserted.unwrap());
                assert!(!repeated.unwrap());
                assert!(!gossip.submit(first.clone()).await.unwrap());
                assert_eq!(pool.len(), 1);
                assert_eq!(sender.0.lock().as_slice(), &[first.to_vec()]);
                assert_eq!(
                    pool.local_reannouncement(
                        context.current() + Duration::from_secs(2),
                        16,
                        vera_domain::MAX_TX_BYTES,
                    ),
                    vec![first_tx.clone()]
                );

                let pending = signed_request(1);
                assert!(gossip.submit(pending.clone()).await.unwrap());
                assert_eq!(validator.get().unwrap().lock().await.remembered(), 2);
                pool.prune(&[first_tx.id()]);
                let mut finalized_nonces = NativeNonceStore::default();
                finalized_nonces.check_and_increment(&signer, 0).unwrap();
                recheck(&pool, &validator, state, finalized_nonces).await;
                // The finalized request's admission result is released; the
                // pending one is replayed from it without being decoded again.
                assert_eq!(validator.get().unwrap().lock().await.remembered(), 1);
                let stale = gossip.submit(first).await.unwrap_err();
                assert!(
                    matches!(&stale, vera_jsonrpc::TxSubmitError::Rejected(message)
                        if message.contains("expected 2, got 0")),
                    "{stale}"
                );
                assert!(!pool.contains(&first_tx.id()));
                assert_eq!(pool.len(), 1);

                let peer = signed_request(2);
                assert!(
                    admit(&pool, &validator, CHAIN_ID, peer.clone())
                        .await
                        .unwrap()
                );
                assert!(!gossip.submit(peer.clone()).await.unwrap());
                assert_eq!(pool.len(), 2);
                assert_eq!(sender.0.lock().len(), 2);
                assert_eq!(
                    pool.local_reannouncement(
                        context.current() + Duration::from_secs(10),
                        16,
                        vera_domain::MAX_TX_BYTES,
                    ),
                    vec![Tx::new(pending.clone())]
                );
                pool.prune(&[Tx::new(pending).id(), Tx::new(peer).id()]);
                assert!(
                    pool.local_reannouncement(
                        context.current() + Duration::from_secs(20),
                        16,
                        vera_domain::MAX_TX_BYTES,
                    )
                    .is_empty()
                );

                let mut filler: Vec<_> = (0..5)
                    .map(|byte| Tx::new(vec![byte; vera_domain::MAX_TX_BYTES].into()))
                    .collect();
                filler.push(Tx::new(
                    vec![0xff; (64 << 20) - 5 * vera_domain::MAX_TX_BYTES].into(),
                ));
                for tx in &filler {
                    assert!(pool.insert(tx.clone()));
                }
                let blocked = signed_request(3);
                assert!(matches!(
                    gossip.submit(blocked.clone()).await,
                    Err(vera_jsonrpc::TxSubmitError::AtCapacity)
                ));
                assert_eq!(pool.len(), filler.len());
                assert_eq!(sender.0.lock().len(), 2);
                assert!(!pool.contains(&Tx::new(blocked.clone()).id()));
                pool.prune(&[filler[0].id()]);
                assert!(gossip.submit(blocked.clone()).await.unwrap());
                assert!(pool.contains(&Tx::new(blocked).id()));
                assert_eq!(sender.0.lock().len(), 3);
            })
        },
    );
}

fn free_transfer(signer: &alloy_signer_local::PrivateKeySigner, nonce: u64, to: u8) -> Bytes {
    use alloy_consensus::{SignableTransaction as _, TxEip1559, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718 as _;
    use alloy_signer::SignerSync as _;

    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit: 21_000,
        to: alloy_primitives::TxKind::Call(alloy_primitives::Address::repeat_byte(to)),
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    TxEnvelope::Eip1559(tx.into_signed(signature))
        .encoded_2718()
        .into()
}

#[test]
fn a_request_the_proposer_dropped_no_longer_holds_its_senders_nonce() {
    let directory = tempfile::tempdir().unwrap();
    runtime::Runner::new(runtime::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                let cache = CacheRef::new(NZU16!(4084), NZUsize!(64));
                let databases = VeraStateSet::init(
                    context.child("release_state"),
                    state_set_config("release", cache),
                    None,
                )
                .await;
                let sender = alloy_signer_local::PrivateKeySigner::random();
                let other = alloy_signer_local::PrivateKeySigner::random();
                let accounts = vera_genesis::GenesisState {
                    genesis_alloc: [&sender, &other]
                        .map(|signer| (signer.address(), alloy_primitives::U256::ZERO))
                        .to_vec(),
                    genesis_storage: vec![],
                    genesis_code: vec![],
                    participant_addresses: vec![],
                };
                vera_app::apply_genesis(&databases, &accounts)
                    .await
                    .unwrap();
                let validator: SharedValidator = Arc::new(OnceLock::new());
                validator
                    .set(Mutex::new(Admission::new(MempoolValidator::new(
                        CommittedState::new(databases),
                        ExecutionConfig::new(CHAIN_ID),
                        0,
                    ))))
                    .unwrap();
                let pool = InMemoryMempool::new();
                let admit = |bytes: Bytes| admit(&pool, &validator, CHAIN_ID, bytes);

                let refused = free_transfer(&sender, 0, 1);
                let queued = free_transfer(&other, 0, 1);
                let native = signed_request(0);
                for bytes in [&refused, &queued, &native] {
                    assert!(admit(bytes.clone()).await.unwrap());
                }
                let corrected = free_transfer(&sender, 0, 2);
                let held = admit(corrected.clone()).await.unwrap_err();
                assert!(
                    matches!(&held, TxSubmitError::Rejected(message)
                        if message.contains("expected 1, got 0")),
                    "{held}"
                );

                pool.prune(&[Tx::new(refused).id()]);
                release(&pool, &validator).await;
                assert!(admit(corrected).await.unwrap());
                assert_eq!(pool.len(), 3);
                let kept = admit(free_transfer(&other, 0, 2)).await.unwrap_err();
                assert!(
                    matches!(&kept, TxSubmitError::Rejected(message)
                        if message.contains("expected 1, got 0")),
                    "{kept}"
                );
                // The native signer's reserved sequence is untouched.
                assert!(admit(signed_request(1)).await.unwrap());
                assert_eq!(validator.get().unwrap().lock().await.remembered(), 2);
            })
        },
    );
}
