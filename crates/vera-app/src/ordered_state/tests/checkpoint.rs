use super::*;
use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _};
use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
use commonware_cryptography::{
    Digestible as _, Sha256, Signer as _,
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519,
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, TestRng, non_empty, ordered::Set};
use vera_domain::{
    Block, BlockId, ConsensusPublicKey, EpochMaterial, LIGHT_BLOCK_NAMESPACE, LightBlock,
    LightConsensusScheme, StateRoot,
};

pub(super) async fn block(source: &OrderedState, height: u64) -> Block {
    let target = source.committed_targets().await;
    let db_targets = crate::db_targets_from_sync(&(target.0, target.1, target.2));
    let db = &source.databases;
    let module_state_root = vera_modules::module_state::combine_module_roots(&[
        db.3.read().await.root().0,
        db.4.read().await.root().0,
        db.5.read().await.root().0,
        db.6.read().await.root().0,
    ]);
    let mut context = Block::genesis_context();
    context.round = Round::new(Epoch::zero(), View::new(height));
    Block {
        context,
        parent: BlockId(B256::ZERO),
        height,
        timestamp: 1000 + height,
        prevrandao: B256::ZERO,
        state_root: StateRoot(vera_qmdb::StateRoot::compute(
            B256::from(db_targets.accounts.root.0),
            B256::from(db_targets.storage.root.0),
            B256::from(db_targets.code.root.0),
        )),
        module_state_root,
        txs: Vec::new(),
        payload: None,
        receipt_commitment: Some(vera_executor::receipt_commitment(30_000_000, &[])),
        native_targets: Some(
            [target.3, target.4, target.5, target.6]
                .each_ref()
                .map(crate::targets::target_from_sync),
        ),
        db_targets,
    }
}

pub(super) fn certify(block: &Block, seed: u64) -> (LightBlock, ConsensusPublicKey) {
    let players =
        Set::from_iter_dedup((0..4).map(|i| ed25519::PrivateKey::from_seed(seed + i).public_key()));
    let (output, shares) =
        deal::<MinSig, _, N3f1>(TestRng::new(seed), Mode::NonZeroCounter, players).unwrap();
    let verifier = LightConsensusScheme::verifier(
        LIGHT_BLOCK_NAMESPACE,
        output.players().clone(),
        output.public().clone(),
    );
    let proposal = Proposal::new(block.context.round, block.context.parent.0, block.digest());
    let votes: Vec<_> = shares
        .into_iter()
        .take(3)
        .map(|(_, share)| {
            let signer = LightConsensusScheme::signer(
                LIGHT_BLOCK_NAMESPACE,
                output.players().clone(),
                output.public().clone(),
                share,
            )
            .unwrap();
            Finalize::sign(&signer, proposal.clone()).unwrap()
        })
        .collect();
    let finalization =
        Finalization::from_finalizes(&verifier, non_empty![@votes.iter()], &Sequential).unwrap();
    let material = EpochMaterial::new(output.players().clone(), output.public().clone());
    (
        LightBlock::from_parts(block, &finalization.encode(), &material.encode()),
        *output.public().public(),
    )
}

#[test]
fn checkpoint_rejects_bad_evidence_and_checks_rebuilt_state_before_publication() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                let source = OrderedState::init(
                    context.child("source"),
                    config(&context, "source", VeraExecutor::new(DEPLOYMENT)),
                    None,
                )
                .await;
                source.apply(recovery::revision(&source, 1).await).await;
                assert!(source.finalize().await.durable().await);
                let block = block(&source, 1).await;
                let db = &source.databases;
                let proof = native::SyncProof::capture(
                    &(db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone()),
                    block.module_state_root,
                )
                .await
                .unwrap();
                let proof = native::SyncProof::decode(proof.encode()).unwrap();
                let (light, key) = certify(&block, 42);
                let checkpoint = OrderedCheckpoint::verify(&light, &key, &proof).unwrap();
                assert_eq!(checkpoint.anchor().digest, block.digest());
                let (_, unrelated_key) = certify(&block, 100);
                assert!(OrderedCheckpoint::verify(&light, &unrelated_key, &proof).is_err());
                let mut altered = light.clone();
                altered.height += 1;
                assert!(OrderedCheckpoint::verify(&altered, &key, &proof).is_err());
                let mut bad_range = block.clone();
                bad_range.db_targets.accounts.floor = bad_range.db_targets.accounts.tip;
                assert!(
                    OrderedCheckpoint::verify(&certify(&bad_range, 42).0, &key, &proof).is_err()
                );
                let mut bad_root = block.clone();
                bad_root.state_root.0[0] ^= 1;
                assert!(
                    OrderedCheckpoint::verify(&certify(&bad_root, 42).0, &key, &proof).is_err()
                );
                let mut missing_receipts = block.clone();
                missing_receipts.receipt_commitment = None;
                assert!(
                    OrderedCheckpoint::verify(&certify(&missing_receipts, 42).0, &key, &proof)
                        .is_err()
                );

                // A certificate can bind internally inconsistent state; verify the rebuilt bitmap too.
                let mut witness = db.3.read().await.ops_root_witness().await.unwrap();
                witness.grafted_root.0[0] ^= 1;
                let mut encoded = proof.encode().to_vec();
                encoded[Digest::SIZE] ^= 1;
                let inconsistent =
                    native::SyncProof::decode(commonware_codec::Copying(encoded.as_slice()))
                        .unwrap();
                let mut block = block;
                block.module_state_root = vera_modules::module_state::combine_module_roots(&[
                    witness.root::<Sha256>(&db.3.read().await.ops_root()).0,
                    db.4.read().await.root().0,
                    db.5.read().await.root().0,
                    db.6.read().await.root().0,
                ]);
                let (light, _) = certify(&block, 42);
                let checkpoint = OrderedCheckpoint::verify(&light, &key, &inconsistent).unwrap();
                let executor = VeraExecutor::new(DEPLOYMENT);
                executor
                    .modules()
                    .write()
                    .unwrap()
                    .nonces
                    .check_and_increment("unpublished", 0)
                    .unwrap();
                let result = OrderedState::sync_checkpoint(
                    context.child("replica"),
                    config(&context, "replica", executor.clone()),
                    sources(&source),
                    checkpoint.clone(),
                    SyncEngineConfig {
                        fetch_batch_size: NZU64!(16),
                        apply_batch_size: NZU64!(32),
                        max_outstanding_requests: 2,
                        update_channel_size: NZUsize!(2),
                        max_retained_roots: 2,
                    },
                )
                .await;
                assert!(result.is_err());
                let reopen = OrderedState::open(
                    context.child("reopen"),
                    config(&context, "replica", executor.clone()).recover_checkpoint(checkpoint),
                )
                .await;
                assert!(matches!(
                    reopen,
                    Err(AppError::RootMismatch("ordered recovery module root"))
                ));
                assert_eq!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .nonces
                        .get_nonce("unpublished")
                        .unwrap(),
                    1
                );
                assert!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
            })
        },
    );
}
