use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::{Finalization, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::Digestible as _;
use commonware_parallel::Sequential;
use commonware_utils::non_empty;
use vera_domain::{
    Block, BlockId, ConsensusContext, ConsensusDigest, ConsensusPublicKey, DbTargets,
    EpochMaterial, LIGHT_BLOCK_NAMESPACE, LightBlock, LightConsensusScheme, StateRoot,
};
use vera_e2e::cluster::KeySet;

pub(super) fn fixture() -> (LightBlock, ConsensusPublicKey) {
    let keys = KeySet::builder().seed(42).build().unwrap();
    let output = &keys.epoch_info().output;
    let material = EpochMaterial::new(output.players().clone(), output.public().clone());
    let verifier = LightConsensusScheme::verifier(
        LIGHT_BLOCK_NAMESPACE,
        output.players().clone(),
        output.public().clone(),
    );
    let round = Round::new(Epoch::new(0), View::new(1));
    let block = Block {
        context: ConsensusContext {
            round,
            leader: material.participants.iter().next().unwrap().clone(),
            parent: (View::new(0), ConsensusDigest::from([0; 32])),
        },
        parent: BlockId(B256::ZERO),
        height: 1,
        timestamp: 1_700_000_000,
        prevrandao: B256::repeat_byte(1),
        randomness: None,
        state_root: StateRoot(B256::repeat_byte(2)),
        module_state_root: B256::repeat_byte(3),
        txs: Vec::new(),
        payload: None,
        native_targets: None,
        receipt_commitment: Some(B256::repeat_byte(4)),
        db_targets: DbTargets::default(),
    };
    let proposal = Proposal::new(round, View::new(0), block.digest());
    let votes: Vec<_> = (0..3)
        .map(|i| {
            let signer = LightConsensusScheme::signer(
                LIGHT_BLOCK_NAMESPACE,
                output.players().clone(),
                output.public().clone(),
                keys.share(i).unwrap().clone(),
            )
            .unwrap();
            Finalize::sign(&signer, proposal.clone()).unwrap()
        })
        .collect();
    let finalization =
        Finalization::from_finalizes(&verifier, non_empty![@votes.iter()], &Sequential).unwrap();
    (
        LightBlock::from_parts(&block, &finalization.encode(), &material.encode()),
        *output.public().public(),
    )
}
