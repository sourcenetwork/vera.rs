//! A deployment with a dealt threshold key that finalizes blocks in tests.

use alloy_primitives::{B256, Bytes};
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::{Finalization, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digestible as _, Signer as _,
    bls12381::{dkg::feldman_desmedt::deal, primitives::variant::MinSig},
    ed25519,
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, TestRng, non_empty, ordered::Set};

use crate::{
    Ancestry, Block, BlockId, ConsensusContext, ConsensusDigest, ConsensusPublicKey, EpochMaterial,
    FinalizedArtifacts, LIGHT_BLOCK_NAMESPACE, LightBlock, LightConsensusScheme,
};

/// An ancestry that fits a block at `height` and commits to no real chain,
/// for tests that build a block at an arbitrary height.
#[must_use]
pub fn ancestry(height: u64) -> Ancestry {
    let peak = ConsensusDigest::from([0x5a; 32]);
    Ancestry::from_peaks(vec![peak; height.count_ones() as usize])
}

/// Four validators holding shares of one dealt consensus key.
#[allow(missing_debug_implementations)]
pub struct TestDeployment {
    signers: Vec<LightConsensusScheme>,
    verifier: LightConsensusScheme,
    material: EpochMaterial,
}

impl TestDeployment {
    /// Deal a consensus key from `seed`; equal seeds give equal keys.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let keys = Set::from_iter_dedup(
            (0..4).map(|index| ed25519::PrivateKey::from_seed(seed + index).public_key()),
        );
        let mut rng = TestRng::new(seed);
        let (output, shares) = deal::<MinSig, _, N3f1>(
            &mut rng,
            commonware_cryptography::bls12381::primitives::sharing::Mode::NonZeroCounter,
            keys,
        )
        .expect("trusted deal");
        let signers = shares
            .into_iter()
            .map(|(_, share)| {
                LightConsensusScheme::signer(
                    LIGHT_BLOCK_NAMESPACE,
                    output.players().clone(),
                    output.public().clone(),
                    share,
                )
                .expect("matching share")
            })
            .collect();
        let verifier = LightConsensusScheme::verifier(
            LIGHT_BLOCK_NAMESPACE,
            output.players().clone(),
            output.public().clone(),
        );
        let material = EpochMaterial::new(output.players().clone(), output.public().clone());
        Self {
            signers,
            verifier,
            material,
        }
    }

    /// The deployment's consensus key.
    #[must_use]
    pub fn key(&self) -> ConsensusPublicKey {
        *self.material.sharing.public()
    }

    /// A native block at `height` on `parent`, in `term`, committing to `module_state_root`.
    #[must_use]
    pub fn block(&self, height: u64, parent: B256, term: u64, module_state_root: B256) -> Block {
        let leader = self
            .material
            .participants
            .iter()
            .next()
            .expect("participants are non-empty")
            .clone();
        Block {
            context: ConsensusContext {
                round: Round::new(Epoch::new(0), View::new(height + 1)),
                leader,
                parent: (View::new(height), ConsensusDigest::from([0x44; 32])),
            },
            parent: BlockId(parent),
            height,
            ancestry: ancestry(height),
            timestamp: 1_700_000_000 + height,
            term,
            module_state_root,
            txs: vec![crate::Tx::new(Bytes::from_static(b"test"))],
            payload: None,
            native_targets: Default::default(),
            receipt_commitment: B256::repeat_byte(9),
        }
    }

    /// A native block extending `parent`, in `term`, committing to its
    /// ancestors and to `module_state_root`.
    #[must_use]
    pub fn child(&self, parent: &Block, term: u64, module_state_root: B256) -> Block {
        let mut block = self.block(parent.height + 1, parent.id().0, term, module_state_root);
        block.ancestry = parent
            .ancestry
            .extended(parent.height, &parent.id())
            .expect("the parent's ancestry fits its height");
        block
    }

    /// The blocks at heights `0..=length` of one history, told apart from
    /// another history of this deployment by `root`.
    #[must_use]
    pub fn chain(&self, length: u64, root: u8) -> Vec<Block> {
        let mut blocks = vec![self.block(0, B256::ZERO, 0, B256::ZERO)];
        for _ in 0..length {
            let next = self.child(&blocks[blocks.len() - 1], 0, B256::repeat_byte(root));
            blocks.push(next);
        }
        blocks
    }

    /// Finalize `block` directly with a quorum of this deployment's shares.
    #[must_use]
    pub fn finalize(&self, block: &Block) -> FinalizedArtifacts {
        let proposal = Proposal::new(block.context.round, block.context.parent.0, block.digest());
        let votes: Vec<_> = self
            .signers
            .iter()
            .take(3)
            .map(|signer| Finalize::sign(signer, proposal.clone()).expect("sign vote"))
            .collect();
        let finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
            Finalization::from_finalizes(&self.verifier, non_empty![@votes.iter()], &Sequential)
                .expect("assemble quorum");
        FinalizedArtifacts {
            block: block.encode().to_vec(),
            descendants: Vec::new(),
            finalization: finalization.encode().to_vec(),
            epoch_material: self.material.encode().to_vec(),
        }
    }

    /// The light block of [`Self::finalize`].
    #[must_use]
    pub fn light_block(&self, block: &Block) -> LightBlock {
        let artifacts = self.finalize(block);
        LightBlock::from_parts(block, &artifacts.finalization, &artifacts.epoch_material)
    }
}
