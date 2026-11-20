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
    Block, BlockId, ConsensusContext, ConsensusDigest, ConsensusPublicKey, DbTargets,
    EpochMaterial, FinalizedArtifacts, LIGHT_BLOCK_NAMESPACE, LightBlock, LightConsensusScheme,
    StateRoot,
};

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
            timestamp: 1_700_000_000 + height,
            term,
            prevrandao: B256::ZERO,
            randomness: None,
            state_root: StateRoot(B256::repeat_byte(0x01)),
            module_state_root,
            txs: vec![crate::Tx::new(Bytes::from_static(b"test"))],
            payload: None,
            native_targets: None,
            receipt_commitment: Some(B256::repeat_byte(9)),
            db_targets: DbTargets::default(),
        }
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
