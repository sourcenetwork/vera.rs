use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_domain::{Block, LightBlockError, testing::TestDeployment};
use vera_modules::vera::anchors::{AnchorError, MAX_ANCHOR_ARTIFACT_BYTES, deployment_id};

use super::submission::{AnchorRefusal, AnchorSubmission, VerifiedSubmission};

fn key(deployment: &TestDeployment) -> Vec<u8> {
    deployment.key().encode().to_vec()
}

fn submission(deployment: &TestDeployment, block: &Block) -> AnchorSubmission {
    AnchorSubmission {
        deployment: deployment_id(&key(deployment)),
        artifacts: deployment.finalize(block),
    }
}

fn verify(deployment: &TestDeployment, block: &Block) -> VerifiedSubmission {
    submission(deployment, block)
        .verify(&key(deployment))
        .unwrap()
}

#[test]
fn a_finalized_revision_verifies_to_its_block_fields() {
    let deployment = TestDeployment::new(1);
    let block = deployment.block(10, B256::repeat_byte(7), 3, B256::repeat_byte(1));
    let revision = verify(&deployment, &block).revision(0, B256::ZERO, &[]);
    assert_eq!(revision.height, 10);
    assert_eq!(revision.block_hash, block.id().0);
    assert_eq!(revision.term, 3);
    assert_eq!(revision.module_state_root, B256::repeat_byte(1));
    assert_eq!(revision.ancestor, None);
}

#[test]
fn an_ancestor_is_named_only_when_the_proof_shows_it() {
    let deployment = TestDeployment::new(2);
    let chain = deployment.chain(12, 1);
    let ids: Vec<_> = chain.iter().map(Block::id).collect();
    let verified = verify(&deployment, &chain[12]);
    let proof = chain[5].ancestry.prove(5, &ids[5..12], 5).unwrap().encode();
    assert_eq!(
        verified.revision(5, ids[5].0, &proof).ancestor,
        Some((5, ids[5].0))
    );
    // Another block, another height, no proof and bytes that are not a proof.
    assert_eq!(verified.revision(5, ids[6].0, &proof).ancestor, None);
    assert_eq!(verified.revision(6, ids[5].0, &proof).ancestor, None);
    assert_eq!(verified.revision(5, ids[5].0, &[]).ancestor, None);
    assert_eq!(verified.revision(5, ids[5].0, &[0xff; 40]).ancestor, None);
    // A history that left this one below the ancestor does not include it.
    let forked = verify(&deployment, &deployment.chain(12, 2)[12]);
    assert_eq!(forked.revision(5, ids[5].0, &proof).ancestor, None);
}

#[test]
fn a_light_block_of_another_deployment_is_refused() {
    let deployment = TestDeployment::new(5);
    let other = TestDeployment::new(50);
    let block = other.block(10, B256::repeat_byte(7), 0, B256::repeat_byte(1));
    let mut foreign = submission(&other, &block);
    assert_eq!(
        foreign.verify(&key(&deployment)),
        Err(AnchorRefusal::Finality(
            LightBlockError::UntrustedConsensusKey
        ))
    );

    // The other deployment's certificate presented with this deployment's material.
    foreign.artifacts.epoch_material = deployment.finalize(&block).epoch_material;
    assert_eq!(
        foreign.verify(&key(&deployment)),
        Err(AnchorRefusal::Finality(LightBlockError::InvalidCertificate))
    );
}

#[test]
fn a_forged_light_block_is_refused() {
    let deployment = TestDeployment::new(6);
    let block = deployment.block(10, B256::repeat_byte(7), 0, B256::repeat_byte(1));
    let honest = submission(&deployment, &block);

    let mut altered = honest.clone();
    let other = deployment.block(10, B256::repeat_byte(7), 0, B256::repeat_byte(9));
    altered.artifacts.block = other.encode().to_vec();
    assert_eq!(
        altered.verify(&key(&deployment)),
        Err(AnchorRefusal::Finality(LightBlockError::ProposalMismatch))
    );

    let mut garbled = honest.clone();
    let last = garbled.artifacts.finalization.len() - 1;
    garbled.artifacts.finalization[last] ^= 1;
    assert!(matches!(
        garbled.verify(&key(&deployment)),
        Err(AnchorRefusal::Finality(_))
    ));

    assert_eq!(
        honest.verify(&key(&deployment)[..10]),
        Err(AnchorRefusal::Anchor(AnchorError::InvalidConsensusKey))
    );
}

#[test]
fn oversized_artifacts_are_refused_before_verification() {
    let deployment = TestDeployment::new(7);
    let block = deployment.block(10, B256::repeat_byte(7), 0, B256::repeat_byte(1));
    let mut large = submission(&deployment, &block);
    large.artifacts.descendants = vec![vec![0; MAX_ANCHOR_ARTIFACT_BYTES]];
    assert_eq!(
        large.verify(&key(&deployment)),
        Err(AnchorRefusal::Anchor(AnchorError::TooLarge))
    );
}
