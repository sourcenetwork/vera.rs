use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_domain::{LightBlockError, testing::TestDeployment};
use vera_modules::vera::anchors::{AnchorError, MAX_ANCHOR_ARTIFACT_BYTES, deployment_id};

use super::submission::{AnchorRefusal, AnchorSubmission};

fn submission(deployment: &TestDeployment, height: u64, term: u64, root: u8) -> AnchorSubmission {
    let block = deployment.block(height, B256::repeat_byte(7), term, B256::repeat_byte(root));
    AnchorSubmission {
        consensus_key: deployment.key().encode().to_vec(),
        artifacts: deployment.finalize(&block),
    }
}

#[test]
fn a_finalized_revision_verifies_to_its_block_fields() {
    let deployment = TestDeployment::new(1);
    let verified = submission(&deployment, 10, 3, 1).verify().unwrap();
    assert_eq!(verified.consensus_key, deployment.key().encode().to_vec());
    assert_eq!(
        deployment_id(&verified.consensus_key),
        deployment_id(&deployment.key().encode())
    );
    let revision = verified.revision(0, B256::ZERO, &[]);
    assert_eq!(revision.height, 10);
    assert_eq!(revision.term, 3);
    assert_eq!(revision.module_state_root, B256::repeat_byte(1));
    assert_eq!(revision.ancestor, None);
}

#[test]
fn an_ancestor_is_named_only_when_the_proof_shows_it() {
    let deployment = TestDeployment::new(2);
    let chain = deployment.chain(12, 1);
    let ids: Vec<_> = chain.iter().map(vera_domain::Block::id).collect();
    let tip = &chain[12];
    let verified = AnchorSubmission {
        consensus_key: deployment.key().encode().to_vec(),
        artifacts: deployment.finalize(tip),
    }
    .verify()
    .unwrap();
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
    let other = deployment.chain(12, 2);
    let forked = AnchorSubmission {
        consensus_key: deployment.key().encode().to_vec(),
        artifacts: deployment.finalize(&other[12]),
    }
    .verify()
    .unwrap();
    assert_eq!(forked.revision(5, ids[5].0, &proof).ancestor, None);
}

#[test]
fn a_light_block_of_another_deployment_is_refused() {
    let deployment = TestDeployment::new(5);
    let other = TestDeployment::new(50);
    let mut foreign = submission(&other, 10, 0, 1);
    foreign.consensus_key = deployment.key().encode().to_vec();
    assert_eq!(
        foreign.verify(),
        Err(AnchorRefusal::Finality(
            LightBlockError::UntrustedConsensusKey
        ))
    );

    // The other deployment's certificate presented with this deployment's material.
    foreign.artifacts.epoch_material = submission(&deployment, 10, 0, 1).artifacts.epoch_material;
    assert_eq!(
        foreign.verify(),
        Err(AnchorRefusal::Finality(LightBlockError::InvalidCertificate))
    );
}

#[test]
fn a_forged_light_block_is_refused() {
    let deployment = TestDeployment::new(6);
    let honest = submission(&deployment, 10, 0, 1);

    let mut altered = honest.clone();
    let block = deployment.block(10, B256::repeat_byte(7), 0, B256::repeat_byte(9));
    altered.artifacts.block = block.encode().to_vec();
    assert_eq!(
        altered.verify(),
        Err(AnchorRefusal::Finality(LightBlockError::ProposalMismatch))
    );

    let mut garbled = honest;
    let last = garbled.artifacts.finalization.len() - 1;
    garbled.artifacts.finalization[last] ^= 1;
    assert!(matches!(garbled.verify(), Err(AnchorRefusal::Finality(_))));

    let mut bad_key = submission(&deployment, 10, 0, 1);
    bad_key.consensus_key.truncate(10);
    assert_eq!(
        bad_key.verify(),
        Err(AnchorRefusal::Anchor(AnchorError::InvalidConsensusKey))
    );
}

#[test]
fn oversized_artifacts_are_refused_before_verification() {
    let deployment = TestDeployment::new(7);
    let mut large = submission(&deployment, 10, 0, 1);
    large.artifacts.descendants = vec![vec![0; MAX_ANCHOR_ARTIFACT_BYTES]];
    assert_eq!(
        large.verify(),
        Err(AnchorRefusal::Anchor(AnchorError::TooLarge))
    );
}
