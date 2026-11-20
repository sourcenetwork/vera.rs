use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_domain::{LightBlockError, testing::TestDeployment};

use super::*;
use crate::types::Timestamp;

fn context(height: u64) -> BlockExecCtx {
    BlockExecCtx {
        timestamp: Timestamp {
            seconds: 1_800_000_000,
            block_height: height,
        },
        ..BlockExecCtx::default()
    }
}

fn submission(deployment: &TestDeployment, height: u64, term: u64, root: u8) -> AnchorSubmission {
    let block = deployment.block(height, B256::repeat_byte(7), term, B256::repeat_byte(root));
    AnchorSubmission {
        consensus_key: deployment.key().encode().to_vec(),
        artifacts: deployment.finalize(&block),
    }
}

#[test]
fn anchors_advance_in_order_and_keep_the_latest_revision() {
    let deployment = TestDeployment::new(1);
    let mut module = VeraModule::new();
    let first = module
        .anchor_revision(&context(5), &submission(&deployment, 10, 0, 1))
        .unwrap();
    assert!(first.recorded);
    assert_eq!(first.record.sequence, 1);
    assert_eq!(first.record.height, 10);
    assert_eq!(first.record.module_state_root, B256::repeat_byte(1));
    assert_eq!(first.record.anchored_at, 5);
    assert_eq!(first.record.deployment, deployment_id(&deployment.key()));

    let second = module
        .anchor_revision(&context(6), &submission(&deployment, 20, 0, 2))
        .unwrap();
    assert_eq!(second.record.sequence, 2);
    assert_eq!(
        module.latest_anchor(&second.record.deployment).unwrap(),
        Some(second.record)
    );
}

#[test]
fn an_anchor_that_goes_backwards_is_refused() {
    let deployment = TestDeployment::new(2);
    let mut module = VeraModule::new();
    module
        .anchor_revision(&context(1), &submission(&deployment, 20, 0, 1))
        .unwrap();
    assert_eq!(
        module.anchor_revision(&context(2), &submission(&deployment, 19, 0, 1)),
        Err(AnchorError::NotNewer {
            latest: 20,
            height: 19
        })
    );
}

#[test]
fn a_second_history_at_an_anchored_height_cannot_displace_the_first() {
    let deployment = TestDeployment::new(3);
    let mut module = VeraModule::new();
    let first = module
        .anchor_revision(&context(1), &submission(&deployment, 20, 0, 1))
        .unwrap();
    let fork = submission(&deployment, 20, 0, 2);
    assert_eq!(
        module.anchor_revision(&context(2), &fork),
        Err(AnchorError::NotNewer {
            latest: 20,
            height: 20
        })
    );
    assert_eq!(
        module.latest_anchor(&first.record.deployment).unwrap(),
        Some(first.record.clone())
    );

    let again = module
        .anchor_revision(&context(3), &submission(&deployment, 20, 0, 1))
        .unwrap();
    assert!(!again.recorded);
    assert_eq!(again.record, first.record);
}

#[test]
fn a_lower_term_is_refused() {
    let deployment = TestDeployment::new(4);
    let mut module = VeraModule::new();
    module
        .anchor_revision(&context(1), &submission(&deployment, 20, 2, 1))
        .unwrap();
    assert_eq!(
        module.anchor_revision(&context(2), &submission(&deployment, 30, 1, 1)),
        Err(AnchorError::LowerTerm { latest: 2, term: 1 })
    );
    module
        .anchor_revision(&context(3), &submission(&deployment, 30, 3, 1))
        .unwrap();
}

#[test]
fn a_light_block_of_another_deployment_is_refused() {
    let deployment = TestDeployment::new(5);
    let other = TestDeployment::new(50);
    let mut module = VeraModule::new();
    let mut foreign = submission(&other, 10, 0, 1);
    foreign.consensus_key = deployment.key().encode().to_vec();
    assert_eq!(
        module.anchor_revision(&context(1), &foreign),
        Err(AnchorError::Finality(
            LightBlockError::UntrustedConsensusKey
        ))
    );

    // The other deployment's certificate presented with this deployment's material.
    foreign.artifacts.epoch_material = submission(&deployment, 10, 0, 1).artifacts.epoch_material;
    assert_eq!(
        module.anchor_revision(&context(1), &foreign),
        Err(AnchorError::Finality(LightBlockError::InvalidCertificate))
    );
    assert_eq!(
        module.latest_anchor(&deployment_id(&deployment.key())),
        Ok(None)
    );
}

#[test]
fn a_forged_light_block_is_refused() {
    let deployment = TestDeployment::new(6);
    let mut module = VeraModule::new();
    let honest = submission(&deployment, 10, 0, 1);

    let mut altered = honest.clone();
    let mut block = deployment.block(10, B256::repeat_byte(7), 0, B256::repeat_byte(9));
    block.height = 10;
    altered.artifacts.block = block.encode().to_vec();
    assert_eq!(
        module.anchor_revision(&context(1), &altered),
        Err(AnchorError::Finality(LightBlockError::ProposalMismatch))
    );

    let mut garbled = honest;
    let last = garbled.artifacts.finalization.len() - 1;
    garbled.artifacts.finalization[last] ^= 1;
    assert!(matches!(
        module.anchor_revision(&context(1), &garbled),
        Err(AnchorError::Finality(_))
    ));

    let mut bad_key = submission(&deployment, 10, 0, 1);
    bad_key.consensus_key.truncate(10);
    assert_eq!(
        module.anchor_revision(&context(1), &bad_key),
        Err(AnchorError::InvalidConsensusKey)
    );
}

#[test]
fn oversized_artifacts_are_refused_before_verification() {
    let deployment = TestDeployment::new(7);
    let mut module = VeraModule::new();
    let mut large = submission(&deployment, 10, 0, 1);
    large.artifacts.descendants = vec![vec![0; MAX_ANCHOR_ARTIFACT_BYTES]];
    assert_eq!(
        module.anchor_revision(&context(1), &large),
        Err(AnchorError::TooLarge)
    );
}

#[test]
fn stored_records_must_name_their_deployment() {
    let deployment = TestDeployment::new(8);
    let mut module = VeraModule::new();
    let anchored = module
        .anchor_revision(&context(1), &submission(&deployment, 10, 0, 1))
        .unwrap();
    let bytes = anchored.record.encode();
    assert_eq!(
        AnchorRecord::decode(&anchored.record.deployment, &bytes).unwrap(),
        anchored.record
    );
    assert_eq!(
        AnchorRecord::decode(&B256::repeat_byte(1), &bytes),
        Err(AnchorError::MalformedRecord)
    );
}
