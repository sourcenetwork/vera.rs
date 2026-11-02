use alloy_primitives::Bytes;
use commonware_consensus::{
    simplex::types::Finalize,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digestible as _, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
};
use commonware_utils::{N3f1, TestRng, non_empty};

use super::*;
use crate::{BlockId, ConsensusContext, DbTargets, StateRoot};

fn fixture(
    seed: u64,
) -> (
    Vec<LightConsensusScheme>,
    LightConsensusScheme,
    EpochMaterial,
) {
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
    (signers, verifier, material)
}

fn light_fixture(seed: u64) -> LightBlock {
    light_fixture_with(seed, |_| {})
}

fn light_fixture_with(seed: u64, configure: impl FnOnce(&mut Block)) -> LightBlock {
    let (signers, verifier, material) = fixture(seed);
    let leader = material
        .participants
        .iter()
        .next()
        .expect("participants are non-empty")
        .clone();
    let round = Round::new(Epoch::new(3), View::new(17));
    let mut block = Block {
        context: ConsensusContext {
            round,
            leader,
            parent: (View::new(16), ConsensusDigest::from([0x44; 32])),
        },
        parent: BlockId(B256::repeat_byte(0x07)),
        height: 100,
        timestamp: 1_700_000_000,
        prevrandao: B256::repeat_byte(0x55),
        randomness: None,
        state_root: StateRoot(B256::repeat_byte(0x01)),
        module_state_root: B256::repeat_byte(0x02),
        txs: vec![crate::Tx::new(Bytes::from_static(b"light-block"))],
        payload: None,
        native_targets: None,
        receipt_commitment: Some(B256::repeat_byte(9)),
        db_targets: DbTargets::default(),
    };
    configure(&mut block);
    let proposal = Proposal::new(round, View::new(16), block.digest());
    let votes: Vec<_> = signers
        .iter()
        .take(3)
        .map(|signer| Finalize::sign(signer, proposal.clone()).expect("sign vote"))
        .collect();
    let finalization =
        Finalization::from_finalizes(&verifier, non_empty![@votes.iter()], &Sequential)
            .expect("assemble quorum");
    LightBlock::from_parts(&block, &finalization.encode(), &material.encode())
}

fn trusted_key() -> ConsensusPublicKey {
    *fixture(42).2.sharing.public()
}

#[test]
fn unrelated_consensus_group_is_rejected() {
    let light = light_fixture(100);
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::UntrustedConsensusKey)
    );
}

#[test]
fn valid_light_block_verifies() {
    let light = light_fixture(42);
    assert_eq!(
        verify_light_block(&light, &trusted_key()).unwrap(),
        (B256::repeat_byte(0x01), B256::repeat_byte(0x02))
    );
}

#[test]
fn displayed_header_tampering_fails() {
    let mut light = light_fixture(42);
    light.module_state_root = encode_hex(B256::repeat_byte(0x99).as_slice());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::BlockFieldMismatch("module_state_root"))
    );
}

#[test]
fn proposal_payload_tampering_fails() {
    let mut light = light_fixture(42);
    let encoded = decode_hex("finalization", &light.finalization).unwrap();
    let mut finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(commonware_codec::Copying(encoded.as_slice())).unwrap();
    finalization.proposal.payload = ConsensusDigest::from([0x99; 32]);
    light.finalization = encode_hex(&finalization.encode());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::ProposalMismatch)
    );
}

#[test]
fn malformed_finalization_fails() {
    let mut light = light_fixture(42);
    light.finalization = "0xdeadbeef".into();
    assert!(matches!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::Codec(_))
    ));
}

#[test]
fn wrong_epoch_material_fails() {
    let mut light = light_fixture(42);
    let (_, _, other) = fixture(100);
    light.epoch_material = encode_hex(&other.encode());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::UntrustedConsensusKey)
    );
}

#[test]
fn substituted_certificate_is_rejected() {
    let mut light = light_fixture(42);
    let mut finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(commonware_codec::Copying(
            decode_hex("finalization", &light.finalization)
                .unwrap()
                .as_slice(),
        ))
        .unwrap();
    let unrelated: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(commonware_codec::Copying(
            decode_hex("finalization", &light_fixture(100).finalization)
                .unwrap()
                .as_slice(),
        ))
        .unwrap();
    finalization.certificate = unrelated.certificate;
    light.finalization = encode_hex(&finalization.encode());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::InvalidCertificate)
    );
}

#[test]
fn json_round_trip_preserves_verifiability() {
    let light = light_fixture(42);
    let json = serde_json::to_string(&light).unwrap();
    let decoded: LightBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, light);
    verify_light_block(&decoded, &trusted_key()).unwrap();
}

fn indirect_fixture(count: usize) -> LightBlock {
    let mut light = light_fixture(42);
    let mut parent = decode_block(&decode_hex("block", &light.block).unwrap()).unwrap();
    for index in 0..count {
        let mut child = parent.clone();
        child.parent = parent.id();
        child.height += 1;
        child.timestamp += 1;
        child.state_root = StateRoot(B256::repeat_byte(0x30));
        child.module_state_root = B256::repeat_byte(0x40);
        child.context.parent = (parent.context.round.view(), parent.digest());
        child.context.round = Round::new(Epoch::new(4), View::new(index as u64 + 1));
        light.descendants.push(encode_hex(&child.encode()));
        parent = child;
    }
    light.finalization = signed_finalization(&parent, 42);
    light
}

fn signed_finalization(block: &Block, seed: u64) -> String {
    signed_proposal(
        Proposal::new(block.context.round, block.context.parent.0, block.digest()),
        seed,
    )
}

fn signed_proposal(proposal: Proposal<ConsensusDigest>, seed: u64) -> String {
    let (signers, verifier, _) = fixture(seed);
    let votes: Vec<_> = signers
        .iter()
        .take(3)
        .map(|signer| Finalize::sign(signer, proposal.clone()).unwrap())
        .collect();
    let finalization =
        Finalization::from_finalizes(&verifier, non_empty![@votes.iter()], &Sequential).unwrap();
    encode_hex(&finalization.encode())
}

#[test]
fn descendant_certificate_authenticates_the_requested_roots_across_epochs() {
    let light = indirect_fixture(3);
    assert_eq!(light.epoch, 3);
    let requested = verify_finalized_block(&light, &trusted_key()).unwrap();
    assert_eq!(requested.height, light.height);
    assert_eq!(requested.context.round.epoch().get(), light.epoch);
    assert_eq!(
        requested,
        decode_block(&decode_hex("block", &light.block).unwrap()).unwrap()
    );
    assert_eq!(
        verify_light_block(&light, &trusted_key()).unwrap(),
        (B256::repeat_byte(1), B256::repeat_byte(2))
    );
    let decoded: LightBlock =
        serde_json::from_str(&serde_json::to_string(&light).unwrap()).unwrap();
    assert_eq!(decoded, light);
    verify_light_block(&decoded, &trusted_key()).unwrap();
    let direct = serde_json::to_value(light_fixture(42)).unwrap();
    assert!(direct.get("descendants").is_none());
    verify_light_block(&serde_json::from_value(direct).unwrap(), &trusted_key()).unwrap();
}

#[test]
fn descendant_omission_reordering_and_substitution_are_rejected() {
    let light = indirect_fixture(3);
    for index in 0..light.descendants.len() {
        let mut missing = light.clone();
        missing.descendants.remove(index);
        assert!(verify_light_block(&missing, &trusted_key()).is_err());
    }
    let mut reversed = light.clone();
    reversed.descendants.reverse();
    assert_eq!(
        verify_light_block(&reversed, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
    let mut changed = light.clone();
    let mut child =
        decode_block(&decode_hex("descendant", &changed.descendants[0]).unwrap()).unwrap();
    child.module_state_root = B256::repeat_byte(0x99);
    changed.descendants[0] = encode_hex(&child.encode());
    assert_eq!(
        verify_light_block(&changed, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
    let mut duplicate = light.clone();
    duplicate
        .descendants
        .insert(1, duplicate.descendants[0].clone());
    assert_eq!(
        verify_light_block(&duplicate, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
    let mut disconnected = light;
    disconnected.block = light_fixture(100).block;
    disconnected.block_hash =
        encode_hex(&keccak256(decode_hex("block", &disconnected.block).unwrap()).0);
    assert_eq!(
        verify_light_block(&disconnected, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
}

#[test]
fn signed_height_gaps_and_untrusted_descendant_certificates_are_rejected() {
    let mut light = indirect_fixture(1);
    let mut child =
        decode_block(&decode_hex("descendant", &light.descendants[0]).unwrap()).unwrap();
    light.finalization = signed_finalization(&child, 100);
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::InvalidCertificate)
    );
    child.height += 1;
    light.descendants[0] = encode_hex(&child.encode());
    light.finalization = signed_finalization(&child, 42);
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
}

#[test]
fn proof_limits_apply_before_decoding() {
    let mut light = indirect_fixture(LIGHT_BLOCK_MAX_DESCENDANTS);
    verify_light_block(&light, &trusted_key()).unwrap();
    serde_json::from_str::<LightBlock>(&serde_json::to_string(&light).unwrap()).unwrap();
    light.descendants.push("invalid hex".into());
    assert!(
        serde_json::from_str::<LightBlock>(&serde_json::to_string(&light).unwrap())
            .unwrap_err()
            .to_string()
            .contains("too many light block descendants")
    );
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::LimitExceeded)
    );
    light = light_fixture(42);
    let others = light.finalization.len() - 2 + light.epoch_material.len() - 2;
    light.block = "0".repeat(LIGHT_BLOCK_MAX_ARTIFACT_BYTES * 2 - others);
    light.check_artifact_limits().unwrap();
    light.block.push('0');
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::LimitExceeded)
    );
}

#[test]
fn receipt_evidence_binds_results_to_finality_and_submission() {
    use crate::{ExecutionReceipt, ReceiptResponse, receipt_commitment};
    let first = B256::repeat_byte(1);
    let second = B256::repeat_byte(2);
    let receipts = vec![
        ExecutionReceipt::new(first, true, 0, 0, vec![], None),
        ExecutionReceipt::new(second, false, 0, 0, vec![], None),
    ];
    let revision = light_fixture_with(42, |block| {
        block
            .txs
            .push(crate::Tx::new(Bytes::from_static(b"second")));
        block.receipt_commitment = Some(receipt_commitment(100, &receipts));
    });
    let response = ReceiptResponse {
        revision,
        gas_limit: 100,
        receipts,
    };
    assert!(response.verify(first, &trusted_key()).unwrap().success());
    assert!(!response.verify(second, &trusted_key()).unwrap().success());
    assert!(response.verify(B256::ZERO, &trusted_key()).is_err());
    assert!(
        response
            .verify(first, fixture(100).2.sharing.public())
            .is_err()
    );
    let encoded = serde_json::to_vec(&response).unwrap();
    let decoded: ReceiptResponse = serde_json::from_slice(&encoded).unwrap();
    assert!(decoded.verify(first, &trusted_key()).unwrap().success());
    let mut at_limit = response.clone();
    at_limit
        .receipts
        .resize(LIGHT_BLOCK_MAX_TXS, response.receipts[0].clone());
    let encoded = serde_json::to_vec(&at_limit).unwrap();
    assert!(serde_json::from_slice::<ReceiptResponse>(&encoded).is_ok());
    at_limit.receipts.push(response.receipts[0].clone());
    let encoded = serde_json::to_vec(&at_limit).unwrap();
    assert!(
        serde_json::from_slice::<ReceiptResponse>(&encoded)
            .unwrap_err()
            .to_string()
            .contains("too many execution receipts")
    );
    for mutation in 0..7 {
        let mut changed = response.clone();
        match mutation {
            0 => changed.gas_limit += 1,
            1 => changed.receipts[0].receipt.status = false.into(),
            2 => changed.receipts.swap(0, 1),
            3 => {
                changed.receipts.pop();
            }
            4 => changed.receipts[0].tx_hash = B256::ZERO,
            5 => changed.revision.height += 1,
            6 => {
                changed.receipts[0].receipt.status =
                    alloy_consensus::Eip658Value::PostState(B256::ZERO)
            }
            _ => unreachable!(),
        }
        assert!(
            changed.verify(first, &trusted_key()).is_err(),
            "mutation {mutation}"
        );
    }
    let legacy = ReceiptResponse {
        revision: light_fixture_with(42, |block| {
            block
                .txs
                .push(crate::Tx::new(Bytes::from_static(b"second")));
            block.receipt_commitment = None;
        }),
        ..response.clone()
    };
    assert!(legacy.verify(first, &trusted_key()).is_err());
    let mut duplicate = response;
    duplicate.receipts[1].tx_hash = first;
    duplicate.revision = light_fixture_with(42, |block| {
        block
            .txs
            .push(crate::Tx::new(Bytes::from_static(b"second")));
        block.receipt_commitment = Some(receipt_commitment(100, &duplicate.receipts));
    });
    assert!(duplicate.verify(first, &trusted_key()).is_err());
}

fn epoch_end(block: &mut Block) {
    use commonware_cryptography::bls12381::primitives::sharing::Mode;
    use commonware_glue::dkg::types::{EpochInfo, EpochOutcome};
    let players = fixture(42).2.participants;
    let (output, _) =
        deal::<MinSig, _, N3f1>(TestRng::new(42), Mode::NonZeroCounter, players.clone()).unwrap();
    block.payload = Some(crate::DkgPayload::EpochInfo(EpochInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::new(block.context.round.epoch().get() + 1),
        output,
        players: players.clone(),
        next_players: players,
        directory: commonware_utils::sequence::Unit,
    }));
}

#[test]
fn epoch_end_reproposal_verifies_directly_and_through_ancestry() {
    for indirect in [false, true] {
        let mut light = light_fixture_with(42, epoch_end);
        if indirect {
            light = indirect_fixture(1);
        }
        let encoded = if indirect {
            &light.descendants[0]
        } else {
            &light.block
        };
        let mut block = decode_block(&decode_hex("block", encoded).unwrap()).unwrap();
        epoch_end(&mut block);
        if indirect {
            light.descendants[0] = encode_hex(&block.encode());
        }
        let proposal = Proposal::new(
            Round::new(
                block.context.round.epoch(),
                View::new(block.context.round.view().get() + 1),
            ),
            block.context.round.view(),
            block.digest(),
        );
        light.finalization = signed_proposal(proposal, 42);
        verify_finalized_block(&light, &trusted_key()).unwrap();
        let forged = signed_proposal(
            Proposal::new(block.context.round, block.context.parent.0, block.digest()),
            100,
        );
        let mut certificate = Finalization::<LightConsensusScheme, ConsensusDigest>::decode(
            commonware_codec::Copying(
                decode_hex("finalization", &light.finalization)
                    .unwrap()
                    .as_slice(),
            ),
        )
        .unwrap();
        certificate.certificate = Finalization::<LightConsensusScheme, ConsensusDigest>::decode(
            commonware_codec::Copying(decode_hex("finalization", &forged).unwrap().as_slice()),
        )
        .unwrap()
        .certificate;
        light.finalization = encode_hex(&certificate.encode());
        assert_eq!(
            verify_finalized_block(&light, &trusted_key()).unwrap_err(),
            LightBlockError::InvalidCertificate
        );
    }
}

#[test]
fn invalid_reproposal_contexts_are_rejected_even_with_valid_signatures() {
    for terminal in [false, true] {
        let mut light = light_fixture_with(42, |block| {
            if terminal {
                epoch_end(block);
            }
        });
        let block = decode_block(&decode_hex("block", &light.block).unwrap()).unwrap();
        for (epoch, view, parent) in [
            (3, 18, 17),
            (4, 18, 17),
            (3, 16, 15),
            (3, 18, 16),
            (3, 18, 18),
        ] {
            light.finalization = signed_proposal(
                Proposal::new(
                    Round::new(Epoch::new(epoch), View::new(view)),
                    View::new(parent),
                    block.digest(),
                ),
                42,
            );
            let result = verify_finalized_block(&light, &trusted_key());
            if terminal && (epoch, view, parent) == (3, 18, 17) {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err(), LightBlockError::ProposalMismatch);
            }
        }
    }
}
