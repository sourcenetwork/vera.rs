use alloy_primitives::B256;

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

fn key(seed: u8) -> Vec<u8> {
    vec![seed; CONSENSUS_KEY_BYTES]
}

const OPERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SUBMITTER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn registration(key: &[u8]) -> DeploymentRegistration {
    DeploymentRegistration {
        consensus_key: hex::encode(key),
        genesis_id: [7; 32],
        operators: crate::vera::administration::OperatorPolicy {
            threshold: 1,
            keys: vec![OPERATOR.into()],
        },
    }
}

/// A module in which the deployments with these keys are registered.
fn registered(keys: &[&[u8]]) -> VeraModule {
    let mut module = VeraModule::new();
    for key in keys {
        module.register_deployment(&registration(key), 100).unwrap();
    }
    module
}

fn revision(height: u64, term: u64, root: u8) -> VerifiedRevision {
    VerifiedRevision {
        height,
        block_hash: B256::repeat_byte(root),
        term,
        timestamp: 1_700_000_000 + height,
        module_state_root: B256::repeat_byte(root),
        ancestor: None,
    }
}

/// A revision the caller proved to descend from the block `ancestor` at `from`.
fn descendant(height: u64, term: u64, root: u8, from: u64, ancestor: u8) -> VerifiedRevision {
    VerifiedRevision {
        ancestor: Some((from, B256::repeat_byte(ancestor))),
        ..revision(height, term, root)
    }
}

#[test]
fn anchors_advance_in_order_and_keep_the_latest_revision() {
    let key = key(1);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(5), &deployment_id(&key), &revision(10, 0, 1))
        .unwrap();
    assert!(first.recorded);
    assert_eq!(first.record.sequence, 1);
    assert_eq!(first.record.height, 10);
    assert_eq!(first.record.module_state_root, B256::repeat_byte(1));
    assert_eq!(first.record.anchored_at, 5);
    assert_eq!(first.record.deployment, deployment_id(&key));
    assert_eq!(first.record.consensus_key.as_ref(), key.as_slice());

    let second = module
        .record_anchor(
            &context(6),
            &deployment_id(&key),
            &descendant(20, 0, 2, 10, 1),
        )
        .unwrap();
    assert_eq!(second.record.sequence, 2);
    assert_eq!(
        module.latest_anchor(&second.record.deployment).unwrap(),
        Some(second.record)
    );
}

#[test]
fn an_anchor_that_goes_backwards_is_refused() {
    let key = key(2);
    let mut module = registered(&[&key]);
    module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &deployment_id(&key), &revision(19, 0, 1)),
        Err(AnchorError::NotNewer {
            latest: 20,
            height: 19
        })
    );
}

#[test]
fn a_second_history_at_an_anchored_height_cannot_displace_the_first() {
    let key = key(3);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &deployment_id(&key), &revision(20, 0, 2)),
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
        .record_anchor(&context(3), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    assert!(!again.recorded);
    assert_eq!(again.record, first.record);
}

#[test]
fn a_lower_term_is_refused() {
    let key = key(4);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    module
        .record_anchor(&context(1), &deployment, &revision(20, 2, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &deployment, &descendant(30, 1, 3, 20, 1)),
        Err(AnchorError::LowerTerm { latest: 2, term: 1 })
    );
    module
        .record_anchor(&context(3), &deployment, &descendant(30, 3, 3, 20, 1))
        .unwrap();
}

#[test]
fn deployments_keep_separate_anchors() {
    let mut module = registered(&[&key(5), &key(50)]);
    module
        .record_anchor(&context(1), &deployment_id(&key(5)), &revision(20, 0, 1))
        .unwrap();
    let other = module
        .record_anchor(&context(2), &deployment_id(&key(50)), &revision(10, 0, 1))
        .unwrap();
    assert!(other.recorded);
    assert_eq!(other.record.sequence, 1);
    assert_ne!(deployment_id(&key(5)), deployment_id(&key(50)));
}

#[test]
fn only_a_registered_deployment_is_anchored() {
    let key = key(6);
    let deployment = deployment_id(&key);
    let mut module = VeraModule::new();
    assert_eq!(
        module.record_anchor(&context(1), &deployment, &revision(10, 0, 1)),
        Err(AnchorError::NotRegistered)
    );
    assert_eq!(
        module.record_fork(&context(1), &deployment, &revision(10, 0, 1)),
        Err(AnchorError::NotRegistered)
    );
    assert_eq!(module.latest_anchor(&deployment), Ok(None));

    let record = module
        .register_deployment(&registration(&key), 100)
        .unwrap();
    assert_eq!(record.deployment, deployment);
    assert_eq!(record.consensus_key.as_ref(), key.as_slice());
    assert_eq!(record.genesis_id, B256::repeat_byte(7));
    assert_eq!(record.registered_at, 100);
    assert_eq!(
        module.deployment(&deployment).unwrap(),
        Some(record.clone())
    );
    assert_eq!(
        DeploymentRecord::decode(&deployment, &record.encode()).unwrap(),
        record
    );
    assert_eq!(
        DeploymentRecord::decode(&B256::ZERO, &record.encode()),
        Err(AnchorError::MalformedRecord)
    );
    let anchored = module
        .record_anchor(&context(1), &deployment, &revision(10, 0, 1))
        .unwrap();
    assert_eq!(anchored.record.consensus_key.as_ref(), key.as_slice());
}

#[test]
fn a_registration_is_checked_and_only_its_operator_policy_can_be_replaced() {
    let key = key(14);
    let mut module = VeraModule::new();
    let mut short = registration(&key);
    short.consensus_key.truncate(20);
    let mut upper = registration(&key);
    upper.consensus_key = upper.consensus_key.to_uppercase();
    for malformed in [short, upper] {
        assert_eq!(
            module.register_deployment(&malformed, 1),
            Err(AnchorError::InvalidConsensusKey)
        );
    }
    let mut no_genesis = registration(&key);
    no_genesis.genesis_id = [0; 32];
    let mut no_operators = registration(&key);
    no_operators.operators.threshold = 2;
    for invalid in [no_genesis, no_operators] {
        assert_eq!(
            module.register_deployment(&invalid, 1),
            Err(AnchorError::InvalidRegistration)
        );
    }

    module.register_deployment(&registration(&key), 1).unwrap();
    let mut other_genesis = registration(&key);
    other_genesis.genesis_id = [8; 32];
    assert_eq!(
        module.register_deployment(&other_genesis, 2),
        Err(AnchorError::InvalidRegistration)
    );
    let mut rotated = registration(&key);
    rotated.operators.keys = vec![SUBMITTER.into()];
    let replaced = module.register_deployment(&rotated, 3).unwrap();
    assert_eq!(replaced.operators, rotated.operators);
    assert_eq!(replaced.registered_at, 1);
}

#[test]
fn a_submitter_needs_a_grant_and_stays_within_its_daily_quota() {
    let key = key(15);
    let deployment = deployment_id(&key);
    let grant = AnchorSubmitterGrant {
        deployment: deployment.0,
        submitter: SUBMITTER.into(),
        quota: 2,
    };
    let mut module = VeraModule::new();
    assert_eq!(
        module.set_anchor_submitter(&grant),
        Err(AnchorError::NotRegistered)
    );
    module.register_deployment(&registration(&key), 1).unwrap();
    for (submitter, quota) in [(SUBMITTER, 0), ("did:web:example.com", 1), ("did:key:z", 1)] {
        let invalid = AnchorSubmitterGrant {
            submitter: submitter.into(),
            quota,
            ..grant.clone()
        };
        assert_eq!(
            module.set_anchor_submitter(&invalid),
            Err(AnchorError::InvalidGrant)
        );
    }
    assert_eq!(
        module.charge_anchor_submission(&context(1), &deployment, SUBMITTER),
        Err(AnchorError::NotGranted)
    );

    module.set_anchor_submitter(&grant).unwrap();
    let charge = |module: &mut VeraModule, seconds: u64, submitter: &str| {
        let mut context = context(1);
        context.timestamp.seconds = seconds;
        module.charge_anchor_submission(&context, &deployment, submitter)
    };
    let day = 1_800_000_000 / 86_400 * 86_400;
    assert_eq!(charge(&mut module, day, SUBMITTER), Ok(()));
    assert_eq!(charge(&mut module, day + 86_399, SUBMITTER), Ok(()));
    assert_eq!(
        charge(&mut module, day + 86_399, SUBMITTER),
        Err(AnchorError::QuotaExceeded { quota: 2 })
    );
    let record = module
        .anchor_submitter(&deployment, SUBMITTER)
        .unwrap()
        .unwrap();
    assert_eq!(
        (record.quota, record.used, record.day),
        (2, 2, day / 86_400)
    );
    assert_eq!(record.remaining(day), 0);
    assert_eq!(record.remaining(day + 86_400), 2);
    // Another signer, and the signer for another deployment, have no grant.
    let other = SUBMITTER.replace("z6Mkha", "z6Mkhb");
    assert_eq!(
        charge(&mut module, day, &other),
        Err(AnchorError::NotGranted)
    );
    assert_eq!(
        module.charge_anchor_submission(&context(1), &B256::ZERO, SUBMITTER),
        Err(AnchorError::NotGranted)
    );

    // A raised quota keeps the day's count, and the next day starts at zero.
    module
        .set_anchor_submitter(&AnchorSubmitterGrant {
            quota: 3,
            ..grant.clone()
        })
        .unwrap();
    assert_eq!(charge(&mut module, day + 10, SUBMITTER), Ok(()));
    assert!(charge(&mut module, day + 10, SUBMITTER).is_err());
    assert_eq!(charge(&mut module, day + 86_400, SUBMITTER), Ok(()));

    let revocation = AnchorSubmitterRevocation {
        deployment: deployment.0,
        submitter: SUBMITTER.into(),
    };
    module.revoke_anchor_submitter(&revocation).unwrap();
    assert_eq!(
        module.revoke_anchor_submitter(&revocation),
        Err(AnchorError::NotGranted)
    );
    assert_eq!(
        charge(&mut module, day + 86_400, SUBMITTER),
        Err(AnchorError::NotGranted)
    );
}

#[test]
fn stored_records_must_name_their_deployment() {
    let mut module = registered(&[&key(8)]);
    let anchored = module
        .record_anchor(&context(1), &deployment_id(&key(8)), &revision(10, 0, 1))
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

    let mut foreign_key = anchored.record.clone();
    foreign_key.consensus_key = key(9).into();
    assert_eq!(
        AnchorRecord::decode(&foreign_key.deployment, &foreign_key.encode()),
        Err(AnchorError::MalformedRecord)
    );

    let mut short_key = anchored.record;
    short_key.consensus_key = vec![8; 10].into();
    short_key.deployment = deployment_id(&short_key.consensus_key);
    assert_eq!(
        AnchorRecord::decode(&short_key.deployment, &short_key.encode()),
        Err(AnchorError::MalformedRecord)
    );
}

#[test]
fn an_anchor_must_descend_from_the_latest_one() {
    let key = key(10);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    let refused = Err(AnchorError::NotDescendant {
        latest: 20,
        height: 30,
    });
    // No ancestor, another block at the anchored height, and the anchored block at another height.
    assert_eq!(
        module.record_anchor(&context(2), &deployment_id(&key), &revision(30, 0, 3)),
        refused
    );
    assert_eq!(
        module.record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(30, 0, 3, 20, 9)
        ),
        refused
    );
    assert_eq!(
        module.record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(30, 0, 3, 19, 1)
        ),
        refused
    );
    assert_eq!(
        module.latest_anchor(&first.record.deployment).unwrap(),
        Some(first.record)
    );
    let second = module
        .record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(30, 0, 3, 20, 1),
        )
        .unwrap();
    assert_eq!(second.record.sequence, 2);
    // The next anchor extends the second one, not the first.
    assert_eq!(
        module.record_anchor(
            &context(3),
            &deployment_id(&key),
            &descendant(40, 0, 4, 20, 1)
        ),
        Err(AnchorError::NotDescendant {
            latest: 30,
            height: 40
        })
    );
}

#[test]
fn a_block_that_leaves_the_anchored_history_is_recorded_as_a_fork() {
    let key = key(11);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    assert_eq!(
        module.record_fork(&context(1), &deployment, &revision(20, 0, 2)),
        Err(AnchorError::NoAnchor)
    );
    module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();

    // Another block at the anchored height.
    let same_height = module
        .record_fork(&context(2), &deployment_id(&key), &revision(20, 0, 2))
        .unwrap();
    assert_eq!(
        (
            same_height.sequence,
            same_height.anchored_height,
            same_height.height
        ),
        (1, 20, 20)
    );
    assert_eq!(same_height.anchored_block, B256::repeat_byte(1));
    assert_eq!(same_height.ancestor, B256::repeat_byte(2));
    assert_eq!(same_height.reported_at, 2);
    assert_eq!(
        module.record_fork(&context(3), &deployment_id(&key), &revision(20, 0, 2)),
        Err(AnchorError::ForkRecorded)
    );

    // A block above it whose ancestor at the anchored height is another block.
    let above = module
        .record_fork(
            &context(3),
            &deployment_id(&key),
            &descendant(25, 0, 5, 20, 2),
        )
        .unwrap();
    assert_eq!((above.height, above.ancestor), (25, B256::repeat_byte(2)));
    assert_eq!(
        module.forks(&deployment).unwrap(),
        vec![same_height, above.clone()]
    );
    assert_eq!(
        ForkRecord::decode(&deployment, &above.encode()).unwrap(),
        above
    );
    assert_eq!(
        ForkRecord::decode(&B256::ZERO, &above.encode()),
        Err(AnchorError::MalformedRecord)
    );

    let not_a_fork = |height| Err(AnchorError::NotAFork { latest: 20, height });
    // The anchored block, a descendant of it, an unproven block and one below the anchor.
    assert_eq!(
        module.record_fork(&context(4), &deployment_id(&key), &revision(20, 0, 1)),
        not_a_fork(20)
    );
    assert_eq!(
        module.record_fork(
            &context(4),
            &deployment_id(&key),
            &descendant(30, 0, 6, 20, 1)
        ),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(&context(4), &deployment_id(&key), &revision(30, 0, 7)),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(
            &context(4),
            &deployment_id(&key),
            &descendant(30, 0, 7, 19, 2)
        ),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(
            &context(4),
            &deployment_id(&key),
            &descendant(19, 0, 8, 18, 2)
        ),
        not_a_fork(19)
    );
    // The latest anchor is unchanged, and the next one still extends it.
    module
        .record_anchor(
            &context(5),
            &deployment_id(&key),
            &descendant(30, 0, 6, 20, 1),
        )
        .unwrap();
}

#[test]
fn every_anchor_stays_in_the_deployments_history() {
    let other = key(13);
    let key = key(12);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key, &other]);
    let first = module
        .record_anchor(&context(1), &deployment_id(&key), &revision(10, 0, 1))
        .unwrap();
    let second = module
        .record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(20, 0, 2, 10, 1),
        )
        .unwrap();
    // A resubmission and a refusal add nothing.
    module
        .record_anchor(
            &context(3),
            &deployment_id(&key),
            &descendant(20, 0, 2, 10, 1),
        )
        .unwrap();
    module
        .record_anchor(&context(3), &deployment_id(&key), &revision(30, 0, 3))
        .unwrap_err();
    module
        .record_anchor(&context(4), &deployment_id(&other), &revision(5, 0, 9))
        .unwrap();

    let entries: Vec<_> = module
        .store
        .prefix_scan(&anchor_history_prefix(&deployment))
        .iter()
        .map(|(stored, bytes)| AnchorEntry::decode(&deployment, stored, bytes).unwrap())
        .collect();
    assert_eq!(
        entries,
        [
            AnchorEntry::from(&first.record),
            AnchorEntry::from(&second.record)
        ]
    );
    assert_eq!(
        (
            entries[0].sequence,
            entries[0].height,
            entries[0].anchored_at
        ),
        (1, 10, 1)
    );
    assert_eq!(entries[1].module_state_root, B256::repeat_byte(2));
    assert_eq!(
        module.anchor_entry(&deployment, 2).unwrap().as_ref(),
        Some(&entries[1])
    );
    assert_eq!(module.anchor_entry(&deployment, 3), Ok(None));
    assert!(entries[1].encode().len() <= MAX_ANCHOR_ENTRY_BYTES);

    // An entry is the one its key names, and the latest anchor is no entry.
    let bytes = entries[0].encode();
    assert_eq!(
        AnchorEntry::decode(&deployment, &anchor_entry_key(&deployment, 2), &bytes),
        Err(AnchorError::MalformedRecord)
    );
    assert_eq!(
        AnchorEntry::decode(&B256::ZERO, &anchor_entry_key(&B256::ZERO, 1), &bytes),
        Err(AnchorError::MalformedRecord)
    );
    assert!(!anchor_key(&deployment).starts_with(&anchor_history_prefix(&deployment)));
}
