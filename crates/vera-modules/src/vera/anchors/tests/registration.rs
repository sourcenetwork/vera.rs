//! Registered deployments and the signers granted to submit for them.

use super::*;

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
