//! Two workers act for one secp256k1 key under different `did:key` spellings,
//! and a second node proves a single owner and one decision per actor.

#[path = "one_actor_spelling/support.rs"]
mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use k256::ecdsa::SigningKey;
use support::*;
use vera_acp::{Relationship, Subject};
use vera_client::{
    BULLETIN_ADDRESS, BlsSigner, ModuleId, PERMISSION_LIMITS, RECORD_PROOF_BYTES, UnsignedToken,
    VeraClient,
};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_identity::Did;
use vera_modules::acp::{
    abi::IAcp, delegated_operation::DelegatedOperation, operation::operation_key, types::PolicyCmd,
};
use vera_modules::bulletin::abi::IBulletin;
use vera_permission::DecisionOperation;

#[tokio::test]
async fn workers_under_different_spellings_act_for_one_owner() {
    let deployment = 9092;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let replica = VeraClient::new(cluster.node(1).rpc_url());
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    for (spellings, seed) in [(OWNER, 42), (READER, 43)] {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let canonical = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            key.verifying_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        assert_eq!(spellings[0], canonical);
        for spelling in spellings {
            assert_eq!(vera_crypto::actor::canonical_did(spelling), canonical);
        }
    }
    // Each worker holds delegations that name the owner in its own spelling.
    let compressed = (BlsSigner::new(7u64.into(), deployment).unwrap(), OWNER[0]);
    let uncompressed = (BlsSigner::new(8u64.into(), deployment).unwrap(), OWNER[1]);
    let genesis = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse::<alloy_primitives::B256>()
        .unwrap()
        .0;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let delegation = |(worker, issuer): &(BlsSigner, &str), scope| {
        let unsigned =
            UnsignedToken::delegation(issuer, worker.did(), deployment, now, now + 120, scope);
        sign(&key, unsigned.unwrap())
    };
    let operation =
        |(worker, issuer): &(BlsSigner, &str), entropy, bound: &DelegatedOperation<'_>| {
            let mut id = [entropy; 32];
            id[..8].copy_from_slice(&(now + 120).to_be_bytes());
            let claims = JwtClaims {
                iss: (*issuer).into(),
                sub: worker.did().into(),
                exp: now + 120,
                aud: format!("vera:{deployment}"),
                scope: bound.scope(),
                iat: now,
                nbf: now,
                relay: None,
                request: Some(OperationClaim {
                    id: OperationId(id),
                    digest: bound.digest().unwrap(),
                    genesis_id: genesis,
                }),
            };
            (
                OperationId(id),
                sign(&key, UnsignedToken::operation(&claims).unwrap()),
            )
        };

    let created = submit(
        &client,
        &uncompressed.0,
        &trusted,
        IAcp::bearerCreatePolicyCall {
            bearerToken: delegation(&uncompressed, DelegationScope::CreatePolicy),
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
        },
    )
    .await;
    let policy = client
        .read_policy_page(None, 1, created, &trusted)
        .await
        .unwrap()
        .records
        .remove(0);
    assert_eq!(policy.metadata.owner_did, OWNER[0]);
    assert_eq!(policy.metadata.tx_signer, uncompressed.0.did());
    let policy = policy.policy.id;
    let command = |token: String, command: &PolicyCmd| IAcp::bearerPolicyCmdCall {
        policyId: policy.parse().unwrap(),
        bearerToken: token,
        cmd: serde_json::to_vec(command).unwrap().into(),
    };

    let object = report();
    let register = PolicyCmd::RegisterObject(object.clone());
    let bound = DelegatedOperation::PolicyCommand(&policy, &register);
    let (_, token) = operation(&compressed, 1, &bound);
    submit(&client, &compressed.0, &trusted, command(token, &register)).await;
    let (_, retry) = operation(&uncompressed, 1, &bound);
    let registered = submit(
        &client,
        &uncompressed.0,
        &trusted,
        command(retry, &register),
    )
    .await;

    let prefix = vera_client::object_owner_prefix(&policy, &object).unwrap();
    let ownership = certified(|| {
        replica.read_current_policy_prefix(
            &policy,
            &prefix,
            registered,
            &trusted,
            RECORD_PROOF_BYTES,
        )
    })
    .await;
    let owner = ownership
        .verify_object_owner(&policy, &object, registered, &trusted)
        .unwrap()
        .unwrap();
    assert_eq!(owner.0.as_str(), OWNER[0]);

    let reader = |spelling: &str| {
        Relationship::with_entity("file", "report", "reader", Did::new(spelling).unwrap())
    };
    let granted = submit(
        &client,
        &uncompressed.0,
        &trusted,
        command(
            delegation(&uncompressed, DelegationScope::PolicyCommands),
            &PolicyCmd::SetRelationship(reader(READER[3])),
        ),
    )
    .await;
    let decide = |actor: &'static str, minimum, expected| {
        let (replica, policy) = (&replica, &policy);
        async move {
            let request = read(actor);
            let (revision, allowed) = certified(|| {
                replica.verify_current_access(
                    policy,
                    &request,
                    minimum,
                    &trusted,
                    PERMISSION_LIMITS,
                )
            })
            .await;
            assert!(revision.height >= minimum);
            assert_eq!(allowed, expected, "{actor} at revision {}", revision.height);
        }
    };
    let relationships = |minimum| {
        let (replica, policy) = (&replica, policy.parse().unwrap());
        async move {
            let page =
                certified(|| replica.read_relationship_page(policy, None, 16, minimum, &trusted));
            let page = page.await;
            assert!(page.continuation.is_none());
            page.records
        }
    };
    for actor in OWNER.into_iter().chain(READER) {
        decide(actor, granted, true).await;
    }
    decide(STRANGER, granted, false).await;
    let subjects: Vec<_> = relationships(granted)
        .await
        .into_iter()
        .map(|record| (record.relationship.relation, record.relationship.subject))
        .collect();
    let entity = |did: &str| Subject::Entity(Did::new(did).unwrap());
    assert_eq!(subjects.len(), 2);
    assert!(subjects.contains(&("owner".into(), entity(OWNER[0]))));
    assert!(subjects.contains(&("reader".into(), entity(READER[0]))));

    let request = read(READER[2]);
    let recorded = DelegatedOperation::CheckAccess(&policy, &request);
    let (id, token) = operation(&compressed, 2, &recorded);
    let decided = submit(
        &client,
        &compressed.0,
        &trusted,
        IAcp::bearerCheckAccessCall {
            bearerToken: token,
            policyId: policy.parse().unwrap(),
            request: serde_json::to_vec(&request).unwrap().into(),
        },
    )
    .await;
    for caller in OWNER {
        let key = operation_key(caller, id).unwrap();
        let record = certified(|| {
            replica.read_current_record(ModuleId::Acp, &key, decided, &trusted, RECORD_PROOF_BYTES)
        })
        .await;
        let expected = DecisionOperation {
            deployment_id: deployment,
            caller: caller.into(),
            operation_id: id.0.into(),
            policy_id: policy.clone(),
            request: request.clone(),
        };
        let outcome = record
            .verify_decision_outcome(&expected, decided, &trusted)
            .unwrap()
            .expect("the decision outcome is recorded once for every spelling");
        assert_eq!(outcome.record.decision.actor, READER[0]);
        assert_eq!(outcome.record.decision.creator, compressed.0.did());
    }

    let revoked = submit(
        &client,
        &compressed.0,
        &trusted,
        command(
            delegation(&compressed, DelegationScope::PolicyCommands),
            &PolicyCmd::DeleteRelationship(reader(READER[1])),
        ),
    )
    .await;
    for actor in OWNER {
        decide(actor, revoked, true).await;
    }
    for actor in READER {
        decide(actor, revoked, false).await;
    }
    let remaining = relationships(revoked).await;
    assert_eq!(remaining.len(), 1, "revocation leaves no second tuple");
    assert_eq!(remaining[0].relationship.subject, entity(OWNER[0]));

    let namespace = "bulletin/spellings";
    let collaborator = |minimum| {
        let replica = &replica;
        async move {
            let mut records = Vec::new();
            for spelling in READER {
                let read =
                    || replica.read_bulletin_collaborator(namespace, spelling, minimum, &trusted);
                records.push(certified(read).await.value.map(|record| record.did));
            }
            records
        }
    };
    submit_to(
        BULLETIN_ADDRESS,
        &client,
        &compressed.0,
        &trusted,
        IBulletin::registerNamespaceCall {
            namespace: "spellings".into(),
        },
    )
    .await;
    let added = submit_to(
        BULLETIN_ADDRESS,
        &client,
        &compressed.0,
        &trusted,
        IBulletin::addCollaboratorCall {
            namespace: namespace.into(),
            collaboratorDid: READER[1].into(),
        },
    )
    .await;
    assert_eq!(
        collaborator(added).await,
        vec![Some(READER[0].to_owned()); 4]
    );
    let removed = submit_to(
        BULLETIN_ADDRESS,
        &client,
        &compressed.0,
        &trusted,
        IBulletin::removeCollaboratorCall {
            namespace: namespace.into(),
            collaboratorDid: READER[2].into(),
        },
    )
    .await;
    assert_eq!(collaborator(removed).await, vec![None; 4]);
}
