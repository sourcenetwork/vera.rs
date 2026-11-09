//! Certified bulletin lifecycle, bounded enumeration and collaborator revocation.

use std::time::Duration;

use alloy_sol_types::{SolCall, SolEvent};
use commonware_codec::Encode as _;
use vera_client::{BULLETIN_ADDRESS, BlsSigner, VeraClient};
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_modules::bulletin::{abi::IBulletin, keys};

async fn submit(
    client: &VeraClient,
    observer: &VeraClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
    success: bool,
) -> u64 {
    let calldata = call.abi_encode();
    let expected_post = if success && calldata.starts_with(&IBulletin::createPostCall::SELECTOR) {
        Some(IBulletin::createPostCall::abi_decode(&calldata).unwrap())
    } else {
        None
    };
    let wire = signer
        .sign_native_tx(BULLETIN_ADDRESS, calldata.into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (observed, local) = tokio::try_join!(
                observer.read_receipt(id, trusted),
                client.read_receipt(id, trusted),
            )
            .unwrap();
            if let (Some(proof), Some(_)) = (observed, local) {
                let request = serde_json::to_vec(&serde_json::json!({
                    "kind": "receipt", "trusted_key": hex::encode(trusted.encode()),
                    "submission": id, "proof": proof,
                }))
                .unwrap();
                let buffer = unsafe { vera_verifier::vera_verify(request.as_ptr(), request.len()) };
                let response: serde_json::Value = serde_json::from_slice(unsafe {
                    std::slice::from_raw_parts(buffer.data, buffer.len)
                })
                .unwrap();
                unsafe { vera_verifier::vera_buffer_free(buffer) };
                assert!(response.get("result").is_some(), "{response}");
                let receipt = proof.verify(id, trusted).unwrap();
                assert_eq!(receipt.success(), success, "{receipt:?}");
                if let Some(post) = &expected_post {
                    assert_eq!(receipt.logs().len(), 1);
                    let event = IBulletin::PostCreated::decode_log(&receipt.logs()[0]).unwrap();
                    let expected =
                        keys::generate_post_id(&keys::namespace_id(&post.namespace), &post.payload);
                    assert_eq!(
                        event.data.postId,
                        expected.parse::<alloy_primitives::B256>().unwrap()
                    );
                    assert_eq!(event.data.artifact, post.artifact);
                }
                break proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

fn post(namespace: &str, payload: &[u8]) -> IBulletin::createPostCall {
    IBulletin::createPostCall {
        namespace: namespace.into(),
        payload: payload.to_vec().into(),
        proof: vec![1, 2, 3].into(),
        artifact: "bulletin/conformance".into(),
    }
}

#[tokio::test]
async fn certified_bulletin_reads_follow_grants_pages_and_restart() {
    let deployment = 9065;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
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
    let observed = cluster.observe(Duration::from_millis(100));
    observed
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let writer = VeraClient::new(cluster.node(0).rpc_url());
    let reader = VeraClient::new(cluster.node(3).rpc_url());
    let owner = BlsSigner::new(7u64.into(), deployment).unwrap();
    let collaborator = BlsSigner::new(8u64.into(), deployment).unwrap();
    let absent = reader
        .read_bulletin_namespace("team", 0, &trusted)
        .await
        .unwrap();
    assert!(absent.value.is_none());
    assert!(
        reader
            .list_bulletin_namespaces(None, 1, absent.revision, &trusted)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert!(
        reader
            .read_bulletin_policy_id(absent.revision, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let rejected = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::registerNamespaceCall {
            namespace: String::new(),
        },
        false,
    )
    .await;
    assert!(
        reader
            .read_bulletin_policy_id(rejected, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    assert!(
        reader
            .list_bulletin_namespaces(None, 1, rejected, &trusted)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    let mut minimum = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::registerNamespaceCall {
            namespace: "team".into(),
        },
        true,
    )
    .await;
    let bulletin_policy = reader
        .read_bulletin_policy_id(minimum, &trusted)
        .await
        .unwrap();
    let policy_id = bulletin_policy.value.unwrap();
    let policy = reader
        .read_policy(policy_id, bulletin_policy.revision, &trusted)
        .await
        .unwrap();
    assert_eq!(policy.value.unwrap().policy.id, hex::encode(policy_id));
    let namespace = reader
        .read_bulletin_namespace("team", minimum, &trusted)
        .await
        .unwrap();
    let namespace = namespace.value.unwrap();
    assert_eq!(namespace.id, "bulletin/team");
    assert_eq!(namespace.owner_did, owner.did());
    assert_eq!(namespace.created_at.block_height, minimum);
    let denied = b"before grant";
    minimum = submit(
        &writer,
        &reader,
        &collaborator,
        &trusted,
        post(namespace.id.as_str(), denied),
        false,
    )
    .await;
    assert!(
        reader
            .read_bulletin_post(
                namespace.id.as_str(),
                &keys::generate_post_id("bulletin/team", denied),
                minimum,
                &trusted
            )
            .await
            .unwrap()
            .value
            .is_none()
    );
    minimum = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::addCollaboratorCall {
            namespace: namespace.id.as_str().into(),
            collaboratorDid: collaborator.did().into(),
        },
        true,
    )
    .await;
    assert_eq!(
        reader
            .read_bulletin_collaborator(
                namespace.id.as_str(),
                collaborator.did(),
                minimum,
                &trusted
            )
            .await
            .unwrap()
            .value
            .unwrap()
            .did,
        collaborator.did()
    );
    let collaborators = reader
        .list_bulletin_collaborators(namespace.id.as_str(), None, 1, minimum, &trusted)
        .await
        .unwrap();
    assert_eq!(collaborators.records.len(), 1);
    assert!(collaborators.continuation.is_none());
    for payload in [b"first".as_slice(), b"second"] {
        let mut request = post(namespace.id.as_str(), payload);
        if payload == b"first" {
            request.proof = Default::default();
        }
        let expected_proof = request.proof.clone();
        minimum = submit(&writer, &reader, &collaborator, &trusted, request, true).await;
        let record = reader
            .read_bulletin_post(
                namespace.id.as_str(),
                &keys::generate_post_id("bulletin/team", payload),
                minimum,
                &trusted,
            )
            .await
            .unwrap()
            .value
            .unwrap();
        assert_eq!(record.payload, payload);
        assert_eq!(record.proof.as_slice(), expected_proof.as_ref());
        assert_eq!(record.creator_did, collaborator.did());
    }
    let first = reader
        .list_bulletin_posts(namespace.id.as_str(), None, 1, minimum, &trusted)
        .await
        .unwrap();
    assert_eq!(first.records.len(), 1);
    let next = first.continuation.unwrap();
    assert!(
        reader
            .list_bulletin_posts("other", Some(next.clone()), 1, minimum, &trusted)
            .await
            .is_err()
    );
    let last = reader
        .list_bulletin_posts(
            namespace.id.as_str(),
            Some(next),
            1,
            first.revision,
            &trusted,
        )
        .await
        .unwrap();
    assert_eq!(last.records.len(), 1);
    assert!(last.continuation.is_none());
    assert!(first.records[0].id < last.records[0].id);
    minimum = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::removeCollaboratorCall {
            namespace: namespace.id.as_str().into(),
            collaboratorDid: collaborator.did().into(),
        },
        true,
    )
    .await;
    assert!(
        reader
            .read_bulletin_collaborator(
                namespace.id.as_str(),
                collaborator.did(),
                minimum,
                &trusted
            )
            .await
            .unwrap()
            .value
            .is_none()
    );
    assert!(
        reader
            .list_bulletin_collaborators(namespace.id.as_str(), None, 1, minimum, &trusted)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    submit(
        &writer,
        &reader,
        &collaborator,
        &trusted,
        post(namespace.id.as_str(), b"after revocation"),
        false,
    )
    .await;
    minimum = namespace_isolation(&writer, &reader, &owner, &collaborator, &trusted).await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    assert_eq!(
        reader
            .read_bulletin_policy_id(minimum, &trusted)
            .await
            .unwrap()
            .value,
        Some(policy_id)
    );
    let restored = reader
        .list_bulletin_posts(namespace.id.as_str(), None, 2, minimum, &trusted)
        .await
        .unwrap();
    assert_eq!(
        restored.records,
        [first.records[0].clone(), last.records[0].clone()]
    );
    assert!(restored.continuation.is_none());
    assert!(
        reader
            .read_bulletin_collaborator(
                namespace.id.as_str(),
                collaborator.did(),
                minimum,
                &trusted
            )
            .await
            .unwrap()
            .value
            .is_none()
    );
    for namespace in ["a/b", "a|b", "a%7Cb"] {
        let posts = reader
            .list_bulletin_posts(namespace, None, 2, minimum, &trusted)
            .await
            .unwrap();
        assert_eq!(posts.records.len(), 1);
        assert_eq!(posts.records[0].namespace, format!("bulletin/{namespace}"));
        let grant = reader
            .read_bulletin_collaborator(namespace, collaborator.did(), minimum, &trusted)
            .await
            .unwrap();
        assert_eq!(grant.value.is_some(), namespace != "a|b");
    }
    let untrusted = *KeySet::builder()
        .seed(deployment + 1)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    assert!(
        reader
            .read_bulletin_namespace(namespace.id.as_str(), minimum, &untrusted)
            .await
            .is_err()
    );
}

async fn namespace_isolation(
    writer: &VeraClient,
    reader: &VeraClient,
    owner: &BlsSigner,
    collaborator: &BlsSigner,
    trusted: &ConsensusPublicKey,
) -> u64 {
    for namespace in ["a/b", "a|b", "a%7Cb"] {
        submit(
            writer,
            reader,
            owner,
            trusted,
            IBulletin::registerNamespaceCall {
                namespace: namespace.into(),
            },
            true,
        )
        .await;
        submit(
            writer,
            reader,
            owner,
            trusted,
            IBulletin::addCollaboratorCall {
                namespace: namespace.into(),
                collaboratorDid: collaborator.did().into(),
            },
            true,
        )
        .await;
        let minimum = submit(
            writer,
            reader,
            collaborator,
            trusted,
            post(namespace, b"shared"),
            true,
        )
        .await;
        let posts = reader
            .list_bulletin_posts(namespace, None, 2, minimum, trusted)
            .await
            .unwrap();
        assert_eq!(posts.records.len(), 1);
        assert_eq!(posts.records[0].namespace, format!("bulletin/{namespace}"));
    }
    submit(
        writer,
        reader,
        owner,
        trusted,
        IBulletin::removeCollaboratorCall {
            namespace: "a|b".into(),
            collaboratorDid: collaborator.did().into(),
        },
        true,
    )
    .await
}
