//! Canonical integration test — full module lifecycle.
//!
//! Exercises native BLS requests from two signers through every module:
//! ACP (policy, object, relationship, access control),
//! Bulletin (namespace, collaborator, post),
//! Vera (token queries and invalidation), and cross-signer verification.
//!
//! One cluster startup, one comprehensive test.
//!
//! Requires `cargo build -p verad` before running.

#[path = "support/acp_v1.rs"]
mod acp_v1;
#[path = "support/broadcast.rs"]
mod broadcast;
#[path = "support/native_receipt.rs"]
mod native_receipt;
#[path = "support/receipt.rs"]
mod receipt;

use std::time::Duration;

use alloy_primitives::{Address, B256, FixedBytes};
use alloy_sol_types::{SolCall, SolEvent};

use jsonrpsee::core::client::SubscriptionClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use vera_client::{
    ACP_ADDRESS, BULLETIN_ADDRESS, BlsSigner, ClientError, NativeReceipt, PolicyMarshalingType,
    VERA_ADDRESS, VeraClient,
};
use vera_domain::GossipHeader;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_e2e::observe::ClusterAssertions;
use vera_modules::acp::abi::IAcp;
use vera_modules::bulletin::abi::IBulletin;
use vera_modules::vera::abi::IVera;

/// Hardhat account 1 private key (the end user who signs bearer tokens).
const HARDHAT_KEY_1: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Minimal DPI-compliant ACP policy for testing.
const TEST_POLICY_YAML: &str = "\
name: test-policy
meta:
  z: last
  a: first
resources:
  - name: document
    relations:
      - name: owner
      - name: reader
    permissions:
      - name: read
        expr: owner + reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
";

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
}

async fn broadcast_native_tx(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &BlsSigner,
    target: Address,
    calldata: Vec<u8>,
) -> NativeReceipt {
    broadcast::native(cluster, client, signer, target, calldata).await
}

/// Assert common fields on a native request's receipt.
fn assert_bls_receipt(receipt: &NativeReceipt, target: Address, signer: &str, label: &str) {
    assert_eq!(receipt.status, 1, "{label} should succeed");
    assert!(
        receipt.block_number > 0,
        "{label} should be included in a real block"
    );
    assert!(receipt.gas_used > 0, "{label} should consume gas");
    assert_ne!(
        receipt.transaction_hash,
        B256::ZERO,
        "{label} tx hash should be non-degenerate"
    );
    assert_eq!(
        receipt.from,
        Address::ZERO,
        "{label} receipt 'from' should be Address::ZERO for native txs"
    );
    assert_eq!(
        receipt.to,
        Some(target),
        "{label} receipt 'to' should be the target module"
    );
    assert_eq!(
        receipt.signer_did.as_deref(),
        Some(signer),
        "{label} receipt should name its signer"
    );
    assert!(
        receipt.native_nonce.is_some(),
        "{label} receipt should carry the native sequence"
    );
}

/// Assert that a receipt contains at least one log matching the expected module address and event topic.
fn assert_event_log(receipt: &NativeReceipt, address: Address, topic: B256, label: &str) {
    assert!(!receipt.logs.is_empty(), "{label} should emit event logs");
    let log = &receipt.logs[0];
    assert_eq!(
        log.address, address,
        "{label} log address should be the module"
    );
    assert!(!log.topics.is_empty(), "{label} log should have topics");
    assert_eq!(
        log.topics[0], topic,
        "{label} log topic[0] should match event signature"
    );
}

/// Full module lifecycle: ACP + Bulletin, owner + BLS, writes + queries.
#[tokio::test]
async fn canonical_module_test() {
    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9001;
    let trusted = *KeySet::builder()
        .nodes(4)
        .seed(chain_id)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let genesis = GenesisBuilder::devnet();

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .seed(chain_id)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("cluster should start");

    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("cluster should become healthy");

    let state = cluster.observe(Duration::from_millis(200));
    state
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("should reach height 3");

    let client = VeraClient::new(cluster.node(0).rpc_url());

    let status = client
        .node_status()
        .await
        .expect("vera_nodeStatus should work");
    assert_eq!(status.chain_id, chain_id, "chain ID should match");

    // The owner creates the policy the other signer is later granted access to.
    let owner = BlsSigner::random(chain_id).expect("random BLS signer");
    let bls_signer = BlsSigner::random(chain_id).expect("random BLS signer");

    let owner_did = owner.did().to_owned();
    let bls_did = bls_signer.did().to_owned();

    // Track block numbers across all receipts — must be monotonically non-decreasing.
    let mut max_block = 0u64;

    // ── A: ACP Policy Creation (owner + BLS in parallel) ────────────

    let owner_nonce = vera_client::random_policy_nonce();
    let owner_policy_id = parse_policy_id(
        &vera_client::predict_policy_id(
            TEST_POLICY_YAML,
            &PolicyMarshalingType::ShortYaml,
            &owner_nonce,
            &owner_did,
        )
        .expect("test policy should compile"),
    );
    let a1_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: owner_nonce.0.into(),
    }
    .abi_encode();
    let a2_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    }
    .abi_encode();

    let (owner_receipt, bls_receipt) = tokio::join!(
        broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, a1_calldata),
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, a2_calldata),
    );

    // A1 assertions
    assert_bls_receipt(
        &owner_receipt,
        ACP_ADDRESS,
        &owner_did,
        "owner create_policy",
    );
    assert_event_log(
        &owner_receipt,
        ACP_ADDRESS,
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "A1 owner createPolicy",
    );
    assert_eq!(
        owner_receipt.native_nonce,
        Some(0),
        "A1 is the owner's first request"
    );
    let nonce_after_a1 = client
        .get_native_nonce(&owner_did)
        .await
        .expect("vera_getNativeNonce should work");
    assert_eq!(
        nonce_after_a1, 1,
        "owner sequence should advance to 1 after its first request"
    );

    // A2 assertions
    assert_bls_receipt(&bls_receipt, ACP_ADDRESS, &bls_did, "BLS create_policy");
    assert_event_log(
        &bls_receipt,
        ACP_ADDRESS,
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "A2 BLS createPolicy",
    );

    // Block number monotonicity
    max_block = max_block
        .max(owner_receipt.block_number)
        .max(bls_receipt.block_number);

    // A3. get_policy_ids → 2 policies
    state
        .wait_for_height(max_block + 1, Duration::from_secs(15))
        .await
        .expect("cluster should advance past create_policy blocks");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert_eq!(
        policy_ids.len(),
        2,
        "should have 2 policies (owner + BLS), got: {policy_ids:?}"
    );

    assert!(
        policy_ids
            .iter()
            .any(|id| parse_policy_id(id) == owner_policy_id),
        "the owner's policy should have its predicted id, got: {policy_ids:?}"
    );

    // A4. Policy content verification
    for (i, policy_id_str) in policy_ids.iter().enumerate() {
        let policy_id = parse_policy_id(policy_id_str);

        let policy_bytes = client
            .get_policy(policy_id)
            .await
            .unwrap_or_else(|e| panic!("get_policy({policy_id_str}) should succeed: {e}"));
        assert!(
            !policy_bytes.is_empty(),
            "policy {i} bytes should not be empty"
        );

        let record: serde_json::Value = serde_json::from_slice(&policy_bytes)
            .unwrap_or_else(|e| panic!("policy {i} should be valid JSON: {e}"));

        let name = record
            .pointer("/policy/name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(name, "test-policy", "policy {i} name should match");

        let resources = record.pointer("/policy/resources");
        assert!(
            resources.is_some(),
            "policy {i} should have resources field"
        );
        let resources_str = serde_json::to_string(resources.unwrap()).unwrap();
        assert!(
            resources_str.contains("document"),
            "policy {i} resources should contain 'document'"
        );

        let raw_policy = record
            .get("raw_policy")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            raw_policy.contains("test-policy"),
            "policy {i} raw_policy should contain the original YAML"
        );
    }

    // ── B: ACP Object Registration (owner + BLS in parallel) ───────

    let b1_calldata = IAcp::registerObjectCall {
        policyId: owner_policy_id,
        objectId: "doc-owner".into(),
        resource: "document".into(),
    }
    .abi_encode();
    let b2_calldata = IAcp::registerObjectCall {
        policyId: owner_policy_id,
        objectId: "doc-bls".into(),
        resource: "document".into(),
    }
    .abi_encode();

    let (b1_receipt, b2_receipt) = tokio::join!(
        broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, b1_calldata),
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, b2_calldata),
    );

    assert_bls_receipt(
        &b1_receipt,
        ACP_ADDRESS,
        &owner_did,
        "owner register_object",
    );
    assert_event_log(
        &b1_receipt,
        ACP_ADDRESS,
        IAcp::ObjectRegistered::SIGNATURE_HASH,
        "B1 owner registerObject",
    );
    assert_bls_receipt(&b2_receipt, ACP_ADDRESS, &bls_did, "BLS register_object");
    assert_event_log(
        &b2_receipt,
        ACP_ADDRESS,
        IAcp::ObjectRegistered::SIGNATURE_HASH,
        "B2 BLS registerObject",
    );

    assert!(
        b1_receipt.block_number >= max_block,
        "B1 block should be >= previous max (b1={}, max={max_block})",
        b1_receipt.block_number
    );
    assert!(
        b2_receipt.block_number >= max_block,
        "B2 block should be >= previous max (b2={}, max={max_block})",
        b2_receipt.block_number
    );
    max_block = max_block
        .max(b1_receipt.block_number)
        .max(b2_receipt.block_number);

    // Verify both objects registered
    let ((owner_registered, _), (bls_registered, _)) = tokio::join!(
        async {
            client
                .get_object_owner(owner_policy_id, "document", "doc-owner")
                .await
                .expect("get_object_owner(doc-owner) should succeed")
        },
        async {
            client
                .get_object_owner(owner_policy_id, "document", "doc-bls")
                .await
                .expect("get_object_owner(doc-bls) should succeed")
        },
    );
    assert!(owner_registered, "doc-owner should be registered");
    assert!(bls_registered, "doc-bls should be registered");

    // ── C: ACP Relationships + Access ────────────────────────────

    // C1. owner set_relationship: grant bls_did "reader" on "doc-owner"
    let c1_calldata = IAcp::setRelationshipCall {
        policyId: owner_policy_id,
        resource: "document".into(),
        objectId: "doc-owner".into(),
        relation: "reader".into(),
        actor: bls_did.clone(),
    }
    .abi_encode();
    let c1_receipt = broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, c1_calldata).await;
    assert_eq!(
        c1_receipt.status, 1,
        "owner set_relationship should succeed"
    );
    assert_event_log(
        &c1_receipt,
        ACP_ADDRESS,
        IAcp::RelationshipSet::SIGNATURE_HASH,
        "C1 owner setRelationship",
    );
    assert!(
        c1_receipt.block_number >= max_block,
        "C1 block should be >= previous max"
    );
    max_block = max_block.max(c1_receipt.block_number);

    // C2-C4. Verify relationship and access checks in parallel
    let (has_rel, can_read, can_update, owner_can_read) = tokio::join!(
        async {
            client
                .has_relationship(owner_policy_id, "document", "doc-owner", "reader", &bls_did)
                .await
                .expect("has_relationship should succeed")
        },
        async {
            client
                .verify_access_request(
                    owner_policy_id,
                    vec!["document".into()],
                    vec!["doc-owner".into()],
                    vec!["read".into()],
                    &bls_did,
                )
                .await
                .expect("verify_access_request(read) should succeed")
        },
        async {
            client
                .verify_access_request(
                    owner_policy_id,
                    vec!["document".into()],
                    vec!["doc-owner".into()],
                    vec!["update".into()],
                    &bls_did,
                )
                .await
                .expect("verify_access_request(update) should succeed")
        },
        async {
            client
                .verify_access_request(
                    owner_policy_id,
                    vec!["document".into()],
                    vec!["doc-owner".into()],
                    vec!["read".into()],
                    &owner_did,
                )
                .await
                .expect("verify_access_request(owner read) should succeed")
        },
    );
    assert!(has_rel, "bls_did should have reader relationship");
    assert!(can_read, "bls_did should have read access");
    assert!(!can_update, "bls_did should NOT have update access");
    assert!(owner_can_read, "owner should have read access");

    // ── D: ACP Delete + Access Revocation ────────────────────────

    // D1. delete_relationship — revocation requires management authority, so the
    // owner signer (policy + doc-owner owner) revokes the grant it created in C1.
    let d1_calldata = IAcp::deleteRelationshipCall {
        policyId: owner_policy_id,
        resource: "document".into(),
        objectId: "doc-owner".into(),
        relation: "reader".into(),
        actor: bls_did.clone(),
    }
    .abi_encode();
    let d1_receipt = broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, d1_calldata).await;
    assert_eq!(d1_receipt.status, 1, "delete_relationship should succeed");
    assert_event_log(
        &d1_receipt,
        ACP_ADDRESS,
        IAcp::RelationshipDeleted::SIGNATURE_HASH,
        "D1 deleteRelationship",
    );
    assert!(
        d1_receipt.block_number >= max_block,
        "D1 block should be >= previous max"
    );
    max_block = max_block.max(d1_receipt.block_number);

    // D2-D4. Verify deletion and access revocation in parallel
    let (has_rel, can_read, owner_can_read) = tokio::join!(
        async {
            client
                .has_relationship(owner_policy_id, "document", "doc-owner", "reader", &bls_did)
                .await
                .expect("has_relationship should succeed")
        },
        async {
            client
                .verify_access_request(
                    owner_policy_id,
                    vec!["document".into()],
                    vec!["doc-owner".into()],
                    vec!["read".into()],
                    &bls_did,
                )
                .await
                .expect("verify_access_request should succeed")
        },
        async {
            client
                .verify_access_request(
                    owner_policy_id,
                    vec!["document".into()],
                    vec!["doc-owner".into()],
                    vec!["read".into()],
                    &owner_did,
                )
                .await
                .expect("verify_access_request(owner) should succeed")
        },
    );
    assert!(!has_rel, "bls_did reader relationship should be deleted");
    assert!(
        !can_read,
        "bls_did should NOT have read access after revocation"
    );
    assert!(owner_can_read, "owner should still have read access");

    // ── D.5: Bearer Token ACP Operations ──────────────────────────

    // Account 1 is the "end user" — signs the JWT but never submits requests.
    // The owner signer is the "defra node" — submits requests carrying the bearer token.
    let user_key =
        vera_client::Secp256k1SigningKey::from_slice(&hex::decode(HARDHAT_KEY_1).unwrap())
            .expect("valid signing key");
    let user_did = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        user_key.verifying_key().to_sec1_point(true).as_bytes(),
    )
    .expect("valid DID");

    let bearer_token =
        vera_client::create_bearer_token(&user_key, &owner_did, chain_id, 0, 9_999_999_999)
            .expect("create bearer token");

    // D5.1. Register object via bearer token — account 1 (JWT issuer) becomes owner
    let d5_cmd =
        vera_modules::acp::types::PolicyCmd::RegisterObject(vera_modules::acp::types::Object {
            resource: "document".into(),
            id: "doc-bearer".into(),
        });
    let d5_cmd_bytes = serde_json::to_vec(&d5_cmd).expect("serialize PolicyCmd");
    let d5_calldata = IAcp::bearerPolicyCmdCall {
        bearerToken: bearer_token.clone(),
        policyId: owner_policy_id,
        cmd: d5_cmd_bytes.into(),
    }
    .abi_encode();
    let d5_receipt = broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, d5_calldata).await;
    assert_eq!(
        d5_receipt.status, 1,
        "bearer register_object should succeed"
    );
    assert!(
        d5_receipt.block_number >= max_block,
        "D5.1 block should be >= previous max"
    );
    max_block = max_block.max(d5_receipt.block_number);

    // D5.2. Verify object owner is the JWT issuer (account 1), not the tx signer (account 0)
    let (bearer_registered, bearer_owner_bytes) = client
        .get_object_owner(owner_policy_id, "document", "doc-bearer")
        .await
        .expect("get_object_owner(doc-bearer) should succeed");
    assert!(bearer_registered, "doc-bearer should be registered");
    let bearer_owner_json: serde_json::Value =
        serde_json::from_slice(&bearer_owner_bytes).expect("owner record should be valid JSON");
    let bearer_owner_did = bearer_owner_json
        .get("metadata")
        .and_then(|m| m.get("owner_did"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        bearer_owner_did, user_did,
        "bearer-registered object owner should be the JWT issuer (account 1), not the tx signer"
    );

    // D5.3. Set relationship via bearer token — grant bls_did "reader" on doc-bearer
    let d5_rel = vera_acp::Relationship::new(
        "document",
        "doc-bearer",
        "reader",
        vera_acp::Subject::entity(vera_identity::Did::new(&bls_did).expect("valid DID")),
    );
    let d5_set_cmd = vera_modules::acp::types::PolicyCmd::SetRelationship(d5_rel);
    let d5_set_bytes = serde_json::to_vec(&d5_set_cmd).expect("serialize PolicyCmd");
    let d5_set_calldata = IAcp::bearerPolicyCmdCall {
        bearerToken: bearer_token.clone(),
        policyId: owner_policy_id,
        cmd: d5_set_bytes.into(),
    }
    .abi_encode();
    let d5_set_receipt =
        broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, d5_set_calldata).await;
    assert_eq!(
        d5_set_receipt.status, 1,
        "bearer set_relationship should succeed"
    );
    assert!(
        d5_set_receipt.block_number >= max_block,
        "D5.3 block should be >= previous max"
    );
    max_block = max_block.max(d5_set_receipt.block_number);

    // D5.4. Verify the relationship was set
    let bearer_has_rel = client
        .has_relationship(
            owner_policy_id,
            "document",
            "doc-bearer",
            "reader",
            &bls_did,
        )
        .await
        .expect("has_relationship should succeed");
    assert!(
        bearer_has_rel,
        "bls_did should have reader relationship on doc-bearer (set via bearer token)"
    );

    // D5.5. Invalid bearer token (tampered) should produce a reverted tx
    let tampered_token = format!("{}X", bearer_token);
    let d5_bad_cmd =
        vera_modules::acp::types::PolicyCmd::RegisterObject(vera_modules::acp::types::Object {
            resource: "document".into(),
            id: "doc-bad".into(),
        });
    let d5_bad_bytes = serde_json::to_vec(&d5_bad_cmd).expect("serialize PolicyCmd");
    let d5_bad_calldata = IAcp::bearerPolicyCmdCall {
        bearerToken: tampered_token,
        policyId: owner_policy_id,
        cmd: d5_bad_bytes.into(),
    }
    .abi_encode();
    let d5_bad_receipt =
        broadcast_native_tx(&cluster, &client, &owner, ACP_ADDRESS, d5_bad_calldata).await;
    assert_eq!(
        d5_bad_receipt.status, 0,
        "tampered bearer token should revert"
    );

    for (relay, subject, object_id) in [
        (&owner, &owner_did, "expired-owner"),
        (&bls_signer, &bls_did, "expired-bls"),
    ] {
        let expired_token = vera_client::create_bearer_token(&user_key, subject, chain_id, 0, 1)
            .expect("create expired token");
        let cmd =
            vera_modules::acp::types::PolicyCmd::RegisterObject(vera_modules::acp::types::Object {
                resource: "document".into(),
                id: object_id.into(),
            });
        let calldata = IAcp::bearerPolicyCmdCall {
            bearerToken: expired_token.clone(),
            policyId: owner_policy_id,
            cmd: serde_json::to_vec(&cmd).unwrap().into(),
        }
        .abi_encode();
        let receipt = broadcast_native_tx(&cluster, &client, relay, ACP_ADDRESS, calldata).await;
        assert_eq!(receipt.status, 0, "expired bearer command must fail");
        for i in 0..cluster.node_count() {
            let reader = VeraClient::new(cluster.node(i).rpc_url());
            let (registered, _) = reader
                .get_object_owner(owner_policy_id, "document", object_id)
                .await
                .unwrap();
            assert!(!registered, "expired command changed state on node {i}");
        }
    }

    // ── E: Bulletin Namespace + Post ─────────────────────────────

    // E1+E2. Register namespaces in parallel (different namespaces, different signers)
    let e1_calldata = IBulletin::registerNamespaceCall {
        namespace: "test-ns-owner".into(),
    }
    .abi_encode();
    let e2_calldata = IBulletin::registerNamespaceCall {
        namespace: "test-ns-bls".into(),
    }
    .abi_encode();

    let (e1_receipt, e2_receipt) = tokio::join!(
        broadcast_native_tx(&cluster, &client, &owner, BULLETIN_ADDRESS, e1_calldata),
        broadcast_native_tx(
            &cluster,
            &client,
            &bls_signer,
            BULLETIN_ADDRESS,
            e2_calldata
        ),
    );

    assert_eq!(
        e1_receipt.status, 1,
        "owner register_namespace should succeed"
    );
    assert_event_log(
        &e1_receipt,
        BULLETIN_ADDRESS,
        IBulletin::NamespaceCreated::SIGNATURE_HASH,
        "E1 owner registerNamespace",
    );
    assert_bls_receipt(
        &e2_receipt,
        BULLETIN_ADDRESS,
        &bls_did,
        "BLS register_namespace",
    );
    assert_event_log(
        &e2_receipt,
        BULLETIN_ADDRESS,
        IBulletin::NamespaceCreated::SIGNATURE_HASH,
        "E2 BLS registerNamespace",
    );
    assert!(
        e1_receipt.block_number >= max_block,
        "E1 block should be >= previous max"
    );
    assert!(
        e2_receipt.block_number >= max_block,
        "E2 block should be >= previous max"
    );
    max_block = max_block
        .max(e1_receipt.block_number)
        .max(e2_receipt.block_number);

    // E3. owner add_collaborator (add owner signer as collaborator to its own namespace)
    let e3_calldata = IBulletin::addCollaboratorCall {
        namespace: "test-ns-owner".into(),
        collaboratorDid: owner_did.clone(),
    }
    .abi_encode();
    let e3_receipt =
        broadcast_native_tx(&cluster, &client, &owner, BULLETIN_ADDRESS, e3_calldata).await;
    assert_eq!(
        e3_receipt.status, 1,
        "owner add_collaborator should succeed"
    );
    assert_event_log(
        &e3_receipt,
        BULLETIN_ADDRESS,
        IBulletin::CollaboratorAdded::SIGNATURE_HASH,
        "E3 owner addCollaborator",
    );
    assert!(
        e3_receipt.block_number >= max_block,
        "E3 block should be >= previous max"
    );
    max_block = max_block.max(e3_receipt.block_number);

    // Verify collaborators added
    let collabs = client
        .get_namespace_collaborators("test-ns-owner")
        .await
        .expect("get_namespace_collaborators should succeed");
    assert!(
        !collabs.is_empty(),
        "test-ns-owner should have collaborators after add_collaborator"
    );

    // E4+E5. Create posts in parallel (different namespaces)
    let e4_calldata = IBulletin::createPostCall {
        namespace: "test-ns-owner".into(),
        payload: b"hello-owner".to_vec().into(),
        proof: b"proof".to_vec().into(),
        artifact: "art".into(),
    }
    .abi_encode();
    let e5_calldata = IBulletin::createPostCall {
        namespace: "test-ns-bls".into(),
        payload: b"hello-bls".to_vec().into(),
        proof: b"proof".to_vec().into(),
        artifact: "art".into(),
    }
    .abi_encode();

    let (e4_receipt, e5_receipt) = tokio::join!(
        broadcast_native_tx(&cluster, &client, &owner, BULLETIN_ADDRESS, e4_calldata),
        broadcast_native_tx(
            &cluster,
            &client,
            &bls_signer,
            BULLETIN_ADDRESS,
            e5_calldata
        ),
    );

    assert_eq!(e4_receipt.status, 1, "owner create_post should succeed");
    assert_event_log(
        &e4_receipt,
        BULLETIN_ADDRESS,
        IBulletin::PostCreated::SIGNATURE_HASH,
        "E4 owner createPost",
    );
    assert_bls_receipt(&e5_receipt, BULLETIN_ADDRESS, &bls_did, "BLS create_post");
    assert_event_log(
        &e5_receipt,
        BULLETIN_ADDRESS,
        IBulletin::PostCreated::SIGNATURE_HASH,
        "E5 BLS createPost",
    );
    assert!(
        e4_receipt.block_number >= max_block,
        "E4 block should be >= previous max"
    );
    assert!(
        e5_receipt.block_number >= max_block,
        "E5 block should be >= previous max"
    );
    max_block = max_block
        .max(e4_receipt.block_number)
        .max(e5_receipt.block_number);

    // E6. Query namespaces and posts in parallel
    let (ns_owner, ns_bls, posts_owner, posts_bls) = tokio::join!(
        async {
            client
                .get_namespace("test-ns-owner")
                .await
                .expect("get_namespace(test-ns-owner) should succeed")
        },
        async {
            client
                .get_namespace("test-ns-bls")
                .await
                .expect("get_namespace(test-ns-bls) should succeed")
        },
        async {
            client
                .get_namespace_posts("test-ns-owner")
                .await
                .expect("get_namespace_posts(test-ns-owner) should succeed")
        },
        async {
            client
                .get_namespace_posts("test-ns-bls")
                .await
                .expect("get_namespace_posts(test-ns-bls) should succeed")
        },
    );

    assert!(!ns_owner.is_empty(), "owner namespace should be non-empty");
    assert!(!ns_bls.is_empty(), "BLS namespace should be non-empty");
    assert!(!posts_owner.is_empty(), "owner namespace should have posts");
    assert!(!posts_bls.is_empty(), "BLS namespace should have posts");

    // Verify namespace owner_did fields
    let ns_owner_json: serde_json::Value =
        serde_json::from_slice(&ns_owner).expect("owner namespace should be valid JSON");
    let ns_owner_owner = ns_owner_json
        .get("owner_did")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        ns_owner_owner, owner_did,
        "owner namespace owner_did should match owner signer DID"
    );

    let ns_bls_json: serde_json::Value =
        serde_json::from_slice(&ns_bls).expect("BLS namespace should be valid JSON");
    let ns_bls_owner = ns_bls_json
        .get("owner_did")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        ns_bls_owner, bls_did,
        "BLS namespace owner_did should match BLS signer DID"
    );

    // ── G: Vera Module — Token Queries + Invalidation ─

    // G3. Query non-existent token — should return found=false
    let (found, record) = client
        .get_jws_token("0000000000000000000000000000000000000000000000000000000000000000")
        .await
        .expect("get_jws_token should work for non-existent hash");
    assert!(!found, "non-existent token should not be found");
    assert!(
        record.is_empty(),
        "non-existent token record should be empty"
    );

    // G4. Query tokens by BLS DID — should be empty (no JWS tokens created)
    let tokens_by_did = client
        .get_jws_tokens_by_did(&bls_did)
        .await
        .expect("get_jws_tokens_by_did should work");
    let did_tokens: Vec<serde_json::Value> =
        serde_json::from_slice(&tokens_by_did).expect("tokens_by_did should be valid JSON");
    assert!(did_tokens.is_empty(), "BLS DID should have no JWS tokens");

    // G5. Query tokens by an account that authorized none — should be empty
    let tokens_by_account = client
        .get_jws_tokens_by_account(Address::repeat_byte(0x5a))
        .await
        .expect("get_jws_tokens_by_account should work");
    let acct_tokens: Vec<serde_json::Value> =
        serde_json::from_slice(&tokens_by_account).expect("tokens_by_account should be valid JSON");
    assert!(
        acct_tokens.is_empty(),
        "an account without tokens should list none"
    );

    // G6. Invalidate non-existent token via the owner's typed helper — should be refused
    let owner_invalidate = client
        .native_invalidate_jws(&owner, "nonexistent_token_hash")
        .await;
    match &owner_invalidate {
        Err(ClientError::Refused { receipt, .. }) => {
            max_block = max_block.max(receipt.block_number);
            assert!(
                receipt.logs.is_empty(),
                "G6 refused owner request should have empty logs"
            );
        }
        other => panic!("owner invalidate of non-existent token should be refused, got: {other:?}"),
    }

    // G7. Invalidate non-existent token via BLS — should revert.
    // Uses broadcast_native_tx (all-node submission) so the tx reaches
    // the cluster even if one node is briefly unavailable.
    let g7_calldata = IVera::invalidateJWSCall {
        tokenHash: "nonexistent_token_hash".into(),
    }
    .abi_encode();
    let g7_receipt =
        broadcast_native_tx(&cluster, &client, &bls_signer, VERA_ADDRESS, g7_calldata).await;
    assert_eq!(
        g7_receipt.status, 0,
        "G7 BLS invalidate of non-existent token should revert"
    );
    assert!(
        g7_receipt.logs.is_empty(),
        "G7 reverted BLS tx should have empty logs"
    );
    max_block = max_block.max(g7_receipt.block_number);

    let final_owner_nonce = client
        .get_native_nonce(&owner_did)
        .await
        .expect("vera_getNativeNonce should work");
    assert_eq!(
        final_owner_nonce, 12,
        "nonce must include rejected bearer commands"
    );

    let final_bls_nonce = client
        .get_native_nonce(&bls_did)
        .await
        .expect("vera_getNativeNonce should work");
    assert_eq!(
        final_bls_nonce, 6,
        "nonce must include rejected bearer commands"
    );

    // ── F: Cross-Node Consistency + Health ────────────────────────

    // F1. All nodes agree on state
    let consistency_height = max_block + 1;
    let consistency_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    state
        .wait_for_height(
            consistency_height,
            consistency_deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
        .expect("all nodes should advance past last tx block");

    // Bulletin's ensure_policy creates an internal ACP policy on first
    // register_namespace, so we expect 3 total: 2 user + 1 bulletin.
    for node_idx in 0..cluster.node_count() {
        let node_client = VeraClient::new(cluster.node(node_idx).rpc_url());

        // Parallel per-node queries
        let (
            node_policy_ids,
            node_ns_owner,
            node_ns_bls,
            (doc_owner_registered, _),
            (doc_bls_registered, _),
            node_has_rel,
            node_posts_owner,
            node_posts_bls,
        ) = tokio::join!(
            async {
                node_client
                    .get_policy_ids()
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_policy_ids: {e}"))
            },
            async {
                node_client
                    .get_namespace("test-ns-owner")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_namespace(test-ns-owner): {e}"))
            },
            async {
                node_client
                    .get_namespace("test-ns-bls")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_namespace(test-ns-bls): {e}"))
            },
            async {
                node_client
                    .get_object_owner(owner_policy_id, "document", "doc-owner")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_object_owner(doc-owner): {e}"))
            },
            async {
                node_client
                    .get_object_owner(owner_policy_id, "document", "doc-bls")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_object_owner(doc-bls): {e}"))
            },
            async {
                node_client
                    .has_relationship(owner_policy_id, "document", "doc-owner", "reader", &bls_did)
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} has_relationship: {e}"))
            },
            async {
                node_client
                    .get_namespace_posts("test-ns-owner")
                    .await
                    .unwrap_or_else(|e| {
                        panic!("node{node_idx} get_namespace_posts(test-ns-owner): {e}")
                    })
            },
            async {
                node_client
                    .get_namespace_posts("test-ns-bls")
                    .await
                    .unwrap_or_else(|e| {
                        panic!("node{node_idx} get_namespace_posts(test-ns-bls): {e}")
                    })
            },
        );

        assert_eq!(
            node_policy_ids.len(),
            3,
            "node{node_idx} should have 3 policies (2 user + 1 bulletin), got: {node_policy_ids:?}"
        );
        for user_pid in &policy_ids {
            assert!(
                node_policy_ids.contains(user_pid),
                "node{node_idx} should contain user policy {user_pid}"
            );
        }
        assert!(
            !node_ns_owner.is_empty(),
            "node{node_idx} owner namespace should be non-empty"
        );
        assert!(
            !node_ns_bls.is_empty(),
            "node{node_idx} BLS namespace should be non-empty"
        );
        assert!(
            doc_owner_registered,
            "node{node_idx} doc-owner should be registered"
        );
        assert!(
            doc_bls_registered,
            "node{node_idx} doc-bls should be registered"
        );
        assert!(
            !node_has_rel,
            "node{node_idx} bls_did reader relationship should be deleted (revoked in D)"
        );
        assert!(
            !node_posts_owner.is_empty(),
            "node{node_idx} test-ns-owner should have posts"
        );
        assert!(
            !node_posts_bls.is_empty(),
            "node{node_idx} test-ns-bls should have posts"
        );

        // Cross-node native nonce consistency
        let node_bls_nonce = node_client
            .get_native_nonce(&bls_did)
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} get_native_nonce: {e}"));
        assert_eq!(node_bls_nonce, 6, "node{node_idx} native nonce should be 6");
        let node_owner_nonce = node_client
            .get_native_nonce(&owner_did)
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} get_native_nonce(owner): {e}"));
        assert_eq!(
            node_owner_nonce, 12,
            "node{node_idx} owner native nonce should be 12"
        );
    }

    // F2. Cluster health, within the same deadline as the fixed-height barrier.
    loop {
        let snapshots = state.all_nodes();
        let minimum = snapshots
            .iter()
            .map(|node| node.effective_height())
            .min()
            .unwrap_or(0);
        let maximum = snapshots
            .iter()
            .map(|node| node.effective_height())
            .max()
            .unwrap_or(0);
        let observed: Vec<_> = snapshots
            .iter()
            .map(|node| (node.node_index, node.is_healthy, node.effective_height()))
            .collect();
        assert!(
            tokio::time::Instant::now() < consistency_deadline,
            "cluster health deadline expired: min={minimum}, max={maximum}, tolerance=2, \
             expected nodes={}, observed (node, healthy, height)={observed:?}",
            cluster.node_count(),
        );
        if snapshots.len() == cluster.node_count()
            && snapshots.iter().all(|node| node.is_healthy)
            && minimum >= consistency_height
            && maximum - minimum <= 2
        {
            break;
        }
        tokio::time::sleep_until(
            consistency_deadline.min(tokio::time::Instant::now() + Duration::from_millis(100)),
        )
        .await;
    }
    state
        .assert_no_errors()
        .expect("no unexpected errors in cluster logs");
    state
        .assert_chain_id(chain_id)
        .expect("chain ID should be consistent across nodes");

    // F3. Node status with tighter checks
    let mut total_finalized = 0u64;
    let mut any_proposed = false;
    for node_idx in 0..cluster.node_count() {
        let node_client = VeraClient::new(cluster.node(node_idx).rpc_url());
        let status = node_client
            .node_status()
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} node_status should succeed: {e}"));

        assert_eq!(
            status.chain_id, chain_id,
            "node{node_idx} chain_id should match configured chain_id"
        );
        assert!(
            status.finalized_count > 0,
            "node{node_idx} should have finalized at least one block (got {})",
            status.finalized_count
        );

        total_finalized += status.finalized_count;
        if status.proposed_count > 0 {
            any_proposed = true;
        }
    }

    assert!(
        any_proposed,
        "at least one node should have proposed_count > 0"
    );
    // 4 nodes, each should have finalized at least max_block blocks
    assert!(
        total_finalized >= 4 * max_block,
        "total finalized across all nodes ({total_finalized}) should be >= 4 * {max_block}"
    );

    // ── H: Finalized Header Subscription + Verified Events ───────

    let ws_client = WsClientBuilder::default()
        .build(&cluster.node(0).ws_url())
        .await
        .expect("WebSocket connection should succeed");

    // H1. Subscribe to finalized headers
    let mut headers = ws_client
        .subscribe::<GossipHeader, _>(
            "vera_subscribeHeaders",
            rpc_params![],
            "vera_unsubscribeHeaders",
        )
        .await
        .expect("header subscription should succeed");

    // H2-H5. Each module's event reaches a finalized, certified revision whose
    // header streams to the subscriber, and the verified receipt carries only
    // that module's event.
    let h_requests = [
        (
            &owner,
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
                marshalType: 1,
                nonce: vera_client::random_policy_nonce().0.into(),
            }
            .abi_encode(),
            IAcp::PolicyCreated::SIGNATURE_HASH,
            "H2 owner createPolicy",
        ),
        (
            &bls_signer,
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
                marshalType: 1,
                nonce: vera_client::random_policy_nonce().0.into(),
            }
            .abi_encode(),
            IAcp::PolicyCreated::SIGNATURE_HASH,
            "H3 BLS createPolicy",
        ),
        (
            &owner,
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: "h-ns-owner".into(),
            }
            .abi_encode(),
            IBulletin::NamespaceCreated::SIGNATURE_HASH,
            "H4 owner registerNamespace",
        ),
        (
            &bls_signer,
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: "h-ns-bls".into(),
            }
            .abi_encode(),
            IBulletin::NamespaceCreated::SIGNATURE_HASH,
            "H5 BLS registerNamespace",
        ),
    ];
    for (signer, module, calldata, topic, label) in h_requests {
        let receipt = broadcast_native_tx(&cluster, &client, signer, module, calldata).await;
        assert_bls_receipt(&receipt, module, signer.did(), label);
        assert_event_log(&receipt, module, topic, label);

        let header = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let header = headers
                    .next()
                    .await
                    .expect("header subscription should not be closed")
                    .expect("header should deserialize");
                if header.height >= receipt.block_number {
                    return header;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{label} header should arrive within timeout"));
        assert_eq!(header.chain_id, chain_id, "{label} header chain ID");
        if header.height == receipt.block_number {
            assert_eq!(
                header.block_hash, receipt.block_hash,
                "{label} header should name the receipt's block"
            );
        }

        let proof = receipt::wait_for_proof(&client, receipt.transaction_hash, &trusted).await;
        let verified = proof.verify(receipt.transaction_hash, &trusted).unwrap();
        assert!(
            verified.success(),
            "{label} verified receipt should succeed"
        );
        assert!(
            !verified.logs().is_empty(),
            "{label} verified receipt should carry events"
        );
        // No cross-talk: every verified event comes from the called module.
        for log in verified.logs() {
            assert_eq!(log.address, module, "{label} event address");
        }
        assert_eq!(verified.logs()[0].topics()[0], topic, "{label} event topic");
    }

    for receipt in [
        &e1_receipt,
        &e2_receipt,
        &e4_receipt,
        &e5_receipt,
        &g7_receipt,
    ] {
        let response = receipt::wait_for_proof(&client, receipt.transaction_hash, &trusted).await;
        let verified = response.verify(receipt.transaction_hash, &trusted).unwrap();
        assert_eq!(response.revision.height, receipt.block_number);
        assert_eq!(verified.success(), receipt.status == 1);
        assert_eq!(verified.logs().len(), receipt.logs.len());
    }
    let next_owner = BlsSigner::random(chain_id).unwrap();
    for receipt in acp_v1::lifecycle(&client, &bls_signer, &next_owner).await {
        let proof = receipt::wait_for_proof(&client, receipt.transaction_hash, &trusted).await;
        assert!(
            proof
                .verify(receipt.transaction_hash, &trusted)
                .unwrap()
                .success()
        );
    }
}
