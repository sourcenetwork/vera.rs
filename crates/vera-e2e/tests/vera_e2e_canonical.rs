//! Canonical integration test — full module lifecycle.
//!
//! Exercises both EVM and BLS transaction paths through every module:
//! ACP (policy, object, relationship, access control),
//! Bulletin (namespace, collaborator, post),
//! and cross-path verification (BLS write + EVM query, EVM write + BLS query).
//!
//! One cluster startup, one comprehensive test.
//!
//! Requires `cargo build -p verad` before running.

#[path = "support/acp_v1.rs"]
mod acp_v1;
#[path = "support/receipt.rs"]
mod receipt;

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolEvent};

use jsonrpsee::core::client::SubscriptionClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use vera_client::{
    ACP_ADDRESS, BULLETIN_ADDRESS, BlsSigner, ClientError, EvmSigner, TransactionReceipt,
    VERA_ADDRESS, VeraClient,
};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_e2e::observe::ClusterAssertions;
use vera_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use vera_modules::acp::abi::IAcp;
use vera_modules::bulletin::abi::IBulletin;
use vera_modules::vera::abi::IVera;

/// Hardhat account 0 private key (pre-funded by `GenesisBuilder::funded_accounts`).
const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Hardhat account 1 private key (used as bearer token signer — not funded, no EVM txs).
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

/// Sign an EVM transaction and broadcast to all nodes in the cluster.
///
/// Each node gossips admitted txs to all validators, so one submission
/// reaches every validator; broadcasting to every node keeps the test
/// robust against a node that is briefly unavailable.
async fn broadcast_evm_tx(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &EvmSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let nonce = client
        .get_nonce(signer.address())
        .await
        .expect("get_nonce should work");
    let raw = signer
        .sign_tx(target, Bytes::from(calldata), nonce)
        .expect("EVM sign should succeed");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let r = raw.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move {
                let result = VeraClient::new(url).send_raw_transaction(&r).await;
                (i, result)
            })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok((_node_idx, Ok(hash))) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the EVM tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
        .await
        .expect("EVM receipt should appear")
}

/// Sign a native BLS transaction and broadcast to all nodes in the cluster.
///
/// Each node gossips admitted txs to all validators, so one submission
/// reaches every validator; broadcasting to every node keeps the test
/// robust against a node that is briefly unavailable.
async fn broadcast_native_tx(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &BlsSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let wire = signer
        .sign_native_tx(target, Bytes::from(calldata))
        .expect("BLS sign should succeed");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let w = wire.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move {
                let result = VeraClient::new(url).send_native_tx(&w).await;
                (i, result)
            })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok((_node_idx, Ok(hash))) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the BLS tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
        .await
        .expect("BLS receipt should appear")
}

/// Assert common fields on a BLS native transaction receipt.
fn assert_bls_receipt(receipt: &TransactionReceipt, target: Address, label: &str) {
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
        "{label} receipt 'to' should be the target precompile"
    );
}

/// Assert that a receipt contains at least one log matching the expected precompile address and event topic.
fn assert_event_log(receipt: &TransactionReceipt, address: Address, topic: B256, label: &str) {
    assert!(!receipt.logs.is_empty(), "{label} should emit event logs");
    let log = &receipt.logs[0];
    assert_eq!(
        log.address, address,
        "{label} log address should be the precompile"
    );
    assert!(!log.topics.is_empty(), "{label} log should have topics");
    assert_eq!(
        log.topics[0], topic,
        "{label} log topic[0] should match event signature"
    );
}

/// Full module lifecycle: ACP + Bulletin, EVM + BLS, writes + queries.
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
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .seed(chain_id)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Fast)
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

    let reported_chain_id = client.chain_id().await.expect("eth_chainId should work");
    assert_eq!(reported_chain_id, chain_id, "chain ID should match");

    let evm_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");
    let bls_signer = BlsSigner::random(chain_id).expect("random BLS signer");

    let evm_did = evm_signer.did();
    let bls_did = bls_signer.did().to_owned();

    // Track block numbers across all receipts — must be monotonically non-decreasing.
    let mut max_block = 0u64;

    // ── A: ACP Policy Creation (EVM + BLS in parallel) ────────────

    let balance_before = client
        .get_balance(evm_signer.address())
        .await
        .expect("eth_getBalance should work");
    assert!(balance_before > U256::ZERO, "test account should be funded");

    let a1_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let a2_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();

    let (evm_receipt, bls_receipt) = tokio::join!(
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, a1_calldata),
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, a2_calldata),
    );

    // A1 assertions
    assert_eq!(evm_receipt.status, 1, "EVM create_policy should succeed");
    assert!(
        evm_receipt.block_number > 0,
        "EVM tx should be included in a real block"
    );
    assert!(evm_receipt.gas_used > 0, "EVM tx should consume gas");
    assert_ne!(
        evm_receipt.transaction_hash,
        B256::ZERO,
        "EVM tx hash should be non-degenerate"
    );
    assert_eq!(
        evm_receipt.from,
        evm_signer.address(),
        "EVM receipt 'from' should match signer address"
    );
    assert_eq!(
        evm_receipt.to,
        Some(ACP_ADDRESS),
        "EVM receipt 'to' should be the ACP precompile"
    );

    // A1 event log
    assert_event_log(
        &evm_receipt,
        ACP_ADDRESS,
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "A1 EVM createPolicy",
    );

    // A1 extended receipt: EVM tx should have no signer_did
    let a1_native = client
        .get_native_receipt(evm_receipt.transaction_hash)
        .await
        .expect("vera_getTransactionReceipt for EVM tx should work")
        .expect("A1 native receipt should exist");
    assert!(
        a1_native.signer_did.is_none(),
        "EVM tx native receipt should have no signer_did"
    );
    assert!(
        a1_native.native_nonce.is_none(),
        "EVM tx native receipt should have no native_nonce"
    );

    let nonce_after_a1 = client
        .get_nonce(evm_signer.address())
        .await
        .expect("get_nonce should work");
    assert_eq!(
        nonce_after_a1, 1,
        "EVM nonce should increment to 1 after first tx"
    );

    let balance_after = client
        .get_balance(evm_signer.address())
        .await
        .expect("get_balance should work");
    assert!(
        balance_after < balance_before,
        "balance should decrease after paying gas (before={balance_before}, after={balance_after})"
    );

    // A2 assertions
    assert_bls_receipt(&bls_receipt, ACP_ADDRESS, "BLS create_policy");
    assert_event_log(
        &bls_receipt,
        ACP_ADDRESS,
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "A2 BLS createPolicy",
    );

    // A2 extended receipt: vera_getTransactionReceipt should include signer_did
    let a2_native = client
        .get_native_receipt(bls_receipt.transaction_hash)
        .await
        .expect("vera_getTransactionReceipt should work")
        .expect("A2 native receipt should exist");
    assert_eq!(
        a2_native.signer_did.as_deref(),
        Some(bls_did.as_str()),
        "A2 native receipt signer_did should match BLS DID"
    );
    assert!(
        a2_native.native_nonce.is_some(),
        "A2 native receipt should have native_nonce"
    );

    // Block number monotonicity
    max_block = max_block
        .max(evm_receipt.block_number)
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
        "should have 2 policies (EVM + BLS), got: {policy_ids:?}"
    );

    let evm_policy_id = parse_policy_id(&policy_ids[0]);
    let _bls_policy_id = parse_policy_id(&policy_ids[1]);

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

    // ── B: ACP Object Registration (EVM + BLS in parallel) ───────

    let b1_calldata = IAcp::registerObjectCall {
        policyId: evm_policy_id,
        objectId: "doc-evm".into(),
        resource: "document".into(),
    }
    .abi_encode();
    let b2_calldata = IAcp::registerObjectCall {
        policyId: evm_policy_id,
        objectId: "doc-bls".into(),
        resource: "document".into(),
    }
    .abi_encode();

    let (b1_receipt, b2_receipt) = tokio::join!(
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, b1_calldata),
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, b2_calldata),
    );

    assert_eq!(b1_receipt.status, 1, "EVM register_object should succeed");
    assert_event_log(
        &b1_receipt,
        ACP_ADDRESS,
        IAcp::ObjectRegistered::SIGNATURE_HASH,
        "B1 EVM registerObject",
    );
    assert_bls_receipt(&b2_receipt, ACP_ADDRESS, "BLS register_object");
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
    let ((evm_registered, _), (bls_registered, _)) = tokio::join!(
        async {
            client
                .get_object_owner(evm_policy_id, "document", "doc-evm")
                .await
                .expect("get_object_owner(doc-evm) should succeed")
        },
        async {
            client
                .get_object_owner(evm_policy_id, "document", "doc-bls")
                .await
                .expect("get_object_owner(doc-bls) should succeed")
        },
    );
    assert!(evm_registered, "doc-evm should be registered");
    assert!(bls_registered, "doc-bls should be registered");

    // ── C: ACP Relationships + Access ────────────────────────────

    // C1. EVM set_relationship: grant bls_did "reader" on "doc-evm"
    let c1_calldata = IAcp::setRelationshipCall {
        policyId: evm_policy_id,
        resource: "document".into(),
        objectId: "doc-evm".into(),
        relation: "reader".into(),
        actor: bls_did.clone(),
    }
    .abi_encode();
    let c1_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, c1_calldata).await;
    assert_eq!(c1_receipt.status, 1, "EVM set_relationship should succeed");
    assert_event_log(
        &c1_receipt,
        ACP_ADDRESS,
        IAcp::RelationshipSet::SIGNATURE_HASH,
        "C1 EVM setRelationship",
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
                .has_relationship(evm_policy_id, "document", "doc-evm", "reader", &bls_did)
                .await
                .expect("has_relationship should succeed")
        },
        async {
            client
                .verify_access_request(
                    evm_policy_id,
                    vec!["document".into()],
                    vec!["doc-evm".into()],
                    vec!["read".into()],
                    &bls_did,
                )
                .await
                .expect("verify_access_request(read) should succeed")
        },
        async {
            client
                .verify_access_request(
                    evm_policy_id,
                    vec!["document".into()],
                    vec!["doc-evm".into()],
                    vec!["update".into()],
                    &bls_did,
                )
                .await
                .expect("verify_access_request(update) should succeed")
        },
        async {
            client
                .verify_access_request(
                    evm_policy_id,
                    vec!["document".into()],
                    vec!["doc-evm".into()],
                    vec!["read".into()],
                    &evm_did,
                )
                .await
                .expect("verify_access_request(owner read) should succeed")
        },
    );
    assert!(has_rel, "bls_did should have reader relationship");
    assert!(can_read, "bls_did should have read access");
    assert!(!can_update, "bls_did should NOT have update access");
    assert!(owner_can_read, "owner (evm_did) should have read access");

    // ── D: ACP Delete + Access Revocation ────────────────────────

    // D1. delete_relationship — revocation requires management authority, so the
    // EVM signer (policy + doc-evm owner) revokes the grant it created in C1.
    let d1_calldata = IAcp::deleteRelationshipCall {
        policyId: evm_policy_id,
        resource: "document".into(),
        objectId: "doc-evm".into(),
        relation: "reader".into(),
        actor: bls_did.clone(),
    }
    .abi_encode();
    let d1_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, d1_calldata).await;
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
                .has_relationship(evm_policy_id, "document", "doc-evm", "reader", &bls_did)
                .await
                .expect("has_relationship should succeed")
        },
        async {
            client
                .verify_access_request(
                    evm_policy_id,
                    vec!["document".into()],
                    vec!["doc-evm".into()],
                    vec!["read".into()],
                    &bls_did,
                )
                .await
                .expect("verify_access_request should succeed")
        },
        async {
            client
                .verify_access_request(
                    evm_policy_id,
                    vec!["document".into()],
                    vec!["doc-evm".into()],
                    vec!["read".into()],
                    &evm_did,
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
    assert!(
        owner_can_read,
        "owner (evm_did) should still have read access"
    );

    // ── D.5: Bearer Token ACP Operations ──────────────────────────

    // Account 1 is the "end user" — signs the JWT but never submits EVM txs.
    // Account 0 is the "defra node" — submits EVM txs containing the bearer token.
    let user_key =
        k256::ecdsa::SigningKey::from_bytes((&hex::decode(HARDHAT_KEY_1).unwrap()[..]).into())
            .expect("valid signing key");
    let user_did = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        user_key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .expect("valid DID");

    let bearer_token =
        vera_client::create_bearer_token(&user_key, &evm_did, chain_id, 0, 9_999_999_999)
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
        policyId: evm_policy_id,
        cmd: d5_cmd_bytes.into(),
    }
    .abi_encode();
    let d5_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, d5_calldata).await;
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
        .get_object_owner(evm_policy_id, "document", "doc-bearer")
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
    let d5_rel = acp::Relationship::new(
        "document",
        "doc-bearer",
        "reader",
        acp::Subject::entity(identity::Did::new(&bls_did).expect("valid DID")),
    );
    let d5_set_cmd = vera_modules::acp::types::PolicyCmd::SetRelationship(d5_rel);
    let d5_set_bytes = serde_json::to_vec(&d5_set_cmd).expect("serialize PolicyCmd");
    let d5_set_calldata = IAcp::bearerPolicyCmdCall {
        bearerToken: bearer_token.clone(),
        policyId: evm_policy_id,
        cmd: d5_set_bytes.into(),
    }
    .abi_encode();
    let d5_set_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, d5_set_calldata).await;
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
        .has_relationship(evm_policy_id, "document", "doc-bearer", "reader", &bls_did)
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
        policyId: evm_policy_id,
        cmd: d5_bad_bytes.into(),
    }
    .abi_encode();
    let d5_bad_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, d5_bad_calldata).await;
    assert_eq!(
        d5_bad_receipt.status, 0,
        "tampered bearer token should revert"
    );

    for native in [false, true] {
        let subject = if native { &bls_did } else { &evm_did };
        let expired_token = vera_client::create_bearer_token(&user_key, subject, chain_id, 0, 1)
            .expect("create expired token");
        let object_id = if native {
            "expired-native"
        } else {
            "expired-relayed"
        };
        let cmd =
            vera_modules::acp::types::PolicyCmd::RegisterObject(vera_modules::acp::types::Object {
                resource: "document".into(),
                id: object_id.into(),
            });
        let calldata = IAcp::bearerPolicyCmdCall {
            bearerToken: expired_token.clone(),
            policyId: evm_policy_id,
            cmd: serde_json::to_vec(&cmd).unwrap().into(),
        }
        .abi_encode();
        let receipt = if native {
            broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, calldata).await
        } else {
            broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, calldata).await
        };
        assert_eq!(receipt.status, 0, "expired bearer command must fail");
        for i in 0..cluster.node_count() {
            let reader = VeraClient::new(cluster.node(i).rpc_url());
            let (registered, _) = reader
                .get_object_owner(evm_policy_id, "document", object_id)
                .await
                .unwrap();
            assert!(!registered, "expired command changed state on node {i}");
        }
    }

    // ── E: Bulletin Namespace + Post ─────────────────────────────

    // E1+E2. Register namespaces in parallel (different namespaces, different signers)
    let e1_calldata = IBulletin::registerNamespaceCall {
        namespace: "test-ns-evm".into(),
    }
    .abi_encode();
    let e2_calldata = IBulletin::registerNamespaceCall {
        namespace: "test-ns-bls".into(),
    }
    .abi_encode();

    let (e1_receipt, e2_receipt) = tokio::join!(
        broadcast_evm_tx(
            &cluster,
            &client,
            &evm_signer,
            BULLETIN_ADDRESS,
            e1_calldata
        ),
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
        "EVM register_namespace should succeed"
    );
    assert_event_log(
        &e1_receipt,
        BULLETIN_ADDRESS,
        IBulletin::NamespaceCreated::SIGNATURE_HASH,
        "E1 EVM registerNamespace",
    );
    assert_bls_receipt(&e2_receipt, BULLETIN_ADDRESS, "BLS register_namespace");
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

    // E3. EVM add_collaborator (add EVM signer as collaborator to its own namespace)
    let e3_calldata = IBulletin::addCollaboratorCall {
        namespace: "test-ns-evm".into(),
        collaboratorDid: evm_did.clone(),
    }
    .abi_encode();
    let e3_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        BULLETIN_ADDRESS,
        e3_calldata,
    )
    .await;
    assert_eq!(e3_receipt.status, 1, "EVM add_collaborator should succeed");
    assert_event_log(
        &e3_receipt,
        BULLETIN_ADDRESS,
        IBulletin::CollaboratorAdded::SIGNATURE_HASH,
        "E3 EVM addCollaborator",
    );
    assert!(
        e3_receipt.block_number >= max_block,
        "E3 block should be >= previous max"
    );
    max_block = max_block.max(e3_receipt.block_number);

    // Verify collaborators added
    let collabs = client
        .get_namespace_collaborators("test-ns-evm")
        .await
        .expect("get_namespace_collaborators should succeed");
    assert!(
        !collabs.is_empty(),
        "test-ns-evm should have collaborators after add_collaborator"
    );

    // E4+E5. Create posts in parallel (different namespaces)
    let e4_calldata = IBulletin::createPostCall {
        namespace: "test-ns-evm".into(),
        payload: b"hello-evm".to_vec().into(),
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
        broadcast_evm_tx(
            &cluster,
            &client,
            &evm_signer,
            BULLETIN_ADDRESS,
            e4_calldata
        ),
        broadcast_native_tx(
            &cluster,
            &client,
            &bls_signer,
            BULLETIN_ADDRESS,
            e5_calldata
        ),
    );

    assert_eq!(e4_receipt.status, 1, "EVM create_post should succeed");
    assert_event_log(
        &e4_receipt,
        BULLETIN_ADDRESS,
        IBulletin::PostCreated::SIGNATURE_HASH,
        "E4 EVM createPost",
    );
    assert_bls_receipt(&e5_receipt, BULLETIN_ADDRESS, "BLS create_post");
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
    let (ns_evm, ns_bls, posts_evm, posts_bls) = tokio::join!(
        async {
            client
                .get_namespace("test-ns-evm")
                .await
                .expect("get_namespace(test-ns-evm) should succeed")
        },
        async {
            client
                .get_namespace("test-ns-bls")
                .await
                .expect("get_namespace(test-ns-bls) should succeed")
        },
        async {
            client
                .get_namespace_posts("test-ns-evm")
                .await
                .expect("get_namespace_posts(test-ns-evm) should succeed")
        },
        async {
            client
                .get_namespace_posts("test-ns-bls")
                .await
                .expect("get_namespace_posts(test-ns-bls) should succeed")
        },
    );

    assert!(!ns_evm.is_empty(), "EVM namespace should be non-empty");
    assert!(!ns_bls.is_empty(), "BLS namespace should be non-empty");
    assert!(!posts_evm.is_empty(), "EVM namespace should have posts");
    assert!(!posts_bls.is_empty(), "BLS namespace should have posts");

    // Verify namespace owner_did fields
    let ns_evm_json: serde_json::Value =
        serde_json::from_slice(&ns_evm).expect("EVM namespace should be valid JSON");
    let ns_evm_owner = ns_evm_json
        .get("owner_did")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        ns_evm_owner, evm_did,
        "EVM namespace owner_did should match EVM signer DID"
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

    // ── G: Vera Module — Config, Params, Token Queries + Invalidation ─

    // G1. Read chain config (eth_call to 0x0812)
    let chain_config = client
        .get_chain_config()
        .await
        .expect("get_chain_config should work");
    assert!(!chain_config.is_empty(), "chain config should be non-empty");
    let config_json: serde_json::Value =
        serde_json::from_slice(&chain_config).expect("chain config should be valid JSON");
    assert!(
        config_json.is_object(),
        "chain config should be a JSON object"
    );

    // G2. Read Vera params (eth_call to 0x0812)
    let vera_params = client
        .get_hub_params()
        .await
        .expect("get_hub_params should work");
    assert!(!vera_params.is_empty(), "vera params should be non-empty");
    let params_json: serde_json::Value =
        serde_json::from_slice(&vera_params).expect("vera params should be valid JSON");
    assert!(
        params_json.is_object(),
        "vera params should be a JSON object"
    );

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

    // G5. Query tokens by EVM account — should be empty
    let tokens_by_account = client
        .get_jws_tokens_by_account(evm_signer.address())
        .await
        .expect("get_jws_tokens_by_account should work");
    let acct_tokens: Vec<serde_json::Value> =
        serde_json::from_slice(&tokens_by_account).expect("tokens_by_account should be valid JSON");
    assert!(
        acct_tokens.is_empty(),
        "EVM account should have no JWS tokens"
    );

    // G6. Invalidate non-existent token via EVM — should revert
    let evm_invalidate_err = client
        .invalidate_jws(&evm_signer, "nonexistent_token_hash")
        .await;
    match &evm_invalidate_err {
        Err(ClientError::TxReverted { receipt, .. }) => {
            max_block = max_block.max(receipt.block_number);
            assert!(
                receipt.logs.is_empty(),
                "G6 reverted EVM tx should have empty logs"
            );
        }
        other => panic!("EVM invalidate of non-existent token should revert, got: {other:?}"),
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

    let final_evm_nonce = client
        .get_nonce(evm_signer.address())
        .await
        .expect("get_nonce should work");
    assert_eq!(
        final_evm_nonce, 12,
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
            node_ns_evm,
            node_ns_bls,
            (doc_evm_registered, _),
            (doc_bls_registered, _),
            node_has_rel,
            node_posts_evm,
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
                    .get_namespace("test-ns-evm")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_namespace(test-ns-evm): {e}"))
            },
            async {
                node_client
                    .get_namespace("test-ns-bls")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_namespace(test-ns-bls): {e}"))
            },
            async {
                node_client
                    .get_object_owner(evm_policy_id, "document", "doc-evm")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_object_owner(doc-evm): {e}"))
            },
            async {
                node_client
                    .get_object_owner(evm_policy_id, "document", "doc-bls")
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} get_object_owner(doc-bls): {e}"))
            },
            async {
                node_client
                    .has_relationship(evm_policy_id, "document", "doc-evm", "reader", &bls_did)
                    .await
                    .unwrap_or_else(|e| panic!("node{node_idx} has_relationship: {e}"))
            },
            async {
                node_client
                    .get_namespace_posts("test-ns-evm")
                    .await
                    .unwrap_or_else(|e| {
                        panic!("node{node_idx} get_namespace_posts(test-ns-evm): {e}")
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
            !node_ns_evm.is_empty(),
            "node{node_idx} EVM namespace should be non-empty"
        );
        assert!(
            !node_ns_bls.is_empty(),
            "node{node_idx} BLS namespace should be non-empty"
        );
        assert!(
            doc_evm_registered,
            "node{node_idx} doc-evm should be registered"
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
            !node_posts_evm.is_empty(),
            "node{node_idx} test-ns-evm should have posts"
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

    // ── H: WebSocket Event Subscriptions ─────────────────────────

    let ws_client = WsClientBuilder::default()
        .build(&cluster.node(0).ws_url())
        .await
        .expect("WebSocket connection should succeed");

    // H1. Subscribe to logs for each precompile address
    let mut acp_sub = ws_client
        .subscribe::<serde_json::Value, _>(
            "eth_subscribe",
            rpc_params![
                "logs",
                serde_json::json!({"address": format!("{:#x}", ACP_ADDRESS)})
            ],
            "eth_unsubscribe",
        )
        .await
        .expect("ACP log subscription should succeed");

    let mut bulletin_sub = ws_client
        .subscribe::<serde_json::Value, _>(
            "eth_subscribe",
            rpc_params![
                "logs",
                serde_json::json!({"address": format!("{:#x}", BULLETIN_ADDRESS)})
            ],
            "eth_unsubscribe",
        )
        .await
        .expect("Bulletin log subscription should succeed");

    // H2. Submit EVM createPolicy → expect PolicyCreated on ACP subscription
    let h2_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let h2_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, h2_calldata).await;
    assert_eq!(h2_receipt.status, 1, "H2 EVM createPolicy should succeed");
    assert_event_log(
        &h2_receipt,
        ACP_ADDRESS,
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "H2 EVM createPolicy",
    );

    let acp_event = tokio::time::timeout(Duration::from_secs(10), acp_sub.next())
        .await
        .expect("H2 ACP event should arrive within timeout")
        .expect("ACP subscription should not be closed")
        .expect("ACP event should deserialize");
    let acp_addr = acp_event
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        acp_addr,
        format!("{:#x}", ACP_ADDRESS),
        "H2 WS event address should be ACP precompile"
    );

    // H3. Submit BLS createPolicy → expect PolicyCreated on ACP subscription
    let h3_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let h3_receipt =
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, h3_calldata).await;
    assert_eq!(h3_receipt.status, 1, "H3 BLS createPolicy should succeed");
    assert_event_log(
        &h3_receipt,
        ACP_ADDRESS,
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "H3 BLS createPolicy",
    );

    let acp_event2 = tokio::time::timeout(Duration::from_secs(10), acp_sub.next())
        .await
        .expect("H3 ACP event should arrive within timeout")
        .expect("ACP subscription should not be closed")
        .expect("ACP event should deserialize");
    let acp_addr2 = acp_event2
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        acp_addr2,
        format!("{:#x}", ACP_ADDRESS),
        "H3 WS event address should be ACP precompile"
    );

    // H4. Submit EVM registerNamespace → expect NamespaceCreated on Bulletin subscription
    let h4_calldata = IBulletin::registerNamespaceCall {
        namespace: "h-ns-evm".into(),
    }
    .abi_encode();
    let h4_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        BULLETIN_ADDRESS,
        h4_calldata,
    )
    .await;
    assert_eq!(
        h4_receipt.status, 1,
        "H4 EVM registerNamespace should succeed"
    );
    assert_event_log(
        &h4_receipt,
        BULLETIN_ADDRESS,
        IBulletin::NamespaceCreated::SIGNATURE_HASH,
        "H4 EVM registerNamespace",
    );

    let bulletin_event = tokio::time::timeout(Duration::from_secs(10), bulletin_sub.next())
        .await
        .expect("H4 Bulletin event should arrive within timeout")
        .expect("Bulletin subscription should not be closed")
        .expect("Bulletin event should deserialize");
    let bulletin_addr = bulletin_event
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        bulletin_addr,
        format!("{:#x}", BULLETIN_ADDRESS),
        "H4 WS event address should be Bulletin precompile"
    );

    // H5. Submit BLS registerNamespace → expect NamespaceCreated on Bulletin subscription
    let h5_calldata = IBulletin::registerNamespaceCall {
        namespace: "h-ns-bls".into(),
    }
    .abi_encode();
    let h5_receipt = broadcast_native_tx(
        &cluster,
        &client,
        &bls_signer,
        BULLETIN_ADDRESS,
        h5_calldata,
    )
    .await;
    assert_eq!(
        h5_receipt.status, 1,
        "H5 BLS registerNamespace should succeed"
    );
    assert_event_log(
        &h5_receipt,
        BULLETIN_ADDRESS,
        IBulletin::NamespaceCreated::SIGNATURE_HASH,
        "H5 BLS registerNamespace",
    );

    let bulletin_event2 = tokio::time::timeout(Duration::from_secs(10), bulletin_sub.next())
        .await
        .expect("H5 Bulletin event should arrive within timeout")
        .expect("Bulletin subscription should not be closed")
        .expect("Bulletin event should deserialize");
    let bulletin_addr2 = bulletin_event2
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        bulletin_addr2,
        format!("{:#x}", BULLETIN_ADDRESS),
        "H5 WS event address should be Bulletin precompile"
    );

    // H6. No cross-talk: ACP subscription should NOT have received Bulletin events
    // and Bulletin subscription should NOT have received ACP events.
    // After H2-H5 we consumed exactly 2 ACP events and 2 Bulletin events.
    // Any additional event on either subscription within a short window = cross-talk.
    let acp_extra = tokio::time::timeout(Duration::from_millis(500), acp_sub.next()).await;
    assert!(
        acp_extra.is_err(),
        "ACP subscription should have no extra events (no cross-talk from Bulletin)"
    );
    let bulletin_extra =
        tokio::time::timeout(Duration::from_millis(500), bulletin_sub.next()).await;
    assert!(
        bulletin_extra.is_err(),
        "Bulletin subscription should have no extra events (no cross-talk from ACP)"
    );
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
