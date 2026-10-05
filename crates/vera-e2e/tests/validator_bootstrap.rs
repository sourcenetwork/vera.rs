//! ValidatorRegistry bootstrap integration test.
//!
//! Verifies that validators configured in genesis are readable via the
//! ValidatorRegistry precompile, and that write operations (add, remove,
//! status change, self-update) work through EVM transactions.
//!
//! Requires `cargo build -p verad` before running.

#[path = "support/administration.rs"]
mod administration;

use commonware_cryptography::{Signer as _, ed25519};
use vera_client::BlsSigner;
use vera_client::administration::AdministrativeCommand;

use std::{sync::OnceLock, time::Duration};

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolEvent};

use tokio::sync::Mutex;
use vera_client::{
    ACP_ADDRESS, EvmSigner, TransactionReceipt, VALIDATOR_REGISTRY_ADDRESS, VeraClient,
};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster, ValidatorConfig};
use vera_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use vera_modules::acp::abi::IAcp;
use vera_modules::validator_registry::abi::IValidatorRegistry;
use vera_modules::validator_registry::types::ValidatorInfo;

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HARDHAT_KEY_2: &str = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

const REGISTRY_POLICY_YAML: &str = "\
name: validator-registry-policy
resources:
  - name: registry
    relations:
      - name: admin
    permissions:
      - name: manage
        expr: admin
";

fn consensus_key(seed: u64) -> B256 {
    B256::from_slice(ed25519::PrivateKey::from_seed(seed).public_key().as_ref())
}

fn test_validators() -> Vec<ValidatorConfig> {
    vec![
        ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: hex::encode(consensus_key(1)),
            p2p_address: "127.0.0.1:30300".to_string(),
        },
        ValidatorConfig {
            evm_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
            consensus_pubkey: hex::encode(consensus_key(2)),
            p2p_address: "127.0.0.1:30301".to_string(),
        },
    ]
}

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
}

fn validator_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn broadcast_evm_tx(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &EvmSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let nonce = client.get_nonce(signer.address()).await.expect("get_nonce");
    let raw = signer
        .sign_tx(target, Bytes::from(calldata), nonce)
        .expect("sign_tx");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let r = raw.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move { VeraClient::new(url).send_raw_transaction(&r).await })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok(Ok(hash)) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
        .await
        .expect("receipt should appear")
}

async fn eth_call_raw(client: &VeraClient, target: Address, calldata: Vec<u8>) -> Vec<u8> {
    client
        .eth_call(target, Bytes::from(calldata))
        .await
        .expect("eth_call should succeed")
        .to_vec()
}

#[tokio::test]
async fn validator_bootstrap() {
    let _guard = validator_test_lock().lock().await;

    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9001;
    let validators = test_validators();
    let genesis = GenesisBuilder::devnet()
        .operators(administration::operators())
        .funded_accounts(3, "1000000000000000000000000")
        .validators(validators.clone());

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
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
    let admin_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");

    // ── A: Genesis verification ───────────────────────────────────

    // A1: getValidators returns genesis validators
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(all_validators.len(), 2, "should have 2 genesis validators");

    // A2: getValidator for each — verify fields
    for (i, vc) in validators.iter().enumerate() {
        let addr: Address = vc.evm_address.parse().unwrap();
        let calldata = IValidatorRegistry::getValidatorCall { evmAddr: addr }.abi_encode();
        let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
        let decoded = IValidatorRegistry::getValidatorCall::abi_decode_returns(&result)
            .expect("abi decode getValidator");
        let info: Option<ValidatorInfo> =
            serde_json::from_slice(&decoded).expect("parse validator JSON");
        let info = info.expect("validator should exist");
        assert_eq!(
            info.evm_address.to_lowercase(),
            vc.evm_address.to_lowercase(),
            "validator {i} address mismatch"
        );
        assert_eq!(
            info.consensus_pubkey, vc.consensus_pubkey,
            "validator {i} consensus key mismatch"
        );
        assert_eq!(
            info.p2p_address, vc.p2p_address,
            "validator {i} p2p address mismatch"
        );
        assert!(info.active, "validator {i} should be active");
        assert_eq!(info.index, i as u64, "validator {i} index mismatch");
    }

    // A3: getActiveValidatorCount equals 2
    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode getActiveValidatorCount");
    assert_eq!(decoded, U256::from(2), "active count should be 2");

    // ── ACP: Set up policy so write operations are authorized ─────

    // ACP1: Create a registry policy
    let calldata = IAcp::createPolicyCall {
        policy: REGISTRY_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "createPolicy should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IAcp::PolicyCreated::SIGNATURE_HASH,
        "event should be PolicyCreated"
    );

    // Retrieve the actual policy ID via query (indexed string topics are keccak hashes)
    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert_eq!(policy_ids.len(), 1, "should have exactly 1 policy");
    let policy_id = parse_policy_id(&policy_ids[0]);

    // ACP2: Register the registry/registry object
    let calldata = IAcp::registerObjectCall {
        policyId: policy_id,
        objectId: "registry".to_string(),
        resource: "registry".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "registerObject should succeed");

    // ACP3: Set admin relationship for the signer
    let admin_did = admin_signer.did();
    let calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "registry".to_string(),
        objectId: "registry".to_string(),
        relation: "admin".to_string(),
        actor: admin_did,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "setRelationship should succeed");

    // ACP4: Set the policy on the ValidatorRegistry
    let signed = administration::approve(
        &client,
        AdministrativeCommand::InitializeMembershipPolicy(policy_id.0),
        0,
    )
    .await;
    let receipt = client
        .native_apply_administration(
            &BlsSigner::new(42u64.into(), admin_signer.chain_id()).unwrap(),
            &signed,
        )
        .await
        .expect("initialize membership policy");
    assert_eq!(receipt.status, 1);

    // ── B: Add a new validator via EVM tx ─────────────────────────

    let new_validator_addr: Address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        .parse()
        .unwrap();
    let new_consensus_key = consensus_key(3);
    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: new_validator_addr,
        consensusPubkey: new_consensus_key,
        p2pAddr: "127.0.0.1:30302".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "addValidator should succeed");
    assert!(
        !receipt.logs.is_empty(),
        "addValidator should emit ValidatorAdded"
    );
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorAdded::SIGNATURE_HASH,
        "event should be ValidatorAdded"
    );

    // B2: getValidators should return 3
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        all_validators.len(),
        3,
        "should have 3 validators after add"
    );

    // ── C: Status management ──────────────────────────────────────

    // C1: Deactivate the new validator
    let calldata = IValidatorRegistry::setValidatorStatusCall {
        evmAddr: new_validator_addr,
        active: false,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "setValidatorStatus should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorStatusChanged::SIGNATURE_HASH,
        "event should be ValidatorStatusChanged"
    );

    // C2: Active count should be 2
    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode");
    assert_eq!(
        decoded,
        U256::from(2),
        "active count should be 2 after deactivation"
    );

    // C3: Reactivate
    let calldata = IValidatorRegistry::setValidatorStatusCall {
        evmAddr: new_validator_addr,
        active: true,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "reactivation should succeed");

    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode");
    assert_eq!(
        decoded,
        U256::from(3),
        "active count should be 3 after reactivation"
    );

    // ── D: Self-update ────────────────────────────────────────────

    // D1: Validator 0 (Hardhat account 0) updates its own P2P address
    let calldata = IValidatorRegistry::updateP2PAddressCall {
        p2pAddr: "10.0.0.1:9999".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "updateP2PAddress should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorUpdated::SIGNATURE_HASH,
        "event should be ValidatorUpdated"
    );

    // Verify the update
    let addr: Address = validators[0].evm_address.parse().unwrap();
    let calldata = IValidatorRegistry::getValidatorCall { evmAddr: addr }.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded =
        IValidatorRegistry::getValidatorCall::abi_decode_returns(&result).expect("abi decode");
    let info: Option<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validator JSON");
    let info = info.expect("validator should exist");
    assert_eq!(
        info.p2p_address, "10.0.0.1:9999",
        "p2p address should be updated"
    );

    // ── E: Remove validator ───────────────────────────────────────

    // E1: Remove the validator we added in section B
    let calldata = IValidatorRegistry::removeValidatorCall {
        evmAddr: new_validator_addr,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "removeValidator should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorRemoved::SIGNATURE_HASH,
        "event should be ValidatorRemoved"
    );

    // E2: getValidators count back to 2
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        all_validators.len(),
        2,
        "should be back to 2 validators after removal"
    );

    // ── F: Cross-node consistency ─────────────────────────────────

    // The origin receipt does not imply node 1 has applied the removal yet.
    let client2 = VeraClient::new(cluster.node(1).rpc_url());
    let node1_receipt = client2
        .wait_for_receipt(
            receipt.transaction_hash,
            RECEIPT_POLL_INTERVAL,
            RECEIPT_POLL_ATTEMPTS,
        )
        .await
        .expect("removal receipt should appear on node 1");
    assert_eq!(
        node1_receipt.transaction_hash, receipt.transaction_hash,
        "node 1 should confirm the same removal transaction"
    );
    assert_eq!(node1_receipt.status, 1, "removal should succeed on node 1");
    assert_eq!(
        node1_receipt.block_hash, receipt.block_hash,
        "removal block should match across nodes"
    );
    assert_eq!(
        node1_receipt.block_number, receipt.block_number,
        "removal height should match across nodes"
    );

    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client2, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators from node 1");
    let node1_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        node1_validators.len(),
        all_validators.len(),
        "validator count should match across nodes"
    );
    assert_eq!(
        node1_validators, all_validators,
        "validator records should match across nodes"
    );
}

#[tokio::test]
async fn validator_registry_adversarial() {
    let _guard = validator_test_lock().lock().await;

    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9002;
    let validators = test_validators();
    let genesis = GenesisBuilder::devnet()
        .operators(administration::operators())
        .funded_accounts(4, "1000000000000000000000000")
        .validators(validators.clone());

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
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
    let admin_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");
    let rogue_signer = EvmSigner::from_hex(HARDHAT_KEY_2, chain_id).expect("valid signer");

    // ── N1: Write before policy is set → revert ─────────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: rogue_signer.address(),
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N1: addValidator without policy should revert"
    );

    // ── N2: setPolicy with zero policy ID → revert ──────────────

    let calldata = IValidatorRegistry::setPolicyCall {
        policyId: B256::ZERO,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N2: setPolicy with zero ID should revert"
    );

    // ── Set up ACP policy (required for remaining tests) ────────

    let calldata = IAcp::createPolicyCall {
        policy: REGISTRY_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "createPolicy should succeed");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    let policy_id = parse_policy_id(&policy_ids[0]);

    let calldata = IAcp::registerObjectCall {
        policyId: policy_id,
        objectId: "registry".to_string(),
        resource: "registry".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "registerObject should succeed");

    let calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "registry".to_string(),
        objectId: "registry".to_string(),
        relation: "admin".to_string(),
        actor: admin_signer.did(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "setRelationship should succeed");

    let signed = administration::approve(
        &client,
        AdministrativeCommand::InitializeMembershipPolicy(policy_id.0),
        0,
    )
    .await;
    let receipt = client
        .native_apply_administration(
            &BlsSigner::new(42u64.into(), admin_signer.chain_id()).unwrap(),
            &signed,
        )
        .await
        .expect("initialize membership policy");
    assert_eq!(receipt.status, 1);

    // ── N3: setPolicy again → revert (immutable) ────────────────

    let calldata = IValidatorRegistry::setPolicyCall {
        policyId: B256::repeat_byte(0xFF),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 0, "N3: setPolicy twice should revert");
    let repeated = administration::approve(
        &client,
        AdministrativeCommand::InitializeMembershipPolicy(policy_id.0),
        1,
    )
    .await;
    assert!(matches!(
        client
            .native_apply_administration(
                &BlsSigner::new(43u64.into(), chain_id).unwrap(),
                &repeated,
            )
            .await,
        Err(vera_client::ClientError::TxReverted { .. })
    ));
    assert_eq!(client.administration().await.unwrap().unwrap().sequence, 1);

    // ── N4: Unauthorized caller → revert ────────────────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: rogue_signer.address(),
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &rogue_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N4: addValidator from unauthorized caller should revert"
    );

    // ── N5: addValidator with Address::ZERO → revert ────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: Address::ZERO,
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N5: addValidator with zero address should revert"
    );

    // ── N6: addValidator with zero consensus key → revert ───────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
            .parse()
            .unwrap(),
        consensusPubkey: B256::ZERO,
        p2pAddr: "127.0.0.1:40001".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N6: addValidator with zero consensus key should revert"
    );

    // ── N7: addValidator with invalid p2p address → revert ──────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
            .parse()
            .unwrap(),
        consensusPubkey: consensus_key(5),
        p2pAddr: "not-a-socket-addr".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N7: addValidator with invalid p2p should revert"
    );

    // ── N8: addValidator with p2p > 32 bytes → revert ───────────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
            .parse()
            .unwrap(),
        consensusPubkey: consensus_key(5),
        p2pAddr: "111.222.333.444:55555-padding-xx".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N8: addValidator with oversized p2p should revert"
    );

    // ── Add a valid validator for subsequent negative tests ──────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: rogue_signer.address(),
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "addValidator should succeed");

    // ── N9: Duplicate addValidator → revert ─────────────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: rogue_signer.address(),
        consensusPubkey: consensus_key(6),
        p2pAddr: "127.0.0.1:40001".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N9: duplicate addValidator should revert"
    );

    // ── N10: removeValidator for non-existent address → revert ──

    let fake_addr: Address = "0x000000000000000000000000000000000000dEaD"
        .parse()
        .unwrap();
    let calldata = IValidatorRegistry::removeValidatorCall { evmAddr: fake_addr }.abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N10: removeValidator for non-existent should revert"
    );

    // ── N11: setValidatorStatusByIndex out of bounds → revert ───

    let calldata = IValidatorRegistry::setValidatorStatusByIndexCall {
        index: U256::from(999),
        active: false,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N11: setValidatorStatusByIndex out of bounds should revert"
    );

    // ── N12: Non-validator calls updateP2PAddress → revert ──────

    // Use a signer whose address is NOT in the registry. Hardhat account 2
    // was added above, so we need a signer that isn't registered. Create a
    // throwaway signer from account 3.
    let non_validator_key = "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
    let non_validator_signer =
        EvmSigner::from_hex(non_validator_key, chain_id).expect("valid signer");
    let calldata = IValidatorRegistry::updateP2PAddressCall {
        p2pAddr: "10.0.0.1:1234".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &non_validator_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N12: updateP2PAddress from non-validator should revert"
    );

    // ── N13: updateP2PAddress with invalid p2p → revert ─────────

    // Use admin_signer (hardhat 0) which IS a genesis validator
    let calldata = IValidatorRegistry::updateP2PAddressCall {
        p2pAddr: "garbage".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N13: updateP2PAddress with invalid p2p should revert"
    );

    // ── N14: setValidatorStatus for non-existent → revert ───────

    let calldata = IValidatorRegistry::setValidatorStatusCall {
        evmAddr: fake_addr,
        active: false,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(
        receipt.status, 0,
        "N14: setValidatorStatus for non-existent should revert"
    );

    // ── Verify state is unchanged after all rejections ──────────

    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let final_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        final_validators.len(),
        3,
        "should still have exactly 3 validators (2 genesis + 1 added)"
    );

    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode");
    assert_eq!(
        decoded,
        U256::from(3),
        "active count should still be 3 after all rejected operations"
    );
}
