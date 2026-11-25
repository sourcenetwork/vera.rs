//! ValidatorRegistry bootstrap integration test.
//!
//! Verifies that validators configured in genesis are readable via the
//! ValidatorRegistry module, and that write operations (add, remove,
//! status change) work through native requests.
//!
//! Requires `cargo build -p verad` before running.

#[path = "support/administration.rs"]
mod administration;
#[path = "support/broadcast.rs"]
mod broadcast;
#[path = "support/native_receipt.rs"]
mod native_receipt;

use commonware_cryptography::{Signer as _, ed25519};
use vera_client::BlsSigner;
use vera_client::administration::AdministrativeCommand;

use std::{sync::OnceLock, time::Duration};

use alloy_primitives::{Address, B256, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolEvent};

use tokio::sync::Mutex;
use vera_client::{
    ACP_ADDRESS, ClientError, TransactionReceipt, VALIDATOR_REGISTRY_ADDRESS,
    ValidatorAddressUpdate, VeraClient,
};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster, ValidatorConfig};
use vera_modules::acp::abi::IAcp;
use vera_modules::validator_registry::abi::IValidatorRegistry;
use vera_modules::validator_registry::types::ValidatorInfo;

/// Membership address of the validator the tests add and remove.
const ADDED_VALIDATOR: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

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

/// The 32-byte secret of the consensus key `seed` derives, as a validator's key file holds it.
fn consensus_secret(seed: u64) -> [u8; 32] {
    let secret: [u8; 32] = commonware_codec::Encode::encode(&ed25519::PrivateKey::from_seed(seed))
        .as_ref()
        .try_into()
        .expect("an Ed25519 secret is 32 bytes");
    assert_eq!(
        ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes(),
        consensus_key(seed).0
    );
    secret
}

fn test_validators() -> Vec<ValidatorConfig> {
    vec![
        ValidatorConfig {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: hex::encode(consensus_key(1)),
            p2p_address: "127.0.0.1:30300".to_string(),
        },
        ValidatorConfig {
            address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
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

async fn broadcast_native_tx(
    cluster: &TestCluster,
    client: &VeraClient,
    signer: &BlsSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    broadcast::native(cluster, client, signer, target, calldata).await
}

/// Read a registry view through an unsigned native dry run.
async fn registry_view(client: &VeraClient, reader: &BlsSigner, calldata: Vec<u8>) -> Vec<u8> {
    let simulation = client
        .simulate_native_call(reader.did(), VALIDATOR_REGISTRY_ADDRESS, &calldata)
        .await
        .expect("registry view should be served");
    assert!(
        simulation.success,
        "registry view should succeed: {:?}",
        simulation.refusal
    );
    simulation.output.to_vec()
}

/// A member's record as the registry's `getValidator` view returns it.
async fn validator_info(client: &VeraClient, reader: &BlsSigner, member: Address) -> ValidatorInfo {
    let calldata = IValidatorRegistry::getValidatorCall { validator: member }.abi_encode();
    let result = registry_view(client, reader, calldata).await;
    let decoded = IValidatorRegistry::getValidatorCall::abi_decode_returns(&result)
        .expect("abi decode getValidator");
    let info: Option<ValidatorInfo> = serde_json::from_slice(&decoded).expect("validator JSON");
    info.expect("validator should exist")
}

#[tokio::test]
async fn validator_bootstrap() {
    let _guard = validator_test_lock().lock().await;

    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9001;
    let validators = test_validators();
    let genesis = GenesisBuilder::devnet()
        .operators(administration::operators())
        .validators(validators.clone());

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
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
    let admin_signer = BlsSigner::random(chain_id).expect("random BLS signer");

    // ── A: Genesis verification ───────────────────────────────────

    // A1: getValidators returns genesis validators
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(all_validators.len(), 2, "should have 2 genesis validators");

    // A2: getValidator for each — verify fields
    for (i, vc) in validators.iter().enumerate() {
        let addr: Address = vc.address.parse().unwrap();
        let calldata = IValidatorRegistry::getValidatorCall { validator: addr }.abi_encode();
        let result = registry_view(&client, &admin_signer, calldata).await;
        let decoded = IValidatorRegistry::getValidatorCall::abi_decode_returns(&result)
            .expect("abi decode getValidator");
        let info: Option<ValidatorInfo> =
            serde_json::from_slice(&decoded).expect("parse validator JSON");
        let info = info.expect("validator should exist");
        assert_eq!(
            info.address.to_lowercase(),
            vc.address.to_lowercase(),
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
        assert_eq!(
            (info.admission, info.address_sequence),
            (i as u64, 0),
            "validator {i} admission and address sequence"
        );
    }

    // A3: getActiveValidatorCount equals 2
    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode getActiveValidatorCount");
    assert_eq!(decoded, U256::from(2), "active count should be 2");

    // ── ACP: Set up policy so write operations are authorized ─────

    // ACP1: Create a registry policy
    let calldata = IAcp::createPolicyCall {
        policy: REGISTRY_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    }
    .abi_encode();
    let receipt =
        broadcast_native_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "createPolicy should succeed");
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
    let receipt =
        broadcast_native_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "registerObject should succeed");

    // ACP3: Set admin relationship for the signer
    let admin_did = admin_signer.did().to_owned();
    let calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "registry".to_string(),
        objectId: "registry".to_string(),
        relation: "admin".to_string(),
        actor: admin_did,
    }
    .abi_encode();
    let receipt =
        broadcast_native_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "setRelationship should succeed");

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
    assert!(receipt.success);

    // ── B: Add a new validator via a native request ───────────────

    let new_validator_addr: Address = ADDED_VALIDATOR.parse().unwrap();
    let new_consensus_key = consensus_key(3);
    let calldata = IValidatorRegistry::addValidatorCall {
        validator: new_validator_addr,
        consensusPubkey: new_consensus_key,
        p2pAddr: "127.0.0.1:30302".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(receipt.success, "addValidator should succeed");
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
    let result = registry_view(&client, &admin_signer, calldata).await;
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
        validator: new_validator_addr,
        active: false,
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(receipt.success, "setValidatorStatus should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorStatusChanged::SIGNATURE_HASH,
        "event should be ValidatorStatusChanged"
    );

    // C2: Active count should be 2
    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode");
    assert_eq!(
        decoded,
        U256::from(2),
        "active count should be 2 after deactivation"
    );

    // C3: Reactivate
    let calldata = IValidatorRegistry::setValidatorStatusCall {
        validator: new_validator_addr,
        active: true,
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(receipt.success, "reactivation should succeed");

    let calldata = IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode");
    assert_eq!(
        decoded,
        U256::from(3),
        "active count should be 3 after reactivation"
    );

    // ── D: A validator moves its own network address ──────────────

    // D1: the validator's consensus key signs the update; a worker that holds
    // no registry permission submits it.
    let genesis_id = administration::genesis_id(&client).await;
    let worker = BlsSigner::random(chain_id).expect("random BLS signer");
    let admitted = validator_info(&client, &admin_signer, new_validator_addr).await;
    assert_eq!(
        (admitted.admission, admitted.address_sequence),
        (2, 0),
        "the added validator takes the admission after the genesis members'"
    );
    let moved = ValidatorAddressUpdate::sign(
        &consensus_secret(3),
        genesis_id,
        new_validator_addr,
        admitted.admission,
        0,
        "127.0.0.1:30399",
    );
    let receipt = client
        .native_update_validator_address(&worker, &moved)
        .await
        .expect("the validator's own update should be accepted");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorUpdated::SIGNATURE_HASH,
        "event should be ValidatorUpdated"
    );

    // D2: the record carries the new address and the next sequence
    let calldata = IValidatorRegistry::getValidatorCall {
        validator: new_validator_addr,
    }
    .abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getValidatorCall::abi_decode_returns(&result)
        .expect("abi decode getValidator");
    let info: Option<ValidatorInfo> = serde_json::from_slice(&decoded).expect("validator JSON");
    let info = info.expect("validator should exist");
    assert_eq!(
        (info.p2p_address.as_str(), info.address_sequence),
        ("127.0.0.1:30399", 1)
    );

    // D3: the same signature does not apply a second time
    let replayed = client
        .native_update_validator_address(&worker, &moved)
        .await;
    assert!(
        matches!(replayed, Err(ClientError::Refused { .. })),
        "a replayed update should be refused: {replayed:?}"
    );

    // ── E: Remove validator ───────────────────────────────────────

    // E1: Remove the validator we added in section B
    let calldata = IValidatorRegistry::removeValidatorCall {
        validator: new_validator_addr,
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(receipt.success, "removeValidator should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorRemoved::SIGNATURE_HASH,
        "event should be ValidatorRemoved"
    );

    // E2: getValidators count back to 2
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
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
    let node1_receipt = native_receipt::wait(&client2, receipt.transaction_hash).await;
    assert_eq!(
        node1_receipt.transaction_hash, receipt.transaction_hash,
        "node 1 should confirm the same removal transaction"
    );
    assert!(node1_receipt.success, "removal should succeed on node 1");
    assert_eq!(
        node1_receipt.block_hash, receipt.block_hash,
        "removal block should match across nodes"
    );
    assert_eq!(
        node1_receipt.block_number, receipt.block_number,
        "removal height should match across nodes"
    );

    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client2, &admin_signer, calldata).await;
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
        .validators(validators.clone());

    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
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
    let admin_signer = BlsSigner::random(chain_id).expect("random BLS signer");
    let rogue_signer = BlsSigner::random(chain_id).expect("random BLS signer");
    let rogue_validator: Address = ADDED_VALIDATOR.parse().unwrap();

    // ── N1: Write before policy is set → revert ─────────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: rogue_validator,
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N1: addValidator without policy should revert"
    );

    // ── Set up ACP policy (required for remaining tests) ────────

    let calldata = IAcp::createPolicyCall {
        policy: REGISTRY_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    }
    .abi_encode();
    let receipt =
        broadcast_native_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "createPolicy should succeed");

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
    let receipt =
        broadcast_native_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "registerObject should succeed");

    let calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "registry".to_string(),
        objectId: "registry".to_string(),
        relation: "admin".to_string(),
        actor: admin_signer.did().to_owned(),
    }
    .abi_encode();
    let receipt =
        broadcast_native_tx(&cluster, &client, &admin_signer, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "setRelationship should succeed");

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
    assert!(receipt.success);

    // ── N4: Unauthorized caller → revert ────────────────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: rogue_validator,
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &rogue_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N4: addValidator from unauthorized caller should revert"
    );

    // ── N5: addValidator with Address::ZERO → revert ────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: Address::ZERO,
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N5: addValidator with zero address should revert"
    );

    // ── N6: addValidator with zero consensus key → revert ───────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
            .parse()
            .unwrap(),
        consensusPubkey: B256::ZERO,
        p2pAddr: "127.0.0.1:40001".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N6: addValidator with zero consensus key should revert"
    );

    // ── N7: addValidator with invalid p2p address → revert ──────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
            .parse()
            .unwrap(),
        consensusPubkey: consensus_key(5),
        p2pAddr: "not-a-socket-addr".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N7: addValidator with invalid p2p should revert"
    );

    // ── N8: addValidator with p2p > 32 bytes → revert ───────────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
            .parse()
            .unwrap(),
        consensusPubkey: consensus_key(5),
        p2pAddr: "111.222.333.444:55555-padding-xx".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N8: addValidator with oversized p2p should revert"
    );

    // ── Add a valid validator for subsequent negative tests ──────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: rogue_validator,
        consensusPubkey: consensus_key(4),
        p2pAddr: "127.0.0.1:40000".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(receipt.success, "addValidator should succeed");

    // ── N9: Duplicate addValidator → revert ─────────────────────

    let calldata = IValidatorRegistry::addValidatorCall {
        validator: rogue_validator,
        consensusPubkey: consensus_key(6),
        p2pAddr: "127.0.0.1:40001".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(!receipt.success, "N9: duplicate addValidator should revert");

    // ── N10: removeValidator for non-existent address → revert ──

    let fake_addr: Address = "0x000000000000000000000000000000000000dEaD"
        .parse()
        .unwrap();
    let calldata = IValidatorRegistry::removeValidatorCall {
        validator: fake_addr,
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N10: removeValidator for non-existent should revert"
    );

    // ── N12: an address update for an address that is no member → refused

    let genesis_id = administration::genesis_id(&client).await;
    let unknown = ValidatorAddressUpdate::sign(
        &consensus_secret(1),
        genesis_id,
        fake_addr,
        0,
        0,
        "10.0.0.1:1234",
    );
    let refused = client
        .native_update_validator_address(&rogue_signer, &unknown)
        .await;
    assert!(
        matches!(refused, Err(ClientError::Refused { .. })),
        "N12: an update for a non-member should be refused: {refused:?}"
    );

    // ── N13: a party without the validator's consensus key cannot move it

    let member: Address = validators[0].address.parse().unwrap();
    let admission = validator_info(&client, &admin_signer, member)
        .await
        .admission;
    for (label, forged) in [
        (
            "another member's key",
            ValidatorAddressUpdate::sign(
                &consensus_secret(2),
                genesis_id,
                member,
                admission,
                0,
                "10.0.0.1:1234",
            ),
        ),
        (
            "a key that is no member's",
            ValidatorAddressUpdate::sign(
                &[0x5a; 32],
                genesis_id,
                member,
                admission,
                0,
                "10.0.0.1:1234",
            ),
        ),
        (
            "the member's key for another deployment",
            ValidatorAddressUpdate::sign(
                &consensus_secret(1),
                B256::repeat_byte(0xEE),
                member,
                admission,
                0,
                "10.0.0.1:1234",
            ),
        ),
        (
            "the member's key under another admission",
            ValidatorAddressUpdate::sign(
                &consensus_secret(1),
                genesis_id,
                member,
                admission + 1,
                0,
                "10.0.0.1:1234",
            ),
        ),
    ] {
        let refused = client
            .native_update_validator_address(&rogue_signer, &forged)
            .await;
        assert!(
            matches!(
                &refused,
                Err(ClientError::Refused { refusal, .. })
                    if refusal.kind == vera_domain::RefusalKind::Unauthorized
            ),
            "N13: {label} should be refused as unauthorized: {refused:?}"
        );
    }

    // ── N14: setValidatorStatus for non-existent → revert ───────

    let calldata = IValidatorRegistry::setValidatorStatusCall {
        validator: fake_addr,
        active: false,
    }
    .abi_encode();
    let receipt = broadcast_native_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert!(
        !receipt.success,
        "N14: setValidatorStatus for non-existent should revert"
    );

    // ── Verify state is unchanged after all rejections ──────────

    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
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
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getActiveValidatorCountCall::abi_decode_returns(&result)
        .expect("abi decode");
    assert_eq!(
        decoded,
        U256::from(3),
        "active count should still be 3 after all rejected operations"
    );
}
