//! Validator set epoch transition integration test.
//!
//! Verifies registry changes across epoch transitions and checks that reshared
//! certificates remain verifiable with the bootstrap consensus identity.
//!
//! Requires `cargo build -p verad` before running.

#[path = "support/administration.rs"]
mod administration;
#[path = "support/broadcast.rs"]
mod broadcast;
#[path = "support/native_receipt.rs"]
mod native_receipt;

use vera_client::BlsSigner;
use vera_client::administration::AdministrativeCommand;

use std::time::Duration;

use alloy_primitives::{Address, B256, FixedBytes};
use alloy_sol_types::{SolCall, SolEvent};
use commonware_codec::Encode;
use commonware_cryptography::{Signer as _, ed25519};

use vera_client::{ACP_ADDRESS, TransactionReceipt, VALIDATOR_REGISTRY_ADDRESS, VeraClient};
use vera_domain::{EpochMaterial, LightBlock, verify_light_block};
use vera_e2e::RECEIPT_POLL_INTERVAL;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::acp::abi::IAcp;
use vera_modules::validator_registry::abi::IValidatorRegistry;
use vera_modules::validator_registry::types::ValidatorInfo;

const BLOCKS_PER_EPOCH: u64 = 20;

/// Two-view leader terms give each of the five registry members a leader
/// opportunity within a 20-block epoch.
const SIMPLEX: vera_domain::SimplexParameters = vera_domain::SimplexParameters {
    term_length: 2,
    optimistic_views: 1,
    stall_timeout_ms: 5_000,
};

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

// The receipt's epoch records its roster at the boundary for ceremony e + 3.
// That ceremony can first supply the voting material for epoch e + 4.
const fn first_reshared_epoch(receipt_height: u64) -> u64 {
    (receipt_height / BLOCKS_PER_EPOCH)
        .checked_add(4)
        .expect("membership activation epoch")
}

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

async fn setup_acp_policy(cluster: &TestCluster, client: &VeraClient, admin: &BlsSigner) {
    let calldata = IAcp::createPolicyCall {
        policy: REGISTRY_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(cluster, client, admin, ACP_ADDRESS, calldata).await;
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
    let receipt = broadcast_native_tx(cluster, client, admin, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "registerObject should succeed");

    let calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "registry".to_string(),
        objectId: "registry".to_string(),
        relation: "admin".to_string(),
        actor: admin.did().to_owned(),
    }
    .abi_encode();
    let receipt = broadcast_native_tx(cluster, client, admin, ACP_ADDRESS, calldata).await;
    assert!(receipt.success, "setRelationship should succeed");

    let signed = administration::approve(
        client,
        AdministrativeCommand::InitializeMembershipPolicy(policy_id.0),
        0,
    )
    .await;
    let receipt = client
        .native_apply_administration(
            &BlsSigner::new(42u64.into(), admin.chain_id()).unwrap(),
            &signed,
        )
        .await
        .expect("initialize membership policy");
    assert!(receipt.success);
}

#[tokio::test]
async fn validator_epoch_transition() {
    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9010;
    let bootstrap = KeySet::builder()
        .seed(chain_id)
        .build()
        .expect("bootstrap keys");
    let trusted_key = *bootstrap.epoch_info().output.public().public();
    let genesis = GenesisBuilder::devnet()
        .blocks_per_epoch(BLOCKS_PER_EPOCH)
        .simplex(SIMPLEX)
        .operators(administration::operators());

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
    let admin_signer = BlsSigner::random(chain_id).expect("random BLS signer");

    // ── A: Verify genesis validators ──────────────────────────────

    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(all_validators.len(), 4, "should have 4 genesis validators");

    // ── B: Set up ACP policy for write access ─────────────────────

    setup_acp_policy(&cluster, &client, &admin_signer).await;

    // ── C: Add a new validator ────────────────────────────────────

    let new_validator_addr: Address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        .parse()
        .unwrap();
    let new_public_key = ed25519::PrivateKey::from_seed(chain_id + 4).public_key();
    let new_consensus_key = B256::from_slice(Encode::encode(&new_public_key).as_ref());

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: new_validator_addr,
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
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorAdded::SIGNATURE_HASH,
        "event should be ValidatorAdded"
    );

    // Verify the validator was added
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        all_validators.len(),
        5,
        "should have 5 validators after add"
    );

    // ── D: Verify the registry-backed set completes resharing ─────

    let first_epoch = first_reshared_epoch(receipt.block_number);
    let first_height = first_epoch * BLOCKS_PER_EPOCH;
    let mut expected_players: Vec<_> = bootstrap
        .epoch_info()
        .output
        .players()
        .iter()
        .cloned()
        .chain([new_public_key])
        .collect();
    expected_players.sort();
    assert_eq!(expected_players.len(), 5);
    eprintln!(
        "validator added at height {}; first eligible voting epoch {first_epoch}, height {first_height}",
        receipt.block_number
    );
    state
        .wait_for_height(first_height, vera_e2e::readiness_deadline() * 2)
        .await
        .expect("cluster should reach the registry roster's first eligible voting epoch");

    let mut last_status = String::from("no eligible light block observed");
    let result = tokio::time::timeout(vera_e2e::readiness_deadline(), async {
        loop {
            let height = client
                .node_status()
                .await
                .expect("node status")
                .finalized_height
                .unwrap_or(0);
            if height >= first_height {
                let light = match client
                    .rpc_call_typed::<LightBlock>("vera_getLightBlock", serde_json::json!([height]))
                    .await
                {
                    Ok(light) => light,
                    Err(error) => {
                        last_status = format!("latest={height}, light block unavailable: {error}");
                        tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
                        continue;
                    }
                };
                assert_eq!(light.height, height, "light block must match the requested revision");
                assert!(light.epoch >= first_epoch);
                verify_light_block(&light, &trusted_key)
                    .expect("every epoch must retain the bootstrap consensus identity");
                let material = EpochMaterial::decode_bounded(
                    &hex::decode(light.epoch_material.trim_start_matches("0x")).unwrap(),
                )
                .unwrap();
                let changed = material.sharing != *bootstrap.epoch_info().output.public();
                let roster_matches = material.participants.iter().eq(expected_players.iter());
                last_status = format!(
                    "verified height={}, epoch={}, members={}, polynomial_changed={changed}, expected_roster={roster_matches}",
                    light.height, light.epoch, material.participants.len()
                );
                eprintln!("{last_status}");
                if roster_matches {
                    assert!(changed, "resharing must update the polynomial while preserving the consensus identity");
                    return;
                }
                // A failed ceremony legitimately carries the previous output forward.
                // Only certified material for the complete updated roster completes this wait.
            }
            tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
        }
    }).await;
    assert!(
        result.is_ok(),
        "updated validator roster never produced certified resharing material: {last_status}"
    );

    // ── E: Deactivate a validator → triggers another epoch ────────

    let calldata = IValidatorRegistry::setValidatorStatusCall {
        evmAddr: new_validator_addr,
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

    // ── F: Remove the validator → triggers another epoch ──────────

    let calldata = IValidatorRegistry::removeValidatorCall {
        evmAddr: new_validator_addr,
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

    // Verify back to 4 validators
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let final_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        final_validators.len(),
        4,
        "should be back to 4 validators after removal"
    );

    // ── G: Cross-node consistency ─────────────────────────────────

    let client2 = VeraClient::new(cluster.node(1).rpc_url());
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = registry_view(&client2, &admin_signer, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators from node 1");
    let node1_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        node1_validators.len(),
        final_validators.len(),
        "validator count should match across nodes"
    );
}
