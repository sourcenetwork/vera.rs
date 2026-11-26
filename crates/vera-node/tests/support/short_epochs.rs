//! A solo deployment with epochs short enough for a test to cross several.

use std::path::Path;

use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use vera_genesis::{ValidatorConfig, VeraGenesis};
use vera_jsonrpc::NodeStatus;
use vera_modules::vera::administration::OperatorPolicy;
use vera_node::{
    EmbeddedConfig, EmbeddedNode, FileSecretStore, SOLO_STALL_TIMEOUT_MS, SoloDeployment, SoloKeys,
};

use super::support::block_on;

pub(crate) const BLOCKS_PER_EPOCH: u64 = 32;

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// A deployment dealt from `seed`, as `SoloDeployment::create` deals one but for the epoch length.
pub(crate) fn deployment(chain_id: u64, seed: u64) -> SoloDeployment {
    deployment_under(
        chain_id,
        seed,
        OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
    )
}

/// [`deployment`], administered by `operators`.
pub(crate) fn deployment_under(
    chain_id: u64,
    seed: u64,
    operators: OperatorPolicy,
) -> SoloDeployment {
    let key = PrivateKey::from_seed(seed);
    let local = key.public_key();
    let (epoch_info, shares) = vera_node::trusted_setup(seed, [local.clone()]).unwrap();
    let share = shares.get_value(&local).unwrap();
    let genesis = VeraGenesis {
        chain_id,
        operators: Some(operators),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        validators: vec![ValidatorConfig {
            address: format!("{:?}", vera_node::validator_address(&local)),
            consensus_pubkey: hex::encode(local.encode()),
            p2p_address: "127.0.0.1:0".into(),
        }],
        policies: Vec::new(),
        placed_policies: Vec::new(),
        node_demerits: Vec::new(),
        epoch_info: Some(vera_node::epoch_info_hex(&epoch_info)),
        blocks_per_epoch: BLOCKS_PER_EPOCH,
        simplex: vera_domain::SimplexParameters {
            stall_timeout_ms: SOLO_STALL_TIMEOUT_MS,
            ..Default::default()
        },
        timestamp_step_secs: Some(u64::MAX),
    };
    SoloDeployment::new(
        serde_json::to_vec_pretty(&genesis).unwrap(),
        SoloKeys::decode(&key.encode(), &share.encode()).unwrap(),
    )
}

/// Lay `deployment` out in `directory` as a node that keeps its keys in files does.
pub(crate) fn store_in_files(directory: &Path, deployment: &SoloDeployment) {
    std::fs::write(directory.join("solo-genesis.json"), deployment.record()).unwrap();
    vera_cli::write_private(
        directory.join("validator.key"),
        &deployment.keys().validator_key(),
    )
    .unwrap();
    let share = commonware_codec::DecodeExt::decode(commonware_codec::Copying(
        deployment.keys().share().as_slice(),
    ))
    .unwrap();
    FileSecretStore::load(directory.join("secrets.json"))
        .unwrap()
        .put_initial_share(Epoch::zero(), share)
        .unwrap();
}

/// The shared test settings for `deployment`, at the daemon's cadence, which
/// crosses an epoch in seconds. `held` keeps the key material out of the directory.
pub(crate) fn settings(
    directory: &Path,
    deployment: &SoloDeployment,
    held: bool,
) -> EmbeddedConfig {
    let mut config = super::support::config(directory, 0);
    config.genesis = deployment.identity().unwrap();
    config.deployment = held.then(|| deployment.clone());
    config.pacing = None;
    config
}

pub(crate) fn height(node: &EmbeddedNode) -> u64 {
    let status: NodeStatus = block_on(node.rpc().call_empty("vera_nodeStatus")).unwrap();
    status.finalized_height.unwrap_or(0)
}

/// Wait until the node has finalized a block for which `reached` holds, and return its height.
pub(crate) fn run_until(node: &EmbeddedNode, reached: impl Fn(u64) -> bool) -> u64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        let height = height(node);
        if reached(height) {
            return height;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "stalled at height {height}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
