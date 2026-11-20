//! Single-validator deployments owned by one account.

use std::path::{Path, PathBuf};

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _, bls12381::primitives::group::Share, ed25519::PublicKey,
};
use vera_config::NodeConfig;
use vera_genesis::{ValidatorConfig, VeraGenesis};
use vera_modules::vera::administration::OperatorPolicy;

use crate::{FileSecretStore, PeerSet};

mod adopt;
mod deployment;
mod device_key;
mod follow;
mod keys;
mod record;

pub(crate) use adopt::{adopt_solo, export_solo};
pub use deployment::SoloDeployment;
pub use device_key::DeviceKey;
pub(crate) use follow::follow_solo;
pub use keys::SoloKeys;
pub(crate) use record::record_identity;

/// Epoch length that leaves dealing slots for eight validators with default pipelined terms.
pub const SOLO_BLOCKS_PER_EPOCH: u64 = 256;

/// Finality stall, in milliseconds, after which a leader's term is abandoned in a solo deployment.
///
/// A lone validator has no successor, so this only bounds the timeouts and the
/// idle wait a host may configure. It leaves room for a heartbeat well inside
/// the 30 seconds a verifying client accepts a finalized state for.
pub const SOLO_STALL_TIMEOUT_MS: u64 = 30_000;

const GENESIS_FILE: &str = "solo-genesis.json";
/// A genesis written before its share is stored, published once the share is durable.
const PENDING_FILE: &str = "solo-genesis.pending";

/// Identity of a deployment that starts with this device as its only validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoloGenesis {
    /// Deployment chain identifier.
    pub chain_id: u64,
    /// The account's administrative keys; they authorize later membership changes.
    pub operators: OperatorPolicy,
    /// Genesis timestamp in Unix seconds, used only when the deployment is first created.
    pub timestamp: u64,
    /// ACP policies the deployment starts with, under the owners and nonces given.
    pub policies: Vec<vera_modules::acp::PlacedPolicy>,
}

/// Failure to create or reopen a single-validator deployment.
#[derive(Debug, thiserror::Error)]
pub enum SoloError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// File or directory involved.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The validator key could not be loaded or created.
    #[error("validator key: {0}")]
    ValidatorKey(#[from] vera_config::ConfigError),
    /// The stored genesis is unreadable or inconsistent.
    #[error("stored genesis: {0}")]
    Genesis(String),
    /// A seeded policy does not compile, or two share an identifier.
    #[error("seeded policies: {0}")]
    Policies(String),
    /// The directory belongs to a deployment with a different identity.
    #[error("data directory holds a different deployment: {0}")]
    Mismatch(&'static str),
    /// The directory holds validator state but no deployment record, or the reverse.
    #[error("data directory is incomplete: {0}")]
    Incomplete(&'static str),
    /// The listen address is not a socket address.
    #[error("invalid listen address {0}")]
    ListenAddress(String),
    /// Key material could not be dealt or stored.
    #[error("consensus share: {0}")]
    Share(String),
    /// Key material supplied by the host does not decode.
    #[error("key material: {0}")]
    KeyMaterial(&'static str),
    /// The consensus share is not the one the deployment's genesis was dealt with.
    #[error("consensus share does not match the deployment's genesis")]
    ShareMismatch,
}

/// Create the deployment in `config.data_dir`, or reopen the one already there.
///
/// The first call deals the consensus share from operating-system randomness and
/// records the genesis. Later calls reuse both and reject a different identity.
/// A first call interrupted before the genesis is published is finished by the next.
pub fn prepare_solo(
    config: &NodeConfig,
    identity: &SoloGenesis,
) -> Result<(VeraGenesis, PeerSet), SoloError> {
    let directory = &config.data_dir;
    std::fs::create_dir_all(directory).map_err(|source| io(directory, source))?;
    let key = config.validator_key()?;
    let local = key.public_key();
    let listen = listen_address(config)?;
    let store = FileSecretStore::load(directory.join("secrets.json"))
        .map_err(|error| SoloError::Share(format!("{error:#}")))?;
    let stored = directory.join(GENESIS_FILE);
    if !stored.exists() {
        let pending = directory.join(PENDING_FILE);
        if store.has_shares() {
            if !pending.exists() {
                return Err(SoloError::Incomplete(
                    "consensus shares exist without a genesis",
                ));
            }
        } else {
            create(config, identity, &local, &store, &pending)?;
            #[cfg(feature = "fault-injection")]
            crate::crash::point(directory, "solo-dealt");
        }
        std::fs::rename(&pending, &stored).map_err(|source| io(&stored, source))?;
        vera_cli::sync_parent(&stored).map_err(|source| io(directory, source))?;
    }
    let genesis =
        VeraGenesis::load(&stored).map_err(|error| SoloError::Genesis(error.to_string()))?;
    check_identity(&genesis, identity, &local)?;
    if !store.has_shares() {
        return Err(SoloError::Incomplete("consensus share is missing"));
    }
    genesis
        .validate_timestamp()
        .map_err(|error| SoloError::Genesis(error.to_string()))?;
    Ok((genesis, lone_peer(local, listen)))
}

/// Refuse a genesis that is not `identity`'s deployment validated by `local`.
fn check_identity(
    genesis: &VeraGenesis,
    identity: &SoloGenesis,
    local: &PublicKey,
) -> Result<(), SoloError> {
    if genesis.chain_id != identity.chain_id {
        return Err(SoloError::Mismatch("chain identifier"));
    }
    if genesis.operators.as_ref() != Some(&identity.operators) {
        return Err(SoloError::Mismatch("operator policy"));
    }
    if genesis.placed_policies != identity.policies {
        return Err(SoloError::Mismatch("seeded policies"));
    }
    let same_validator = matches!(genesis.validators.as_slice(), [only]
        if only.consensus_pubkey == consensus_pubkey(local)
            && only.evm_address == evm_address(local));
    if !same_validator {
        return Err(SoloError::Mismatch("validator key"));
    }
    Ok(())
}

fn lone_peer(local: PublicKey, listen: std::net::SocketAddr) -> PeerSet {
    PeerSet {
        participants: vec![local.clone()],
        bootstrappers: vec![(local, listen)],
    }
}

fn listen_address(config: &NodeConfig) -> Result<std::net::SocketAddr, SoloError> {
    config
        .network
        .listen_addr
        .parse()
        .map_err(|_| SoloError::ListenAddress(config.network.listen_addr.clone()))
}

/// Deal a share and record the genesis it belongs to under its pending name.
///
/// The pending genesis is durable before the share, so a start interrupted
/// after the share is stored still finds the genesis that share was dealt for;
/// one interrupted earlier holds no share and deals again.
fn create(
    config: &NodeConfig,
    identity: &SoloGenesis,
    local: &PublicKey,
    store: &FileSecretStore,
    pending: &Path,
) -> Result<(), SoloError> {
    let (genesis, share) = deal(identity, local, &config.network.listen_addr)?;
    vera_cli::write_durable(pending, &encode(&genesis)?).map_err(|source| io(pending, source))?;
    store
        .put_initial_share(Epoch::zero(), share)
        .map_err(|error| SoloError::Share(format!("{error:#}")))
}

/// The genesis of a new deployment validated by `local`, with its only share.
fn deal(
    identity: &SoloGenesis,
    local: &PublicKey,
    listen_addr: &str,
) -> Result<(VeraGenesis, Share), SoloError> {
    identity
        .operators
        .validate()
        .map_err(|error| SoloError::Genesis(error.to_string()))?;
    // Compiled before anything is stored: a stored seed list fixes the
    // deployment's identity, so a refused one could not be corrected in place.
    vera_modules::ModuleState::default()
        .acp
        .initialize_placed_policies(&identity.policies)
        .map_err(|error| SoloError::Policies(error.to_string()))?;
    let (epoch_info, shares) = crate::bootstrap::random_setup([local.clone()])
        .map_err(|error| SoloError::Share(format!("{error:#}")))?;
    let share = shares
        .get_value(local)
        .cloned()
        .ok_or_else(|| SoloError::Share("dealer produced no share".into()))?;
    let genesis = VeraGenesis {
        chain_id: identity.chain_id,
        operators: Some(identity.operators.clone()),
        timestamp: identity.timestamp,
        allocations: Vec::new(),
        validators: vec![validator(local, listen_addr)],
        contracts: Vec::new(),
        extra_storage: Vec::new(),
        policies: Vec::new(),
        placed_policies: identity.policies.clone(),
        node_demerits: Vec::new(),
        epoch_info: Some(crate::epoch_info_hex(&epoch_info)),
        blocks_per_epoch: SOLO_BLOCKS_PER_EPOCH,
        simplex: Some(vera_domain::SimplexParameters {
            stall_timeout_ms: SOLO_STALL_TIMEOUT_MS,
            ..Default::default()
        }),
        // A lone validator proposes every block from its own clock, and
        // an idle or paused device must not fall behind it.
        timestamp_step_secs: Some(u64::MAX),
    };
    Ok((genesis, share))
}

fn encode(genesis: &VeraGenesis) -> Result<Vec<u8>, SoloError> {
    serde_json::to_vec_pretty(genesis).map_err(|error| SoloError::Genesis(error.to_string()))
}

/// The registry entry for a deployment's only validator.
#[must_use]
fn validator(key: &PublicKey, listen_addr: &str) -> ValidatorConfig {
    ValidatorConfig {
        evm_address: evm_address(key),
        consensus_pubkey: consensus_pubkey(key),
        p2p_address: listen_addr.into(),
    }
}

fn evm_address(key: &PublicKey) -> String {
    format!("{:?}", crate::validator_address(key))
}

fn consensus_pubkey(key: &PublicKey) -> String {
    hex::encode(commonware_codec::Encode::encode(key))
}

fn io(path: &Path, source: std::io::Error) -> SoloError {
    SoloError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[path = "solo_tests.rs"]
mod tests;
