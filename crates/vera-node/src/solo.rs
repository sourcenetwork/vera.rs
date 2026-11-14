//! Single-validator deployments owned by one account.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use commonware_consensus::types::Epoch;
use commonware_cryptography::Signer as _;
use vera_config::NodeConfig;
use vera_genesis::{ValidatorConfig, VeraGenesis};
use vera_modules::vera::administration::OperatorPolicy;

use crate::{FileSecretStore, PeerSet};

/// Epoch length that leaves dealing slots for eight validators with default pipelined terms.
pub const SOLO_BLOCKS_PER_EPOCH: u64 = 256;

/// Finality stall, in milliseconds, after which a leader's term is abandoned in a solo deployment.
///
/// A lone validator has no successor, so this only bounds the timeouts and the
/// idle wait a host may configure. It leaves room for a heartbeat well inside
/// the 30 seconds a verifying client accepts a finalized state for.
pub const SOLO_STALL_TIMEOUT_MS: u64 = 30_000;

const GENESIS_FILE: &str = "solo-genesis.json";

/// Identity of a deployment that starts with this device as its only validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoloGenesis {
    /// Deployment chain identifier.
    pub chain_id: u64,
    /// The account's administrative keys; they authorize later membership changes.
    pub operators: OperatorPolicy,
    /// Genesis timestamp in Unix seconds, used only when the deployment is first created.
    pub timestamp: u64,
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
}

/// Create the deployment in `config.data_dir`, or reopen the one already there.
///
/// The first call deals the consensus share from operating-system randomness and
/// records the genesis. Later calls reuse both and reject a different identity.
pub fn prepare_solo(
    config: &NodeConfig,
    identity: &SoloGenesis,
) -> Result<(VeraGenesis, PeerSet), SoloError> {
    let directory = &config.data_dir;
    std::fs::create_dir_all(directory).map_err(|source| io(directory, source))?;
    let key = config.validator_key()?;
    let local = key.public_key();
    let listen: std::net::SocketAddr = config
        .network
        .listen_addr
        .parse()
        .map_err(|_| SoloError::ListenAddress(config.network.listen_addr.clone()))?;
    let store = FileSecretStore::load(directory.join("secrets.json"))
        .map_err(|error| SoloError::Share(format!("{error:#}")))?;
    let stored = directory.join(GENESIS_FILE);
    let genesis = if stored.exists() {
        let genesis =
            VeraGenesis::load(&stored).map_err(|error| SoloError::Genesis(error.to_string()))?;
        if genesis.chain_id != identity.chain_id {
            return Err(SoloError::Mismatch("chain identifier"));
        }
        if genesis.operators.as_ref() != Some(&identity.operators) {
            return Err(SoloError::Mismatch("operator policy"));
        }
        let expected = validator(&local, &config.network.listen_addr);
        let same_validator = matches!(genesis.validators.as_slice(), [only]
            if only.consensus_pubkey == expected.consensus_pubkey
                && only.evm_address == expected.evm_address);
        if !same_validator {
            return Err(SoloError::Mismatch("validator key"));
        }
        if !store.has_shares() {
            return Err(SoloError::Incomplete("consensus share is missing"));
        }
        genesis
    } else {
        if store.has_shares() {
            return Err(SoloError::Incomplete(
                "consensus shares exist without a genesis",
            ));
        }
        identity
            .operators
            .validate()
            .map_err(|error| SoloError::Genesis(error.to_string()))?;
        let (epoch_info, shares) = crate::bootstrap::random_setup([local.clone()])
            .map_err(|error| SoloError::Share(format!("{error:#}")))?;
        let share = shares
            .get_value(&local)
            .cloned()
            .ok_or_else(|| SoloError::Share("dealer produced no share".into()))?;
        let genesis = VeraGenesis {
            chain_id: identity.chain_id,
            operators: Some(identity.operators.clone()),
            chain_name: "vera-solo".into(),
            timestamp: identity.timestamp,
            allocations: Vec::new(),
            native_mint: Default::default(),
            validators: vec![validator(&local, &config.network.listen_addr)],
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            policies: Vec::new(),
            node_demerits: Vec::new(),
            epoch_info: Some(crate::epoch_info_hex(&epoch_info)),
            blocks_per_epoch: SOLO_BLOCKS_PER_EPOCH,
            simplex: Some(vera_domain::SimplexParameters {
                stall_timeout_ms: SOLO_STALL_TIMEOUT_MS,
                ..Default::default()
            }),
        };
        // The share is stored first: a genesis record without its share cannot be recovered.
        store
            .put_initial_share(Epoch::zero(), share)
            .map_err(|error| SoloError::Share(format!("{error:#}")))?;
        write_genesis(directory, &stored, &genesis)?;
        genesis
    };
    genesis
        .validate_timestamp()
        .map_err(|error| SoloError::Genesis(error.to_string()))?;
    let peers = PeerSet {
        participants: vec![local.clone()],
        bootstrappers: vec![(local, listen)],
    };
    Ok((genesis, peers))
}

/// The registry entry for a deployment's only validator.
#[must_use]
fn validator(
    key: &commonware_cryptography::ed25519::PublicKey,
    listen_addr: &str,
) -> ValidatorConfig {
    ValidatorConfig {
        evm_address: format!("{:?}", crate::validator_address(key)),
        consensus_pubkey: hex::encode(commonware_codec::Encode::encode(key)),
        p2p_address: listen_addr.into(),
    }
}

fn write_genesis(directory: &Path, path: &Path, genesis: &VeraGenesis) -> Result<(), SoloError> {
    let bytes = serde_json::to_vec_pretty(genesis)
        .map_err(|error| SoloError::Genesis(error.to_string()))?;
    let temporary = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&temporary).map_err(|source| io(&temporary, source))?;
    file.write_all(&bytes)
        .map_err(|source| io(&temporary, source))?;
    file.sync_all().map_err(|source| io(&temporary, source))?;
    std::fs::rename(&temporary, path).map_err(|source| io(path, source))?;
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io(directory, source))
}

fn io(path: &Path, source: std::io::Error) -> SoloError {
    SoloError::Io {
        path: path.to_path_buf(),
        source,
    }
}
