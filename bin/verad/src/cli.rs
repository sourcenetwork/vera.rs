//! CLI for verad.

use std::{path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use commonware_cryptography::Signer as _;
use vera_config::NodeConfig;
use vera_genesis::{ValidatorConfig, VeraGenesis};
use vera_node::{NodeSettings, PeerSet, load_peers};

use crate::testnet;

#[derive(Parser, Debug)]
#[command(name = "verad")]
#[command(about = "SourceHub validator node (commonware + REVM)")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to config file.
    #[arg(short, long, value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,

    /// Override chain ID.
    #[arg(long, global = true)]
    pub chain_id: Option<u64>,

    /// Override data directory.
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Run validator node.
    Validator(ValidatorArgs),
    /// Run single-node devnet (no DKG required).
    Devnet(DevnetArgs),
    /// Run multi-node local testnet (trusted-dealer DKG).
    Testnet(testnet::TestnetArgs),
    /// Run the distributed epoch-0 DKG ceremony.
    Genesis(GenesisArgs),
    /// Interact with a running vera node.
    Client(crate::client::ClientArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct GenesisArgs {
    /// Path to peers.json containing the bootstrap participants and addresses.
    #[arg(long)]
    pub peers: PathBuf,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ValidatorArgs {
    /// Path to peers.json file containing participant information.
    #[arg(long)]
    pub peers: PathBuf,

    /// Override JSON-RPC port (default: 8545 + validator_index).
    #[arg(long)]
    pub rpc_port: Option<u16>,

    /// Inherit a listening TCP descriptor matching the configured RPC address (Unix).
    #[cfg(unix)]
    #[arg(long)]
    pub rpc_listener_fd: Option<std::os::fd::RawFd>,

    /// Leader proposal timeout in milliseconds.
    #[arg(long)]
    pub leader_timeout_ms: Option<u64>,

    /// Notarization timeout in milliseconds.
    #[arg(long)]
    pub notarization_timeout_ms: Option<u64>,

    /// Nullification retry interval in milliseconds.
    #[arg(long)]
    pub nullify_retry_ms: Option<u64>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct DevnetArgs {
    /// Genesis file path (defaults to built-in devnet genesis).
    #[arg(long)]
    pub genesis: Option<PathBuf>,

    /// JSON-RPC listen port.
    #[arg(long, default_value = "8545")]
    pub rpc_port: u16,

    /// Inherit a listening TCP descriptor matching the configured RPC address (Unix).
    #[cfg(unix)]
    #[arg(long)]
    pub rpc_listener_fd: Option<std::os::fd::RawFd>,

    /// Leader proposal timeout in milliseconds.
    #[arg(long)]
    pub leader_timeout_ms: Option<u64>,

    /// Notarization timeout in milliseconds.
    #[arg(long)]
    pub notarization_timeout_ms: Option<u64>,

    /// Nullification retry interval in milliseconds.
    #[arg(long)]
    pub nullify_retry_ms: Option<u64>,
}

impl Cli {
    pub(crate) fn run(self) -> eyre::Result<()> {
        // Client takes ownership; extract it before borrowing self for other arms.
        if let Some(Commands::Client(args)) = self.command {
            return args.run();
        }
        match &self.command {
            Some(Commands::Validator(args)) => self.run_validator(args),
            Some(Commands::Devnet(args)) => self.run_devnet(args),
            Some(Commands::Testnet(args)) => {
                let chain_id = self.chain_id.unwrap_or(9001);
                let data_dir = self.data_dir.clone().unwrap_or_else(|| {
                    std::env::temp_dir().join(format!("vera-testnet-{}", std::process::id()))
                });
                testnet::run(chain_id, data_dir, args)
            }
            Some(Commands::Genesis(args)) => self.run_genesis(args),
            Some(Commands::Client(_)) => unreachable!(),
            None => {
                eprintln!("No subcommand given. Use --help for usage.");
                std::process::exit(1);
            }
        }
    }

    fn load_config(&self) -> eyre::Result<NodeConfig> {
        let mut config = NodeConfig::load(self.config.as_deref())?;
        if let Some(chain_id) = self.chain_id {
            config.chain_id = chain_id;
        }
        if let Some(data_dir) = &self.data_dir {
            config.data_dir = data_dir.clone();
        }
        Ok(config)
    }

    fn run_validator(&self, args: &ValidatorArgs) -> eyre::Result<()> {
        let config = self.load_config()?;
        let peers = load_peers(&args.peers)?;
        let genesis = VeraGenesis::load(&config.data_dir.join("genesis.json"))?;
        let local = config.validator_key()?.public_key();
        let validator_index = peers
            .participants
            .iter()
            .position(|pk| *pk == local)
            .ok_or_else(|| eyre::eyre!("validator key is not listed in peers.json"))?;
        let rpc_port = args.rpc_port.unwrap_or(8545 + validator_index as u16);
        let settings = node_settings(
            config,
            genesis,
            peers,
            rpc_port,
            ConsensusTimeouts {
                leader_timeout_ms: args.leader_timeout_ms,
                notarization_timeout_ms: args.notarization_timeout_ms,
                nullify_retry_ms: args.nullify_retry_ms,
            },
        )?;
        tracing::info!(
            chain_id = settings.config.chain_id,
            validator_index,
            "Starting vera validator"
        );
        #[cfg(unix)]
        let listener = args
            .rpc_listener_fd
            .map(|fd| vera_cli::inherited_tcp_listener(fd, settings.rpc_addr))
            .transpose()?;
        #[cfg(not(unix))]
        let listener = None;
        run(settings, listener)
    }

    fn run_genesis(&self, args: &GenesisArgs) -> eyre::Result<()> {
        use commonware_runtime::{Runner as _, tokio};

        let config = self.load_config()?;
        let peers = load_peers(&args.peers)?;
        let genesis = VeraGenesis::load(&config.data_dir.join("genesis.json"))?;
        let storage = config.data_dir.join("bootstrap-commonware");
        let settings = vera_node::BootstrapSettings {
            secrets_path: config.data_dir.join("secrets.json"),
            config,
            genesis,
            peers,
        };
        let runtime = tokio::Config::default().with_storage_directory(storage);
        let info = tokio::Runner::new(runtime)
            .start(|context| async move { vera_node::run_bootstrap(context, settings).await })
            .map_err(anyhow_to_eyre)?;
        tracing::info!(
            epoch = info.epoch.get(),
            participants = info.players.len(),
            "Completed genesis DKG"
        );
        Ok(())
    }

    fn run_devnet(&self, args: &DevnetArgs) -> eyre::Result<()> {
        let mut config = self.load_config()?;
        let mut genesis = match &args.genesis {
            Some(path) => VeraGenesis::load(path)?,
            None => VeraGenesis::devnet(),
        };
        if self.chain_id.is_none() {
            config.chain_id = genesis.chain_id;
        }
        std::fs::create_dir_all(&config.data_dir)?;
        let key = config.validator_key()?;
        let local = key.public_key();
        configure_devnet_membership(&mut genesis, &local, &config.network.listen_addr)?;
        let (epoch_info, shares) =
            vera_node::trusted_setup(0, [local.clone()]).map_err(anyhow_to_eyre)?;
        genesis.epoch_info = Some(vera_node::epoch_info_hex(&epoch_info));
        let secrets_path = config.data_dir.join("secrets.json");
        let store = vera_node::FileSecretStore::load(&secrets_path).map_err(anyhow_to_eyre)?;
        let share = shares
            .get_value(&local)
            .cloned()
            .ok_or_else(|| eyre::eyre!("dealer produced no share for the devnet key"))?;
        store
            .put_initial_share(commonware_consensus::types::Epoch::zero(), share)
            .map_err(anyhow_to_eyre)?;
        let listen: std::net::SocketAddr = config.network.listen_addr.parse()?;
        let peers = PeerSet {
            participants: vec![local.clone()],
            bootstrappers: vec![(local, listen)],
        };
        let settings = node_settings(
            config,
            genesis,
            peers,
            args.rpc_port,
            ConsensusTimeouts {
                leader_timeout_ms: args.leader_timeout_ms,
                notarization_timeout_ms: args.notarization_timeout_ms,
                nullify_retry_ms: args.nullify_retry_ms,
            },
        )?;
        tracing::info!(
            chain_id = settings.config.chain_id,
            "Starting vera devnet (single-node)"
        );
        #[cfg(unix)]
        let listener = args
            .rpc_listener_fd
            .map(|fd| vera_cli::inherited_tcp_listener(fd, settings.rpc_addr))
            .transpose()?;
        #[cfg(not(unix))]
        let listener = None;
        run(settings, listener)
    }
}

fn configure_devnet_membership(
    genesis: &mut VeraGenesis,
    local: &commonware_cryptography::ed25519::PublicKey,
    listen_addr: &str,
) -> eyre::Result<()> {
    let consensus_pubkey = hex::encode(commonware_codec::Encode::encode(local));
    if genesis.validators.is_empty() {
        genesis.validators.push(ValidatorConfig {
            evm_address: format!("{:?}", vera_node::validator_address(local)),
            consensus_pubkey,
            p2p_address: listen_addr.into(),
        });
    } else {
        eyre::ensure!(
            genesis.validators.len() == 1
                && genesis.validators[0]
                    .consensus_pubkey
                    .trim_start_matches("0x")
                    == consensus_pubkey,
            "devnet membership must contain only the local consensus key"
        );
    }
    Ok(())
}

/// Convert node-crate errors into CLI reports.
pub(crate) fn anyhow_to_eyre(e: anyhow::Error) -> eyre::Report {
    eyre::eyre!("{e:#}")
}

/// Consensus timeouts in milliseconds; unset values use the defaults.
struct ConsensusTimeouts {
    leader_timeout_ms: Option<u64>,
    notarization_timeout_ms: Option<u64>,
    nullify_retry_ms: Option<u64>,
}

const DEFAULT_LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_NOTARIZATION_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_NULLIFY_RETRY: Duration = Duration::from_millis(500);

fn node_settings(
    config: NodeConfig,
    genesis: VeraGenesis,
    peers: PeerSet,
    rpc_port: u16,
    timeouts: ConsensusTimeouts,
) -> eyre::Result<NodeSettings> {
    let secrets_path = config.data_dir.join("secrets.json");
    // The CLI port (already defaulted per validator index) wins over the
    // config address; the config value binds only when it names a port the
    // caller did not override.
    let derived: std::net::SocketAddr = format!("0.0.0.0:{rpc_port}").parse()?;
    let rpc_addr = match config.rpc.http_addr.parse::<std::net::SocketAddr>() {
        Ok(configured) if configured.port() == rpc_port => configured,
        _ => derived,
    };
    Ok(NodeSettings {
        config,
        genesis,
        peers,
        secrets_path,
        rpc_addr,
        leader_timeout: timeouts
            .leader_timeout_ms
            .map_or(DEFAULT_LEADER_TIMEOUT, Duration::from_millis),
        certification_timeout: timeouts
            .notarization_timeout_ms
            .map_or(DEFAULT_NOTARIZATION_TIMEOUT, Duration::from_millis),
        timeout_retry: timeouts
            .nullify_retry_ms
            .map_or(DEFAULT_NULLIFY_RETRY, Duration::from_millis),
    })
}

/// Run the node on a commonware tokio runtime until it stops.
fn run(settings: NodeSettings, listener: Option<std::net::TcpListener>) -> eyre::Result<()> {
    use commonware_runtime::{Runner as _, tokio};
    let runtime = tokio::Config::default()
        .with_storage_directory(settings.config.data_dir.join("commonware"));
    tokio::Runner::new(runtime)
        .start(|context| async move {
            vera_node::run_node_with_rpc_listener(context, settings, listener).await
        })
        .map_err(|e| eyre::eyre!("node stopped: {e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn rpc_listener_descriptor_is_explicit_for_validator_and_devnet() {
        for mut arguments in [
            vec!["verad", "validator", "--peers", "peers.json"],
            vec!["verad", "devnet"],
        ] {
            let parsed = Cli::try_parse_from(&arguments).unwrap();
            let descriptor = |cli: Cli| match cli.command.unwrap() {
                Commands::Validator(args) => args.rpc_listener_fd,
                Commands::Devnet(args) => args.rpc_listener_fd,
                _ => unreachable!(),
            };
            assert_eq!(descriptor(parsed), None);
            arguments.extend(["--rpc-listener-fd", "9"]);
            assert_eq!(descriptor(Cli::try_parse_from(arguments).unwrap()), Some(9));
        }
    }

    #[test]
    fn devnet_initializes_registry_membership_and_rejects_a_different_key() {
        let key = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
        let mut genesis = VeraGenesis::devnet();
        configure_devnet_membership(&mut genesis, &key, "127.0.0.1:3000").unwrap();
        assert_eq!(
            genesis.to_genesis_state().unwrap().participant_addresses,
            vec![vera_node::validator_address(&key)]
        );
        configure_devnet_membership(&mut genesis, &key, "127.0.0.1:3000").unwrap();
        assert_eq!(genesis.validators.len(), 1);
        let other = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
        assert!(configure_devnet_membership(&mut genesis, &other, "127.0.0.1:3000").is_err());
    }
}
