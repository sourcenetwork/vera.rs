//! Multi-node local testnet orchestrator for vera.
//!
//! Generates identity keys, produces threshold schemes via trusted-dealer mode,
//! writes all config files, and spawns N validator child processes on
//! localhost with dynamically allocated ports.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::Duration,
};

use commonware_codec::Encode;
use commonware_cryptography::{Signer as _, ed25519};
use tracing::info;
use vera_genesis::{ValidatorConfig, VeraGenesis};

mod ports;

/// CLI arguments for the testnet command.
#[derive(clap::Args, Debug)]
pub(crate) struct TestnetArgs {
    /// Number of validator nodes (minimum 4 for BFT quorum).
    #[arg(long, default_value = "4")]
    pub nodes: usize,

    /// Base P2P port. 0 = auto-allocate (default).
    #[arg(long, default_value = "0")]
    pub base_p2p_port: u16,

    /// Base JSON-RPC port. 0 = auto-allocate (default).
    #[arg(long, default_value = "0")]
    pub base_rpc_port: u16,

    /// Genesis file path (defaults to built-in devnet genesis).
    #[arg(long)]
    pub genesis: Option<PathBuf>,

    /// Use deterministic keys from a seed (for reproducible testnets).
    #[arg(long)]
    pub seed: Option<u64>,

    /// Only generate config files without starting validators.
    #[arg(long, default_value = "false")]
    pub init_only: bool,
}

/// Run the multi-node testnet.
pub(crate) fn run(
    chain_id: Option<u64>,
    data_dir: PathBuf,
    args: &TestnetArgs,
) -> eyre::Result<()> {
    let n = args.nodes;
    if n < 4 {
        return Err(eyre::eyre!(
            "Minimum 4 nodes required for BFT quorum (got {})",
            n
        ));
    }

    let mut genesis = if let Some(ref path) = args.genesis {
        VeraGenesis::load(path).map_err(|e| eyre::eyre!("Failed to load genesis: {}", e))?
    } else {
        let mut genesis = VeraGenesis::devnet();
        genesis.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        genesis
    };
    genesis.validate_timestamp()?;
    let chain_id = crate::chain_id::reconcile(
        &mut genesis,
        args.genesis.is_some(),
        chain_id.map(crate::chain_id::Requested::Flag),
    )?;
    let ports::Ports {
        p2p: p2p_ports,
        rpc: rpc_ports,
    } = ports::resolve(n, args.base_p2p_port, args.base_rpc_port)?;

    info!(nodes = n, chain_id, data_dir = %data_dir.display(), "Setting up vera testnet");

    // Create base directory.
    std::fs::create_dir_all(&data_dir)?;

    // Resolve seed upfront (used for both identity keys and threshold schemes).
    let seed = args.seed.unwrap_or_else(rand::random);

    info!(
        p2p_ports = ?p2p_ports,
        rpc_ports = ?rpc_ports,
        "Allocated ports"
    );

    // ── Phase 1: Generate identity keys ──────────────────────────────────────

    let mut keys = Vec::with_capacity(n);
    let mut participants = Vec::with_capacity(n);

    for i in 0..n {
        let node_dir = data_dir.join(format!("node{}", i));
        std::fs::create_dir_all(&node_dir)?;

        let key = ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64));

        let pk = key.public_key();
        let pk_hex = hex::encode(Encode::encode(&pk));
        info!(node = i, pk = %pk_hex, "Generated identity key");

        // Write validator.key (32 bytes that NodeConfig::validator_key() reads).
        let key_bytes = Encode::encode(&key);
        vera_cli::write_private(node_dir.join("validator.key"), key_bytes.as_ref())?;

        participants.push(pk);
        keys.push(key);
    }

    // ── Phase 2: Write peers.json ────────────────────────────────────────────

    // Threshold: n - f where f = (n-1)/3 (BFT quorum).
    let f = (n - 1) / 3;
    let threshold = (n - f) as u32;

    let participants_hex: Vec<String> = participants
        .iter()
        .map(|pk| hex::encode(Encode::encode(pk)))
        .collect();

    let bootstrappers: BTreeMap<String, String> = participants
        .iter()
        .enumerate()
        .map(|(i, pk)| {
            let pk_hex = hex::encode(Encode::encode(pk));
            let addr = format!("127.0.0.1:{}", p2p_ports[i]);
            (pk_hex, addr)
        })
        .collect();

    let peers_json = serde_json::json!({
        "participants": participants_hex,
        "bootstrappers": bootstrappers,
    });
    let peers_path = data_dir.join("peers.json");
    std::fs::write(&peers_path, serde_json::to_string_pretty(&peers_json)?)?;
    info!(path = %peers_path.display(), threshold, "Wrote peers.json");

    // ── Phase 3: Write genesis.json to each node ─────────────────────────────

    let (epoch_info, shares) = vera_node::trusted_setup(seed, participants.iter().cloned())
        .map_err(crate::cli::anyhow_to_eyre)?;
    genesis.epoch_info = Some(vera_node::epoch_info_hex(&epoch_info));
    if genesis.validators.is_empty() {
        genesis.validators = participants
            .iter()
            .zip(&p2p_ports)
            .map(|(public_key, port)| ValidatorConfig {
                evm_address: format!("{:?}", vera_node::validator_address(public_key)),
                consensus_pubkey: hex::encode(Encode::encode(public_key)),
                p2p_address: format!("127.0.0.1:{port}"),
            })
            .collect();
    }
    let genesis_json = serde_json::to_string_pretty(&genesis)?;

    for (i, pk) in participants.iter().enumerate() {
        let node_dir = data_dir.join(format!("node{}", i));
        std::fs::write(node_dir.join("genesis.json"), &genesis_json)?;
        let share = shares
            .get_value(pk)
            .cloned()
            .ok_or_else(|| eyre::eyre!("dealer produced no share for node{i}"))?;
        vera_node::FileSecretStore::load(node_dir.join("secrets.json"))
            .map_err(crate::cli::anyhow_to_eyre)?
            .put_initial_share(commonware_consensus::types::Epoch::zero(), share)
            .map_err(crate::cli::anyhow_to_eyre)?;
    }
    info!("Wrote genesis.json and secrets.json to all nodes");

    // ── Phase 4: Write config.toml for each node ─────────────────────────────

    for i in 0..n {
        let node_dir = data_dir.join(format!("node{}", i));

        let config = vera_config::NodeConfig {
            chain_id,
            data_dir: node_dir.clone(),
            network: vera_config::NetworkConfig {
                listen_addr: format!("0.0.0.0:{}", p2p_ports[i]),
                dialable_addr: None,
                discovery: vera_config::DiscoveryConfig::local(),
            },
            rpc: vera_config::RpcConfig {
                http_addr: format!("0.0.0.0:{}", rpc_ports[i]),
                // ws_addr is unused by the RPC server but set explicitly to
                // avoid misleading defaults that look like port conflicts.
                ws_addr: format!("0.0.0.0:{}", rpc_ports[i]),
                ..Default::default()
            },
            ..Default::default()
        };

        let config_path = node_dir.join("config.toml");
        std::fs::write(&config_path, config.to_toml()?)?;
    }
    info!("Wrote config.toml for all nodes");

    if args.init_only {
        print_config_summary(n, &p2p_ports, &rpc_ports, &data_dir, &peers_path, seed);
        return Ok(());
    }

    // ── Phase 5: Spawn validator processes ───────────────────────────────────

    let binary = std::env::current_exe()?;
    let mut children: Vec<(usize, Child)> = Vec::with_capacity(n);

    for (i, rpc_port) in rpc_ports.iter().enumerate() {
        let node_dir = data_dir.join(format!("node{}", i));
        let config_path = node_dir.join("config.toml");

        let child = Command::new(&binary)
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "--data-dir",
                node_dir.to_str().unwrap(),
                "--chain-id",
                &chain_id.to_string(),
                "validator",
                "--peers",
                peers_path.to_str().unwrap(),
                "--rpc-port",
                &rpc_port.to_string(),
            ])
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            )
            .spawn()
            .map_err(|e| eyre::eyre!("Failed to spawn node{}: {}", i, e))?;

        info!(node = i, pid = child.id(), "Spawned validator");
        children.push((i, child));
    }

    // ── Health check ─────────────────────────────────────────────────────────

    info!("Waiting for validators to start...");
    std::thread::sleep(Duration::from_secs(3));

    let mut healthy = 0;
    for attempt in 0..30 {
        healthy = 0;
        for rpc_port in &rpc_ports {
            let url = format!("http://127.0.0.1:{}", rpc_port);
            if check_rpc_health(&url) {
                healthy += 1;
            }
        }
        if healthy == n {
            break;
        }
        if attempt < 29 {
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    if healthy < n {
        tracing::warn!(healthy, total = n, "Not all validators are healthy");
    }

    // ── Print status ─────────────────────────────────────────────────────────

    println!();
    println!("  Vera Testnet ({} nodes, threshold {})", n, threshold);
    println!("  ─────────────────────────────────────────────");
    for i in 0..n {
        let status = if check_rpc_health(&format!("http://127.0.0.1:{}", rpc_ports[i])) {
            "healthy"
        } else {
            "starting"
        };
        println!(
            "  node{}  P2P: {}  RPC: http://127.0.0.1:{}  [{}]",
            i, p2p_ports[i], rpc_ports[i], status
        );
    }
    println!("  ─────────────────────────────────────────────");
    println!("  Chain ID:  {}", chain_id);
    println!("  Data dir:  {}", data_dir.display());
    println!("  Peers:     {}", peers_path.display());
    println!();
    println!("  Press Ctrl+C to stop all validators");
    println!();

    // ── Wait for children ────────────────────────────────────────────────────
    //
    // On Ctrl+C, SIGINT is sent to the entire process group.
    // Children receive it, shut down, and we reap them here.

    for (i, child) in &mut children {
        match child.wait() {
            Ok(status) => {
                if status.success() {
                    info!(node = i, "Validator exited cleanly");
                } else {
                    tracing::warn!(node = i, code = ?status.code(), "Validator exited with error");
                }
            }
            Err(e) => {
                tracing::error!(node = i, error = %e, "Failed to wait for validator");
            }
        }
    }

    Ok(())
}

/// Print summary when using --init-only.
fn print_config_summary(
    n: usize,
    p2p_ports: &[u16],
    rpc_ports: &[u16],
    data_dir: &Path,
    peers_path: &Path,
    seed: u64,
) {
    println!();
    println!("  Vera testnet config generated ({} nodes)", n);
    println!("  ─────────────────────────────────────────────");
    println!("  Data dir:  {}", data_dir.display());
    println!("  Peers:     {}", peers_path.display());
    println!("  Seed:      {}", seed);
    println!();
    println!("  Port assignments:");
    for i in 0..n {
        println!(
            "    node{}  P2P: {}  RPC: {}",
            i, p2p_ports[i], rpc_ports[i]
        );
    }
    println!();
    println!("  Start each validator with:");
    for (i, rpc_port) in rpc_ports.iter().enumerate() {
        let node_dir = data_dir.join(format!("node{}", i));
        println!(
            "    verad --config {}/config.toml validator --peers {} --rpc-port {}",
            node_dir.display(),
            peers_path.display(),
            rpc_port,
        );
    }
    println!();
}

/// Quick JSON-RPC health check (blocking).
fn check_rpc_health(url: &str) -> bool {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "vera_nodeStatus",
        "params": [],
        "id": 1
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build();

    let Ok(client) = client else {
        return false;
    };

    client
        .post(url)
        .json(&body)
        .send()
        .and_then(|r| r.error_for_status())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_only(genesis: Option<PathBuf>) -> TestnetArgs {
        TestnetArgs {
            nodes: 4,
            base_p2p_port: 0,
            base_rpc_port: 0,
            genesis,
            seed: Some(7),
            init_only: true,
        }
    }

    #[test]
    fn generated_configuration_shares_the_chain_id_and_states_local_discovery() {
        let dir =
            std::env::temp_dir().join(format!("verad-testnet-chain-id-{}", std::process::id()));
        let chain_ids = |network: &Path| {
            let node = network.join("node3");
            (
                VeraGenesis::load(&node.join("genesis.json"))
                    .unwrap()
                    .chain_id,
                vera_config::NodeConfig::load(Some(&node.join("config.toml")))
                    .unwrap()
                    .chain_id,
            )
        };

        let flagged = dir.join("flagged");
        run(Some(1234), flagged.clone(), &init_only(None)).unwrap();
        assert_eq!(chain_ids(&flagged), (1234, 1234));
        for node in 0..4 {
            let config = flagged.join(format!("node{node}")).join("config.toml");
            assert_eq!(
                vera_config::NodeConfig::load(Some(&config))
                    .unwrap()
                    .network
                    .discovery,
                vera_config::DiscoveryConfig::local()
            );
        }

        let template = flagged.join("node0").join("genesis.json");
        let inherited = dir.join("inherited");
        run(None, inherited.clone(), &init_only(Some(template.clone()))).unwrap();
        assert_eq!(chain_ids(&inherited), (1234, 1234));

        let conflicting = dir.join("conflicting");
        assert!(run(Some(9001), conflicting.clone(), &init_only(Some(template))).is_err());
        assert!(!conflicting.exists());

        std::fs::remove_dir_all(dir).unwrap();
    }
}
