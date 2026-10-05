//! TestCluster builder — composes keys, config, and genesis into a runnable cluster.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use test_infra::{BinaryResolver, ManagedProcess, TestRunDir};

use super::{
    genesis::{GenesisBuilder, ValidatorConfig},
    keys::KeySet,
    node_config::{ConsensusPreset, NodeConfigBuilder},
    runtime::{TestCluster, TestNode},
};

type JmtSeeder = Box<dyn Fn(&Path, u64) + Send>;

/// Builder for `TestCluster`.
pub struct TestClusterBuilder {
    node_count: usize,
    seed: Option<u64>,
    genesis: Option<GenesisBuilder>,
    preset: ConsensusPreset,
    chain_id: u64,
    rpc_max_connections: std::num::NonZeroU32,
    jmt_seeder: Option<JmtSeeder>,
    binary: Option<PathBuf>,
    rust_log: Option<String>,
}

impl fmt::Debug for TestClusterBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestClusterBuilder")
            .field("node_count", &self.node_count)
            .field("seed", &self.seed)
            .field("genesis", &self.genesis)
            .field("preset", &self.preset)
            .field("chain_id", &self.chain_id)
            .field("has_jmt_seeder", &self.jmt_seeder.is_some())
            .field("binary", &self.binary)
            .field("rust_log", &self.rust_log)
            .finish()
    }
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            node_count: 1,
            seed: None,
            genesis: None,
            preset: ConsensusPreset::Fast,
            chain_id: 9001,
            rpc_max_connections: std::num::NonZeroU32::new(100).unwrap(),
            jmt_seeder: None,
            binary: None,
            rust_log: None,
        }
    }
}

impl TestClusterBuilder {
    /// Set the per-node RPC connection limit.
    #[must_use]
    pub const fn rpc_max_connections(mut self, limit: std::num::NonZeroU32) -> Self {
        self.rpc_max_connections = limit;
        self
    }

    /// Set the number of nodes in the cluster.
    #[must_use]
    pub const fn nodes(mut self, n: usize) -> Self {
        self.node_count = n;
        self
    }

    /// Set a deterministic seed for key generation.
    #[must_use]
    pub const fn seed(mut self, s: u64) -> Self {
        self.seed = Some(s);
        self
    }

    /// Set a custom genesis configuration.
    #[must_use]
    pub fn genesis(mut self, g: GenesisBuilder) -> Self {
        self.genesis = Some(g);
        self
    }

    /// Set the consensus timing preset.
    #[must_use]
    pub const fn preset(mut self, p: ConsensusPreset) -> Self {
        self.preset = p;
        self
    }

    /// Set the chain ID.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set a JMT seeding callback invoked per node directory before startup.
    #[must_use]
    pub fn jmt_seeder(mut self, f: impl Fn(&Path, u64) + Send + 'static) -> Self {
        self.jmt_seeder = Some(Box::new(f));
        self
    }

    /// Set an explicit path to the verad binary, bypassing BinaryResolver.
    #[must_use]
    pub fn binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary = Some(path.into());
        self
    }

    /// Set the node processes' log filter instead of inheriting `RUST_LOG`.
    #[must_use]
    pub fn rust_log(mut self, filter: impl Into<String>) -> Self {
        self.rust_log = Some(filter.into());
        self
    }

    /// Build and start the cluster.
    pub async fn build(self) -> eyre::Result<TestCluster> {
        let n = self.node_count;
        let chain_id = self.chain_id;

        let base_dir = PathBuf::from(
            std::env::var("VERA_E2E_DIR").unwrap_or_else(|_| "target/e2e".to_string()),
        );
        let run_dir = TestRunDir::new(&base_dir, "VERA_E2E_KEEP")?;

        let genesis_builder = self.genesis.unwrap_or_else(GenesisBuilder::devnet);

        let node_config = NodeConfigBuilder::new()
            .chain_id(chain_id)
            .preset(self.preset)
            .rpc_max_connections(self.rpc_max_connections);

        let consensus = node_config.consensus();

        let mut key_builder = KeySet::builder().nodes(n);
        if let Some(seed) = self.seed {
            key_builder = key_builder.seed(seed);
        }
        let keys = key_builder.build()?;
        let all_ports = test_infra::allocate_ports(n * 2)?;
        let p2p_ports = &all_ports[0..n];
        let rpc_ports = &all_ports[n..n * 2];
        let validators = keys
            .participants()
            .iter()
            .zip(p2p_ports)
            .map(|(public_key, port)| ValidatorConfig {
                evm_address: format!("{:?}", vera_node::validator_address(public_key)),
                consensus_pubkey: hex::encode(commonware_codec::Encode::encode(public_key)),
                p2p_address: format!("127.0.0.1:{port}"),
            })
            .collect();
        let genesis = genesis_builder
            .chain_id(chain_id)
            .validators_if_empty(validators)
            .epoch_info(keys.epoch_info_hex())
            .build();

        let node_dirs: Vec<PathBuf> = (0..n)
            .map(|i| run_dir.node_dir(&format!("node{}", i)))
            .collect::<eyre::Result<Vec<_>>>()?;

        keys.write_to(&node_dirs)?;

        let genesis_json = serde_json::to_string_pretty(&genesis)?;
        for dir in &node_dirs {
            std::fs::write(dir.join("genesis.json"), &genesis_json)?;
        }

        for (i, dir) in node_dirs.iter().enumerate() {
            let config_toml = node_config.build_config_toml(dir, p2p_ports[i], rpc_ports[i]);
            std::fs::write(dir.join("config.toml"), config_toml)?;
        }

        let peers_path = run_dir.path().join("peers.json");
        if n > 1 {
            keys.write_peers(&peers_path, p2p_ports)?;
        }

        if let Some(seeder) = &self.jmt_seeder {
            for dir in &node_dirs {
                seeder(dir, chain_id);
            }
        }

        let leader_ms = consensus.leader_timeout.as_millis().to_string();
        let notarization_ms = consensus.notarization_timeout.as_millis().to_string();
        let nullify_ms = consensus.nullify_retry.as_millis().to_string();

        let binary = match self.binary {
            Some(p) => {
                eyre::ensure!(p.exists(), "verad binary not found at {}", p.display());
                p
            }
            None => resolve_binary()?,
        };
        let rust_log = self
            .rust_log
            .unwrap_or_else(|| std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()));
        let chain_id_str = chain_id.to_string();
        let peers_str = peers_path.to_str().unwrap().to_string();

        let mut nodes = Vec::with_capacity(n);

        for i in 0..n {
            let node_dir = &node_dirs[i];
            let log_dir = node_dir.join("logs");

            let rpc_port_str = rpc_ports[i].to_string();
            let node_dir_str = node_dir.to_str().unwrap().to_string();
            let genesis_str = node_dir.join("genesis.json").to_str().unwrap().to_string();
            let config_str = node_dir.join("config.toml").to_str().unwrap().to_string();

            let args: Vec<&str> = if n == 1 {
                vec![
                    "--config",
                    &config_str,
                    "devnet",
                    "--rpc-port",
                    &rpc_port_str,
                    "--genesis",
                    &genesis_str,
                    "--data-dir",
                    &node_dir_str,
                    "--chain-id",
                    &chain_id_str,
                    "--leader-timeout-ms",
                    &leader_ms,
                    "--notarization-timeout-ms",
                    &notarization_ms,
                    "--nullify-retry-ms",
                    &nullify_ms,
                ]
            } else {
                vec![
                    "--config",
                    &config_str,
                    "--data-dir",
                    &node_dir_str,
                    "--chain-id",
                    &chain_id_str,
                    "validator",
                    "--peers",
                    &peers_str,
                    "--rpc-port",
                    &rpc_port_str,
                    "--leader-timeout-ms",
                    &leader_ms,
                    "--notarization-timeout-ms",
                    &notarization_ms,
                    "--nullify-retry-ms",
                    &nullify_ms,
                ]
            };

            let envs: Vec<(&str, &str)> = vec![("RUST_LOG", &rust_log), ("NO_COLOR", "1")];

            let process =
                ManagedProcess::spawn(&format!("node{}", i), &binary, &args, &envs, &log_dir)?;

            nodes.push(TestNode {
                rpc_port: rpc_ports[i],
                p2p_port: p2p_ports[i],
                data_dir: node_dir.clone(),
                log_dir,
                process,
            });
        }

        Ok(TestCluster {
            _run_dir: run_dir,
            nodes,
            chain_id,
        })
    }
}

/// Resolve the verad binary.
///
/// Uses `BinaryResolver` with the `VERAD` prefix. Set `VERAD_BINARY` to an
/// explicit path, `VERAD_WORKSPACE` to a vera.rs checkout, or ensure `verad`
/// is on PATH.
pub fn resolve_binary() -> eyre::Result<PathBuf> {
    let resolver = BinaryResolver::new("VERAD", "verad").cargo_package("verad");
    let resolved = resolver.resolve()?;
    Ok(resolved.path)
}
