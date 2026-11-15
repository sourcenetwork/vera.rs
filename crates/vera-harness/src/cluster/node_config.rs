//! Node configuration builder for e2e test clusters.

use std::time::Duration;

/// Consensus timing parameters.
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    /// Maximum wait for a leader to propose.
    pub leader_timeout: Duration,
    /// Maximum wait for notarization of a proposal.
    pub notarization_timeout: Duration,
    /// Interval between nullify retries.
    pub nullify_retry: Duration,
}

/// Preset consensus timing configurations.
#[derive(Clone, Copy, Debug, Default)]
pub enum ConsensusPreset {
    /// Fast consensus for testing (100ms/200ms/500ms).
    #[default]
    Fast,
    /// Normal consensus timing (500ms/1s/2s).
    Normal,
    /// Stress testing timing (2s/5s/10s).
    Stress,
}

impl ConsensusPreset {
    /// Resolve the timing parameters for this preset.
    pub const fn params(self) -> ConsensusParams {
        match self {
            Self::Fast => ConsensusParams {
                leader_timeout: Duration::from_millis(100),
                notarization_timeout: Duration::from_millis(200),
                nullify_retry: Duration::from_millis(500),
            },
            Self::Normal => ConsensusParams {
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1),
                nullify_retry: Duration::from_secs(2),
            },
            Self::Stress => ConsensusParams {
                leader_timeout: Duration::from_secs(2),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(10),
            },
        }
    }
}

/// Builder for per-node configuration.
///
/// Generates TOML config files compatible with vera's `NodeConfig` format.
#[derive(Debug)]
pub struct NodeConfigBuilder {
    chain_id: u64,
    rpc_max_connections: std::num::NonZeroU32,
    preset: ConsensusPreset,
    consensus_override: Option<ConsensusParams>,
    discovery_section: bool,
}

impl Default for NodeConfigBuilder {
    fn default() -> Self {
        Self {
            chain_id: 9001,
            rpc_max_connections: std::num::NonZeroU32::new(100).unwrap(),
            preset: ConsensusPreset::Fast,
            consensus_override: None,
            discovery_section: true,
        }
    }
}

impl NodeConfigBuilder {
    /// Set the per-node RPC connection limit.
    #[must_use]
    pub const fn rpc_max_connections(mut self, limit: std::num::NonZeroU32) -> Self {
        self.rpc_max_connections = limit;
        self
    }

    /// Create a builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the chain ID written into generated configs.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set the consensus timing preset.
    #[must_use]
    pub const fn preset(mut self, preset: ConsensusPreset) -> Self {
        self.preset = preset;
        self
    }

    /// Override consensus timing with explicit parameters.
    #[must_use]
    pub const fn consensus_params(mut self, params: ConsensusParams) -> Self {
        self.consensus_override = Some(params);
        self
    }

    /// Write the `[network.discovery]` section into generated configs (default).
    ///
    /// Disable only to drive a node build that predates the setting: it rejects
    /// the section as an unknown key and always runs the local discovery values.
    #[must_use]
    pub const fn discovery_section(mut self, enabled: bool) -> Self {
        self.discovery_section = enabled;
        self
    }

    /// Resolve the effective consensus parameters (override or preset).
    pub fn consensus(&self) -> ConsensusParams {
        self.consensus_override
            .clone()
            .unwrap_or_else(|| self.preset.params())
    }

    /// Build a TOML config string for a specific node directory and ports.
    ///
    /// The nodes of a cluster share one host, so the config states the local
    /// discovery settings unless [`Self::discovery_section`] leaves them out.
    pub fn build_config_toml(
        &self,
        data_dir: &std::path::Path,
        p2p_port: u16,
        rpc_port: u16,
    ) -> String {
        let discovery = if self.discovery_section {
            vera_config::DiscoveryConfig::local()
                .toml_section()
                .expect("local discovery settings serialize")
        } else {
            String::new()
        };
        format!(
            r#"chain_id = {chain_id}
data_dir = "{data_dir}"

[network]
listen_addr = "0.0.0.0:{p2p_port}"

[rpc]
http_addr = "0.0.0.0:{rpc_port}"
ws_addr = "0.0.0.0:{rpc_port}"
max_connections = {rpc_max_connections}

{discovery}"#,
            chain_id = self.chain_id,
            data_dir = data_dir.display(),
            p2p_port = p2p_port,
            rpc_port = rpc_port,
            rpc_max_connections = self.rpc_max_connections,
        )
    }

    /// Get the configured chain ID.
    pub const fn get_chain_id(&self) -> u64 {
        self.chain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_preset_timing() {
        let params = ConsensusPreset::Fast.params();
        assert_eq!(params.leader_timeout, Duration::from_millis(100));
        assert_eq!(params.notarization_timeout, Duration::from_millis(200));
        assert_eq!(params.nullify_retry, Duration::from_millis(500));
    }

    #[test]
    fn normal_preset_timing() {
        let params = ConsensusPreset::Normal.params();
        assert_eq!(params.leader_timeout, Duration::from_millis(500));
        assert_eq!(params.notarization_timeout, Duration::from_secs(1));
        assert_eq!(params.nullify_retry, Duration::from_secs(2));
    }

    #[test]
    fn stress_preset_timing() {
        let params = ConsensusPreset::Stress.params();
        assert_eq!(params.leader_timeout, Duration::from_secs(2));
        assert_eq!(params.notarization_timeout, Duration::from_secs(5));
        assert_eq!(params.nullify_retry, Duration::from_secs(10));
    }

    #[test]
    fn override_takes_precedence() {
        let custom = ConsensusParams {
            leader_timeout: Duration::from_millis(42),
            notarization_timeout: Duration::from_millis(84),
            nullify_retry: Duration::from_millis(168),
        };
        let builder = NodeConfigBuilder::new()
            .preset(ConsensusPreset::Fast)
            .consensus_params(custom);

        let resolved = builder.consensus();
        assert_eq!(resolved.leader_timeout, Duration::from_millis(42));
    }

    #[test]
    fn a_generated_config_states_the_local_discovery_settings() {
        let toml = NodeConfigBuilder::new().build_config_toml(
            std::path::Path::new("/tmp/node0"),
            30_303,
            8_545,
        );
        let config = vera_config::NodeConfig::from_toml(&toml).unwrap();
        assert_eq!(config.network.listen_addr, "0.0.0.0:30303");
        assert_eq!(
            config.network.discovery,
            vera_config::DiscoveryConfig::local()
        );
    }

    #[test]
    fn a_config_for_an_older_node_leaves_the_discovery_section_out() {
        let toml = NodeConfigBuilder::new()
            .discovery_section(false)
            .build_config_toml(std::path::Path::new("/tmp/node0"), 30_303, 8_545);
        assert!(!toml.contains("discovery"), "{toml}");
        let config = vera_config::NodeConfig::from_toml(&toml).unwrap();
        assert_eq!(config.network.listen_addr, "0.0.0.0:30303");
        assert_eq!(config.rpc.http_addr, "0.0.0.0:8545");
    }

    #[test]
    fn default_builder_values() {
        let builder = NodeConfigBuilder::new();
        assert_eq!(builder.get_chain_id(), 9001);
    }
}
