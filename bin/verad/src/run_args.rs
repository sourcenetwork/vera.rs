//! Flags shared by the commands that run a node.

use std::time::Duration;

use vera_config::NodeConfig;
use vera_genesis::VeraGenesis;
use vera_node::{NodeSettings, PeerSet};

use crate::rpc_address::{self, RpcAddressError};

const DEFAULT_LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_NOTARIZATION_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_NULLIFY_RETRY: Duration = Duration::from_millis(500);

#[derive(clap::Args, Debug, Default)]
pub(crate) struct RunArgs {
    /// Override the configured JSON-RPC listen port. Without --config the
    /// default is 8545, plus the validator's index for `validator`.
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

impl RunArgs {
    /// Node settings listening on the configured RPC address, or on `rpc_port` when given.
    pub(crate) fn settings(
        &self,
        config: NodeConfig,
        genesis: VeraGenesis,
        peers: PeerSet,
        rpc_port: Option<u16>,
    ) -> Result<NodeSettings, RpcAddressError> {
        let secrets_path = config.data_dir.join("secrets.json");
        let rpc_addr = rpc_address::resolve(&config.rpc.http_addr, rpc_port)?;
        Ok(NodeSettings {
            config,
            genesis,
            peers,
            secrets_path,
            rpc_addr,
            leader_timeout: self
                .leader_timeout_ms
                .map_or(DEFAULT_LEADER_TIMEOUT, Duration::from_millis),
            certification_timeout: self
                .notarization_timeout_ms
                .map_or(DEFAULT_NOTARIZATION_TIMEOUT, Duration::from_millis),
            timeout_retry: self
                .nullify_retry_ms
                .map_or(DEFAULT_NULLIFY_RETRY, Duration::from_millis),
        })
    }

    /// The inherited RPC listener, when one was passed.
    pub(crate) fn listener(
        &self,
        settings: &NodeSettings,
    ) -> eyre::Result<Option<std::net::TcpListener>> {
        #[cfg(unix)]
        let listener = self
            .rpc_listener_fd
            .map(|fd| vera_cli::inherited_tcp_listener(fd, settings.rpc_addr))
            .transpose()?;
        #[cfg(not(unix))]
        let listener = {
            let _ = settings;
            None
        };
        Ok(listener)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_preserve_configured_rpc_interface_and_port_overrides() {
        for address in [
            "127.0.0.1:9000",
            "192.0.2.1:9000",
            "[::1]:9000",
            "[::]:9000",
        ] {
            let configured: std::net::SocketAddr = address.parse().unwrap();
            for override_port in [None, Some(8545), Some(0)] {
                let config = NodeConfig {
                    rpc: vera_config::RpcConfig {
                        http_addr: address.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let settings = RunArgs::default()
                    .settings(
                        config,
                        VeraGenesis::devnet(),
                        PeerSet {
                            participants: vec![],
                            bootstrappers: vec![],
                        },
                        override_port,
                    )
                    .unwrap();
                assert_eq!(settings.rpc_addr.ip(), configured.ip());
                assert_eq!(
                    settings.rpc_addr.port(),
                    override_port.unwrap_or(configured.port())
                );
            }
        }
    }

    #[test]
    fn unset_timeouts_use_the_defaults_and_flags_replace_them() {
        let settings = |args: RunArgs| {
            args.settings(
                NodeConfig::default(),
                VeraGenesis::devnet(),
                PeerSet {
                    participants: vec![],
                    bootstrappers: vec![],
                },
                None,
            )
            .unwrap()
        };
        let defaults = settings(RunArgs::default());
        assert_eq!(defaults.leader_timeout, DEFAULT_LEADER_TIMEOUT);
        assert_eq!(defaults.certification_timeout, DEFAULT_NOTARIZATION_TIMEOUT);
        assert_eq!(defaults.timeout_retry, DEFAULT_NULLIFY_RETRY);
        let explicit = settings(RunArgs {
            leader_timeout_ms: Some(10),
            notarization_timeout_ms: Some(20),
            nullify_retry_ms: Some(30),
            ..Default::default()
        });
        assert_eq!(explicit.leader_timeout, Duration::from_millis(10));
        assert_eq!(explicit.certification_timeout, Duration::from_millis(20));
        assert_eq!(explicit.timeout_retry, Duration::from_millis(30));
    }
}
