//! Node settings and the peer set file.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use commonware_codec::ReadExt as _;
use commonware_cryptography::ed25519;
use thiserror::Error;
use vera_config::NodeConfig;
use vera_domain::PublicKey;
use vera_genesis::VeraGenesis;

/// Errors reading `peers.json`.
#[derive(Debug, Error)]
pub enum PeerSetError {
    /// The file could not be read.
    #[error("read peers file: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not the expected JSON shape.
    #[error("parse peers file: {0}")]
    Json(#[from] serde_json::Error),
    /// A field is missing or malformed.
    #[error("invalid peers file: {0}")]
    Invalid(String),
}

/// Validators and their dial addresses.
#[derive(Clone, Debug)]
pub struct PeerSet {
    /// Ordered participant public keys.
    pub participants: Vec<PublicKey>,
    /// Dial address per participant that accepts inbound connections.
    pub bootstrappers: Vec<(PublicKey, SocketAddr)>,
}

/// Load `peers.json` as written by the e2e harness and `verad testnet`.
pub fn load_peers(path: &Path) -> Result<PeerSet, PeerSetError> {
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let parse_key = |hex_key: &str| -> Result<PublicKey, PeerSetError> {
        let bytes = hex::decode(hex_key).map_err(|e| PeerSetError::Invalid(e.to_string()))?;
        ed25519::PublicKey::read(&mut commonware_codec::Copying(bytes.as_slice()))
            .map_err(|e| PeerSetError::Invalid(format!("public key: {e}")))
    };
    let participants = json["participants"]
        .as_array()
        .ok_or_else(|| PeerSetError::Invalid("missing participants".into()))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| PeerSetError::Invalid("participant is not a string".into()))
                .and_then(parse_key)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = std::collections::HashSet::new();
    if let Some(duplicate) = participants.iter().find(|key| !seen.insert(*key)) {
        return Err(PeerSetError::Invalid(format!(
            "duplicate participant {duplicate}"
        )));
    }
    let mut bootstrappers = Vec::new();
    for (hex_key, addr) in json["bootstrappers"]
        .as_object()
        .ok_or_else(|| PeerSetError::Invalid("missing bootstrappers".into()))?
    {
        let addr = addr
            .as_str()
            .ok_or_else(|| PeerSetError::Invalid("bootstrapper address".into()))?
            .parse::<SocketAddr>()
            .map_err(|e| PeerSetError::Invalid(format!("bootstrapper address: {e}")))?;
        bootstrappers.push((parse_key(hex_key)?, addr));
    }
    Ok(PeerSet {
        participants,
        bootstrappers,
    })
}

/// Everything `run_node` needs beyond the node config file.
#[derive(Clone, Debug)]
pub struct NodeSettings {
    /// Node config (chain id, data dir, network, rpc).
    pub config: NodeConfig,
    /// Chain genesis.
    pub genesis: VeraGenesis,
    /// Validators and bootstrappers.
    pub peers: PeerSet,
    /// Where the DKG share and dealings live.
    pub secrets_path: PathBuf,
    /// JSON-RPC listen address.
    pub rpc_addr: SocketAddr,
    /// Leader proposal timeout.
    pub leader_timeout: Duration,
    /// Certification (notarization) timeout.
    pub certification_timeout: Duration,
    /// Retry interval for timed-out rounds.
    pub timeout_retry: Duration,
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
