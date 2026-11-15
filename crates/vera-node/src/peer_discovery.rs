//! The consensus listener's discovery configuration.

use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};

use commonware_cryptography::{ChaCha20Poly1305, ed25519::PrivateKey};
use commonware_p2p::authenticated::discovery::{Bootstrapper, Config};
use commonware_runtime::Quota;
use commonware_stream::{
    SakeCups,
    cups::{self, Cups},
    sake::{self, Sake},
};
use vera_config::{DiscoveryConfig, DiscoveryConfigError, HandshakeRate};
use vera_domain::PublicKey;

use crate::{MAILBOX_SIZE, MAX_MESSAGE_SIZE, NAMESPACE, P2P_SUFFIX};

/// Handshake and discovery configuration of a validator's listener.
pub(crate) type PeerDiscovery = Config<SakeCups<PrivateKey, ChaCha20Poly1305>>;

/// Commonware's recommended profile with the settings the node states applied.
pub(crate) fn config(
    signer: PrivateKey,
    listen: SocketAddr,
    dialable: SocketAddr,
    bootstrappers: Vec<Bootstrapper<PublicKey>>,
    max_peers_per_set: NonZeroUsize,
    stated: &DiscoveryConfig,
) -> Result<PeerDiscovery, DiscoveryConfigError> {
    let mut config = Config::recommended(
        Cups::<_, ChaCha20Poly1305>::new(
            Sake {
                signer,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(10),
                version: sake::Version::V1,
            },
            cups::Version::V1,
        ),
        &[NAMESPACE, P2P_SUFFIX].concat(),
        listen,
        dialable,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
        MAILBOX_SIZE,
    );
    apply(&mut config, stated)?;
    Ok(config)
}

fn quota(name: &'static str, rate: HandshakeRate) -> Result<Quota, DiscoveryConfigError> {
    let invalid = DiscoveryConfigError::Rate(name);
    let burst = std::num::NonZeroU32::new(rate.count).ok_or(invalid)?;
    let quota = rate
        .replenish_interval()
        .and_then(Quota::with_period)
        .ok_or(invalid)?;
    Ok(quota.allow_burst(burst))
}

fn apply(config: &mut PeerDiscovery, stated: &DiscoveryConfig) -> Result<(), DiscoveryConfigError> {
    stated.validate()?;
    if let Some(allow) = stated.allow_private_ips {
        config.allow_private_ips = allow;
    }
    if let Some(cooldown) = stated.reconnect_cooldown_ms {
        config.peer_connection_cooldown = Duration::from_millis(cooldown);
    }
    if let Some(limit) = stated.max_concurrent_handshakes {
        config.max_concurrent_handshakes = std::num::NonZeroU32::new(limit)
            .ok_or(DiscoveryConfigError::Zero("max_concurrent_handshakes"))?;
    }
    if let Some(rate) = stated.handshakes_per_ip {
        config.allowed_handshake_rate_per_ip = quota("handshakes_per_ip", rate)?;
    }
    if let Some(rate) = stated.handshakes_per_subnet {
        config.allowed_handshake_rate_per_subnet = quota("handshakes_per_subnet", rate)?;
    }
    if let Some(interval) = stated.dial_interval_ms {
        config.dial_frequency = Duration::from_millis(interval);
    }
    if let Some(failures) = stated.dial_failures_before_refresh {
        config.dial_fail_limit = failures as usize;
    }
    if let Some(interval) = stated.peer_gossip_interval_ms {
        config.gossip_bit_vec_frequency = Duration::from_millis(interval);
    }
    if let Some(duration) = stated.block_duration_seconds {
        config.block_duration = Duration::from_secs(duration);
    }
    Ok(())
}

#[cfg(test)]
#[path = "peer_discovery_tests.rs"]
mod tests;
