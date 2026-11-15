//! Overrides of the peer discovery profile.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Handshake attempts admitted from one source within a window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HandshakeRate {
    /// Attempts admitted per window, which is also the largest burst.
    pub count: u32,
    /// Length of the window in milliseconds.
    pub window_ms: u64,
}

impl HandshakeRate {
    /// Time after which one more attempt is admitted, absent when the rate is not usable.
    #[must_use]
    pub fn replenish_interval(&self) -> Option<Duration> {
        let interval = Duration::from_millis(self.window_ms).checked_div(self.count)?;
        (!interval.is_zero()).then_some(interval)
    }
}

/// Peer discovery settings a node states instead of taking Commonware's
/// recommended value. An absent field keeps the recommended value.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    /// Accept and dial peers on private, loopback and link-local addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_ips: Option<bool>,

    /// Shortest time between two connection reservations for one peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_cooldown_ms: Option<u64>,

    /// Handshakes in progress at once, across all sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_handshakes: Option<u32>,

    /// Handshake attempts admitted from one IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshakes_per_ip: Option<HandshakeRate>,

    /// Handshake attempts admitted from one IP subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshakes_per_subnet: Option<HandshakeRate>,

    /// Average time between two dial attempts across all peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_interval_ms: Option<u64>,

    /// Failed dials of one peer before its address is requested again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_failures_before_refresh: Option<u32>,

    /// Time between two gossip rounds about known peers. Peers accept one
    /// such message per half of their own interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_gossip_interval_ms: Option<u64>,

    /// Time a peer blocked for invalid data stays refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_duration_seconds: Option<u64>,
}

/// A discovery override no listener can run with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryConfigError {
    /// A duration or count of zero.
    #[error("network.discovery.{0} must be greater than zero")]
    Zero(&'static str),

    /// A rate without attempts, without a window, or finer than one nanosecond per attempt.
    #[error(
        "network.discovery.{0} needs a non-zero count and a window of at least one nanosecond per attempt"
    )]
    Rate(&'static str),
}

impl DiscoveryConfig {
    /// The values of Commonware's local profile, for several nodes on one host:
    /// they share an address, so the recommended per-address handshake limit and
    /// reconnect cooldown would stall them.
    #[must_use]
    pub const fn local() -> Self {
        Self {
            allow_private_ips: Some(true),
            reconnect_cooldown_ms: Some(1_000),
            max_concurrent_handshakes: Some(1_024),
            handshakes_per_ip: Some(HandshakeRate {
                count: 16,
                window_ms: 1_000,
            }),
            handshakes_per_subnet: Some(HandshakeRate {
                count: 128,
                window_ms: 1_000,
            }),
            dial_interval_ms: Some(500),
            dial_failures_before_refresh: Some(1),
            peer_gossip_interval_ms: Some(5_000),
            block_duration_seconds: Some(3_600),
        }
    }

    /// These settings, with each one left unstated taken from `fallback`.
    #[must_use]
    pub fn or(self, fallback: Self) -> Self {
        Self {
            allow_private_ips: self.allow_private_ips.or(fallback.allow_private_ips),
            reconnect_cooldown_ms: self
                .reconnect_cooldown_ms
                .or(fallback.reconnect_cooldown_ms),
            max_concurrent_handshakes: self
                .max_concurrent_handshakes
                .or(fallback.max_concurrent_handshakes),
            handshakes_per_ip: self.handshakes_per_ip.or(fallback.handshakes_per_ip),
            handshakes_per_subnet: self
                .handshakes_per_subnet
                .or(fallback.handshakes_per_subnet),
            dial_interval_ms: self.dial_interval_ms.or(fallback.dial_interval_ms),
            dial_failures_before_refresh: self
                .dial_failures_before_refresh
                .or(fallback.dial_failures_before_refresh),
            peer_gossip_interval_ms: self
                .peer_gossip_interval_ms
                .or(fallback.peer_gossip_interval_ms),
            block_duration_seconds: self
                .block_duration_seconds
                .or(fallback.block_duration_seconds),
        }
    }

    /// Whether every setting is left at the recommended value.
    #[must_use]
    pub fn is_recommended(&self) -> bool {
        *self == Self::default()
    }

    /// Reject a stated value the listener cannot run with.
    pub fn validate(&self) -> Result<(), DiscoveryConfigError> {
        for (name, value) in [
            ("reconnect_cooldown_ms", self.reconnect_cooldown_ms),
            (
                "max_concurrent_handshakes",
                self.max_concurrent_handshakes.map(u64::from),
            ),
            ("dial_interval_ms", self.dial_interval_ms),
            (
                "dial_failures_before_refresh",
                self.dial_failures_before_refresh.map(u64::from),
            ),
            ("peer_gossip_interval_ms", self.peer_gossip_interval_ms),
            ("block_duration_seconds", self.block_duration_seconds),
        ] {
            if value == Some(0) {
                return Err(DiscoveryConfigError::Zero(name));
            }
        }
        for (name, rate) in [
            ("handshakes_per_ip", self.handshakes_per_ip),
            ("handshakes_per_subnet", self.handshakes_per_subnet),
        ] {
            if rate.is_some_and(|rate| rate.count == 0 || rate.replenish_interval().is_none()) {
                return Err(DiscoveryConfigError::Rate(name));
            }
        }
        Ok(())
    }

    /// The `[network.discovery]` section of a TOML node configuration, empty
    /// when nothing is stated.
    pub fn toml_section(&self) -> Result<String, crate::ConfigError> {
        #[derive(Serialize)]
        struct Network<'a> {
            discovery: &'a DiscoveryConfig,
        }
        #[derive(Serialize)]
        struct Document<'a> {
            network: Network<'a>,
        }
        if self.is_recommended() {
            return Ok(String::new());
        }
        Ok(toml::to_string(&Document {
            network: Network { discovery: self },
        })?)
    }
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
