use commonware_cryptography::Signer as _;
use commonware_p2p::Ingress;
use commonware_utils::NZUsize;

use super::*;

/// Every setting of a listener that is not its identity or its addresses.
#[derive(Debug, PartialEq)]
struct Profile {
    namespace: Vec<u8>,
    allow_dns: bool,
    allow_private_ips: bool,
    max_message_size: u32,
    max_peers_per_set: NonZeroUsize,
    mailbox_size: NonZeroUsize,
    send_batch_size: NonZeroUsize,
    synchrony_bound: Duration,
    handshake_timeout: Duration,
    dial_timeout: Duration,
    peer_connection_cooldown: Duration,
    max_concurrent_handshakes: std::num::NonZeroU32,
    allowed_handshake_rate_per_ip: Quota,
    allowed_handshake_rate_per_subnet: Quota,
    dial_frequency: Duration,
    dial_fail_limit: usize,
    tracked_peer_sets: NonZeroUsize,
    gossip_bit_vec_frequency: Duration,
    peer_gossip_max_count: usize,
    block_duration: Duration,
}

fn profile(config: &PeerDiscovery) -> Profile {
    Profile {
        namespace: config.namespace.clone(),
        allow_dns: config.allow_dns,
        allow_private_ips: config.allow_private_ips,
        max_message_size: config.max_message_size,
        max_peers_per_set: config.max_peers_per_set,
        mailbox_size: config.mailbox_size,
        send_batch_size: config.send_batch_size,
        synchrony_bound: config.synchrony_bound,
        handshake_timeout: config.handshake_timeout,
        dial_timeout: config.dial_timeout,
        peer_connection_cooldown: config.peer_connection_cooldown,
        max_concurrent_handshakes: config.max_concurrent_handshakes,
        allowed_handshake_rate_per_ip: config.allowed_handshake_rate_per_ip,
        allowed_handshake_rate_per_subnet: config.allowed_handshake_rate_per_subnet,
        dial_frequency: config.dial_frequency,
        dial_fail_limit: config.dial_fail_limit,
        tracked_peer_sets: config.tracked_peer_sets,
        gossip_bit_vec_frequency: config.gossip_bit_vec_frequency,
        peer_gossip_max_count: config.peer_gossip_max_count,
        block_duration: config.block_duration,
    }
}

const PEERS: NonZeroUsize = NZUsize!(12);

fn listen() -> SocketAddr {
    "127.0.0.1:30303".parse().unwrap()
}

fn handshake() -> SakeCups<PrivateKey, ChaCha20Poly1305> {
    Cups::new(
        Sake {
            signer: PrivateKey::from_seed(1),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            version: sake::Version::V1,
        },
        cups::Version::V1,
    )
}

type Preset = fn(
    SakeCups<PrivateKey, ChaCha20Poly1305>,
    &[u8],
    SocketAddr,
    Ingress,
    Vec<Bootstrapper<PublicKey>>,
    NonZeroUsize,
    u32,
    NonZeroUsize,
) -> PeerDiscovery;

fn commonware(preset: Preset) -> Profile {
    profile(&preset(
        handshake(),
        &[NAMESPACE, P2P_SUFFIX].concat(),
        listen(),
        Ingress::Socket(listen()),
        Vec::new(),
        PEERS,
        MAX_MESSAGE_SIZE,
        MAILBOX_SIZE,
    ))
}

fn stated(stated: &DiscoveryConfig) -> Result<Profile, DiscoveryConfigError> {
    config(
        PrivateKey::from_seed(1),
        listen(),
        listen(),
        Vec::new(),
        PEERS,
        stated,
    )
    .map(|config| profile(&config))
}

#[test]
fn a_node_that_states_nothing_runs_commonwares_recommended_profile() {
    assert_eq!(
        stated(&DiscoveryConfig::default()).unwrap(),
        commonware(Config::recommended)
    );
}

#[test]
fn the_local_set_reproduces_commonwares_local_profile() {
    let local = commonware(Config::local);
    assert_ne!(local, commonware(Config::recommended));
    assert_eq!(stated(&DiscoveryConfig::local()).unwrap(), local);
}

#[test]
fn each_stated_setting_changes_that_setting_alone() {
    let local = DiscoveryConfig::local();
    let recommended = || commonware(Config::recommended);
    let reference = commonware(Config::local);
    let cases: [(DiscoveryConfig, Profile); 9] = [
        (
            DiscoveryConfig {
                allow_private_ips: local.allow_private_ips,
                ..Default::default()
            },
            Profile {
                allow_private_ips: reference.allow_private_ips,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                reconnect_cooldown_ms: local.reconnect_cooldown_ms,
                ..Default::default()
            },
            Profile {
                peer_connection_cooldown: reference.peer_connection_cooldown,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                max_concurrent_handshakes: local.max_concurrent_handshakes,
                ..Default::default()
            },
            Profile {
                max_concurrent_handshakes: reference.max_concurrent_handshakes,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                handshakes_per_ip: local.handshakes_per_ip,
                ..Default::default()
            },
            Profile {
                allowed_handshake_rate_per_ip: reference.allowed_handshake_rate_per_ip,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                handshakes_per_subnet: local.handshakes_per_subnet,
                ..Default::default()
            },
            Profile {
                allowed_handshake_rate_per_subnet: reference.allowed_handshake_rate_per_subnet,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                dial_interval_ms: local.dial_interval_ms,
                ..Default::default()
            },
            Profile {
                dial_frequency: reference.dial_frequency,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                dial_failures_before_refresh: local.dial_failures_before_refresh,
                ..Default::default()
            },
            Profile {
                dial_fail_limit: reference.dial_fail_limit,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                peer_gossip_interval_ms: local.peer_gossip_interval_ms,
                ..Default::default()
            },
            Profile {
                gossip_bit_vec_frequency: reference.gossip_bit_vec_frequency,
                ..recommended()
            },
        ),
        (
            DiscoveryConfig {
                block_duration_seconds: local.block_duration_seconds,
                ..Default::default()
            },
            Profile {
                block_duration: reference.block_duration,
                ..recommended()
            },
        ),
    ];
    for (setting, expected) in cases {
        assert_ne!(expected, recommended(), "{setting:?}");
        assert_eq!(stated(&setting).unwrap(), expected, "{setting:?}");
    }
}

#[test]
fn a_stated_recommended_value_equals_leaving_it_out() {
    let explicit = DiscoveryConfig {
        allow_private_ips: Some(false),
        reconnect_cooldown_ms: Some(60_000),
        max_concurrent_handshakes: Some(512),
        handshakes_per_ip: Some(HandshakeRate {
            count: 1,
            window_ms: 5_000,
        }),
        handshakes_per_subnet: Some(HandshakeRate {
            count: 64,
            window_ms: 1_000,
        }),
        dial_interval_ms: Some(1_000),
        dial_failures_before_refresh: Some(2),
        peer_gossip_interval_ms: Some(50_000),
        block_duration_seconds: Some(14_400),
    };
    assert_eq!(stated(&explicit).unwrap(), commonware(Config::recommended));
}

#[test]
fn an_unusable_setting_builds_no_listener() {
    for setting in [
        DiscoveryConfig {
            reconnect_cooldown_ms: Some(0),
            ..Default::default()
        },
        DiscoveryConfig {
            max_concurrent_handshakes: Some(0),
            ..Default::default()
        },
        DiscoveryConfig {
            handshakes_per_ip: Some(HandshakeRate {
                count: 0,
                window_ms: 1_000,
            }),
            ..Default::default()
        },
        DiscoveryConfig {
            handshakes_per_subnet: Some(HandshakeRate {
                count: u32::MAX,
                window_ms: 1,
            }),
            ..Default::default()
        },
    ] {
        assert!(stated(&setting).is_err(), "{setting:?}");
    }
}
