use super::*;
use crate::{ConfigError, NodeConfig};

fn stated(field: &str) -> Result<NodeConfig, ConfigError> {
    NodeConfig::from_toml(&format!("[network.discovery]\n{field}\n"))
}

#[test]
fn an_absent_section_states_nothing_and_is_not_written() {
    let config = NodeConfig::from_toml("").unwrap();
    assert!(config.network.discovery.is_recommended());
    assert!(!config.to_toml().unwrap().contains("discovery"));
    assert!(!config.to_json().unwrap().contains("discovery"));
    assert_eq!(DiscoveryConfig::default().toml_section().unwrap(), "");
}

#[test]
fn each_setting_is_stated_alone() {
    let rate = HandshakeRate {
        count: 4,
        window_ms: 2_000,
    };
    let cases: [(&str, DiscoveryConfig); 9] = [
        (
            "allow_private_ips = true",
            DiscoveryConfig {
                allow_private_ips: Some(true),
                ..Default::default()
            },
        ),
        (
            "reconnect_cooldown_ms = 10000",
            DiscoveryConfig {
                reconnect_cooldown_ms: Some(10_000),
                ..Default::default()
            },
        ),
        (
            "max_concurrent_handshakes = 64",
            DiscoveryConfig {
                max_concurrent_handshakes: Some(64),
                ..Default::default()
            },
        ),
        (
            "handshakes_per_ip = { count = 4, window_ms = 2000 }",
            DiscoveryConfig {
                handshakes_per_ip: Some(rate),
                ..Default::default()
            },
        ),
        (
            "handshakes_per_subnet = { count = 4, window_ms = 2000 }",
            DiscoveryConfig {
                handshakes_per_subnet: Some(rate),
                ..Default::default()
            },
        ),
        (
            "dial_interval_ms = 250",
            DiscoveryConfig {
                dial_interval_ms: Some(250),
                ..Default::default()
            },
        ),
        (
            "dial_failures_before_refresh = 3",
            DiscoveryConfig {
                dial_failures_before_refresh: Some(3),
                ..Default::default()
            },
        ),
        (
            "peer_gossip_interval_ms = 20000",
            DiscoveryConfig {
                peer_gossip_interval_ms: Some(20_000),
                ..Default::default()
            },
        ),
        (
            "block_duration_seconds = 600",
            DiscoveryConfig {
                block_duration_seconds: Some(600),
                ..Default::default()
            },
        ),
    ];
    for (field, expected) in cases {
        let config = stated(field).unwrap();
        assert_eq!(config.network.discovery, expected, "{field}");
        let written = NodeConfig::from_toml(&config.to_toml().unwrap()).unwrap();
        assert_eq!(written.network.discovery, expected, "{field}");
        let json = NodeConfig::from_json(&config.to_json().unwrap()).unwrap();
        assert_eq!(json.network.discovery, expected, "{field}");
    }
}

#[test]
fn values_no_listener_can_run_with_are_rejected() {
    for field in [
        "reconnect_cooldown_ms = 0",
        "max_concurrent_handshakes = 0",
        "dial_interval_ms = 0",
        "dial_failures_before_refresh = 0",
        "peer_gossip_interval_ms = 0",
        "block_duration_seconds = 0",
        "handshakes_per_ip = { count = 0, window_ms = 1000 }",
        "handshakes_per_ip = { count = 1, window_ms = 0 }",
        "handshakes_per_subnet = { count = 0, window_ms = 1000 }",
        "handshakes_per_subnet = { count = 4000000000, window_ms = 1 }",
    ] {
        assert!(
            matches!(stated(field), Err(ConfigError::Discovery(_))),
            "{field}"
        );
    }
    let json = r#"{"network":{"discovery":{"dial_interval_ms":0}}}"#;
    assert!(matches!(
        NodeConfig::from_json(json),
        Err(ConfigError::Discovery(DiscoveryConfigError::Zero(
            "dial_interval_ms"
        )))
    ));
}

#[test]
fn unknown_and_mistyped_settings_are_rejected() {
    for field in [
        "profile = \"local\"",
        "allow_private_ips = 1",
        "reconnect_cooldown_ms = -1",
        "handshakes_per_ip = 16",
        "handshakes_per_ip = { count = 1, window_ms = 1000, burst = 2 }",
        "handshakes_per_ip = { count = 1 }",
    ] {
        assert!(
            matches!(stated(field), Err(ConfigError::TomlParse(_))),
            "{field}"
        );
    }
}

#[test]
fn the_local_set_states_every_setting_and_survives_its_toml_section() {
    let local = DiscoveryConfig::local();
    local.validate().unwrap();
    assert_eq!(local.clone().or(DiscoveryConfig::default()), local);
    assert_eq!(DiscoveryConfig::default().or(local.clone()), local);
    let section = local.toml_section().unwrap();
    assert!(section.starts_with("[network.discovery]"), "{section}");
    let config = NodeConfig::from_toml(&format!(
        "[network]\nlisten_addr = \"0.0.0.0:1\"\n\n{section}"
    ))
    .unwrap();
    assert_eq!(config.network.discovery, local);
}

#[test]
fn a_stated_setting_takes_precedence_over_a_fallback() {
    let stated = DiscoveryConfig {
        reconnect_cooldown_ms: Some(7),
        allow_private_ips: Some(false),
        ..Default::default()
    };
    let merged = stated.or(DiscoveryConfig::local());
    assert_eq!(merged.reconnect_cooldown_ms, Some(7));
    assert_eq!(merged.allow_private_ips, Some(false));
    assert_eq!(
        merged.dial_interval_ms,
        DiscoveryConfig::local().dial_interval_ms
    );
}
