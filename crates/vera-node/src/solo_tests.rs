use std::path::Path;

use vera_config::{NetworkConfig, NodeConfig};
use vera_modules::vera::administration::OperatorPolicy;

use super::{GENESIS_FILE, PENDING_FILE, SoloError, SoloGenesis, prepare_solo};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn config(directory: &Path) -> NodeConfig {
    NodeConfig {
        chain_id: 9_271,
        data_dir: directory.to_path_buf(),
        network: NetworkConfig {
            listen_addr: "127.0.0.1:30303".into(),
            ..NetworkConfig::default()
        },
        ..NodeConfig::default()
    }
}

fn identity() -> SoloGenesis {
    SoloGenesis {
        chain_id: 9_271,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: 1_800_000_000,
        policies: Vec::new(),
    }
}

#[test]
fn creation_publishes_the_genesis_and_leaves_nothing_pending() {
    let directory = tempfile::tempdir().unwrap();
    let (created, _) = prepare_solo(&config(directory.path()), &identity()).unwrap();

    assert!(directory.path().join(GENESIS_FILE).exists());
    assert!(!directory.path().join(PENDING_FILE).exists());
    let (reopened, _) = prepare_solo(&config(directory.path()), &identity()).unwrap();
    assert_eq!(reopened.epoch_info, created.epoch_info);
}

#[test]
fn a_start_interrupted_after_the_share_is_stored_keeps_that_share_and_its_genesis() {
    let directory = tempfile::tempdir().unwrap();
    let (created, _) = prepare_solo(&config(directory.path()), &identity()).unwrap();
    let secrets = std::fs::read(directory.path().join("secrets.json")).unwrap();
    std::fs::rename(
        directory.path().join(GENESIS_FILE),
        directory.path().join(PENDING_FILE),
    )
    .unwrap();

    let (resumed, _) = prepare_solo(&config(directory.path()), &identity()).unwrap();

    assert_eq!(resumed.epoch_info, created.epoch_info);
    assert_eq!(
        std::fs::read(directory.path().join("secrets.json")).unwrap(),
        secrets
    );
    assert!(directory.path().join(GENESIS_FILE).exists());
    assert!(!directory.path().join(PENDING_FILE).exists());
}

#[test]
fn a_start_interrupted_before_the_share_is_stored_deals_again() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(PENDING_FILE), b"{").unwrap();

    let (genesis, _) = prepare_solo(&config(directory.path()), &identity()).unwrap();

    assert!(genesis.epoch_info.is_some());
    assert!(directory.path().join(GENESIS_FILE).exists());
    assert!(!directory.path().join(PENDING_FILE).exists());
}

#[test]
fn shares_without_any_genesis_are_never_replaced() {
    let directory = tempfile::tempdir().unwrap();
    prepare_solo(&config(directory.path()), &identity()).unwrap();
    let secrets = std::fs::read(directory.path().join("secrets.json")).unwrap();
    std::fs::remove_file(directory.path().join(GENESIS_FILE)).unwrap();

    assert!(matches!(
        prepare_solo(&config(directory.path()), &identity()),
        Err(SoloError::Incomplete(
            "consensus shares exist without a genesis"
        ))
    ));
    assert_eq!(
        std::fs::read(directory.path().join("secrets.json")).unwrap(),
        secrets
    );
}

#[test]
fn a_genesis_without_its_share_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    prepare_solo(&config(directory.path()), &identity()).unwrap();
    std::fs::remove_file(directory.path().join("secrets.json")).unwrap();

    assert!(matches!(
        prepare_solo(&config(directory.path()), &identity()),
        Err(SoloError::Incomplete("consensus share is missing"))
    ));
}

#[test]
fn a_resumed_start_still_rejects_a_different_identity() {
    let directory = tempfile::tempdir().unwrap();
    prepare_solo(&config(directory.path()), &identity()).unwrap();
    std::fs::rename(
        directory.path().join(GENESIS_FILE),
        directory.path().join(PENDING_FILE),
    )
    .unwrap();
    let other = SoloGenesis {
        chain_id: 9_272,
        ..identity()
    };

    assert!(matches!(
        prepare_solo(&config(directory.path()), &other),
        Err(SoloError::Mismatch("chain identifier"))
    ));
}
