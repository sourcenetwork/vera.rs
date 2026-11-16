use std::path::Path;

use vera_config::{NetworkConfig, NodeConfig};
use vera_modules::vera::administration::OperatorPolicy;

use super::follow_solo;
use crate::{DeviceKey, SoloDeployment, SoloError, SoloGenesis, prepare_solo};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const LISTEN: &str = "127.0.0.1:30303";
const ACTIVE: &str = "127.0.0.1:30304";

fn config(directory: &Path) -> NodeConfig {
    NodeConfig {
        chain_id: 9_271,
        data_dir: directory.to_path_buf(),
        network: NetworkConfig {
            listen_addr: LISTEN.into(),
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

fn dealt() -> SoloDeployment {
    SoloDeployment::create(&identity(), ACTIVE.parse().unwrap()).unwrap()
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_backup_stores_the_record_and_dials_the_validator_at_the_active_address() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = dealt();

    let (genesis, peers) = follow_solo(
        &config(directory.path()),
        &identity(),
        deployment.record(),
        ACTIVE.parse().unwrap(),
    )
    .unwrap();

    assert_eq!(names(directory.path()), ["solo-genesis.json"]);
    assert_eq!(genesis.chain_id, 9_271);
    let validator = deployment.keys().public_key();
    assert_eq!(peers.participants, std::slice::from_ref(&validator));
    assert_eq!(peers.bootstrappers, [(validator, ACTIVE.parse().unwrap())]);
}

#[test]
fn a_directory_that_keeps_a_validators_key_material_is_not_a_backup() {
    let directory = tempfile::tempdir().unwrap();
    prepare_solo(&config(directory.path()), &identity()).unwrap();
    let record = std::fs::read(directory.path().join("solo-genesis.json")).unwrap();

    assert!(matches!(
        follow_solo(
            &config(directory.path()),
            &identity(),
            &record,
            ACTIVE.parse().unwrap()
        ),
        Err(SoloError::Mismatch(
            "the directory keeps a validator's key material"
        ))
    ));
}

#[test]
fn another_deployment_is_refused_in_a_backups_directory() {
    let directory = tempfile::tempdir().unwrap();
    let active = ACTIVE.parse().unwrap();
    follow_solo(
        &config(directory.path()),
        &identity(),
        dealt().record(),
        active,
    )
    .unwrap();

    assert!(matches!(
        follow_solo(
            &config(directory.path()),
            &identity(),
            dealt().record(),
            active
        ),
        Err(SoloError::Mismatch("validator key"))
    ));
}

#[test]
fn a_transport_key_is_created_once_and_read_back() {
    let directory = tempfile::tempdir().unwrap();

    let created = DeviceKey::load_or_create(directory.path()).unwrap();
    let reopened = DeviceKey::load_or_create(directory.path()).unwrap();

    assert_eq!(names(directory.path()), ["transport.key"]);
    assert_eq!(created.public_key(), reopened.public_key());
    assert_eq!(
        DeviceKey::decode(&created.encode()).unwrap().public_key(),
        created.public_key()
    );
    assert!(!format!("{created:?}").contains(&hex::encode(&created.encode()[..])));
    follow_solo(
        &config(directory.path()),
        &identity(),
        dealt().record(),
        ACTIVE.parse().unwrap(),
    )
    .unwrap();
}
