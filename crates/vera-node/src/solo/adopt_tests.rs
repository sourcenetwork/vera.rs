use std::path::Path;

use vera_config::{NetworkConfig, NodeConfig};
use vera_modules::vera::administration::OperatorPolicy;

use super::{GENESIS_FILE, PENDING_FILE, adopt_solo, export_solo};
use crate::{SoloDeployment, SoloError, SoloGenesis, SoloKeys, prepare_solo};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const LISTEN: &str = "127.0.0.1:30303";

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
    SoloDeployment::create(&identity(), LISTEN.parse().unwrap()).unwrap()
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
fn an_empty_directory_receives_the_record_and_nothing_else() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = dealt();

    let (genesis, peers) = adopt_solo(&config(directory.path()), &identity(), &deployment).unwrap();

    assert_eq!(names(directory.path()), [GENESIS_FILE]);
    assert_eq!(
        std::fs::read(directory.path().join(GENESIS_FILE)).unwrap(),
        deployment.record()
    );
    assert_eq!(peers.participants, [deployment.keys().public_key()]);
    assert_eq!(genesis.chain_id, 9_271);
    assert_eq!(deployment.identity().unwrap(), identity());
}

#[test]
fn the_same_deployment_is_accepted_again_and_changes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = dealt();
    adopt_solo(&config(directory.path()), &identity(), &deployment).unwrap();
    let stored = directory.path().join(GENESIS_FILE);
    let written = std::fs::metadata(&stored).unwrap().modified().unwrap();

    adopt_solo(&config(directory.path()), &identity(), &deployment).unwrap();

    assert_eq!(names(directory.path()), [GENESIS_FILE]);
    assert_eq!(
        std::fs::metadata(&stored).unwrap().modified().unwrap(),
        written
    );
}

#[test]
fn an_interrupted_adoption_is_finished_by_the_next() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(PENDING_FILE), b"{").unwrap();

    adopt_solo(&config(directory.path()), &identity(), &dealt()).unwrap();

    assert_eq!(names(directory.path()), [GENESIS_FILE]);
}

#[test]
fn a_foreign_share_is_refused_with_nothing_written() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("node");
    let (deployment, other) = (dealt(), dealt());
    let mixed = SoloDeployment::new(
        deployment.record(),
        SoloKeys::decode(&deployment.keys().validator_key(), &other.keys().share()).unwrap(),
    );

    assert!(matches!(
        adopt_solo(&config(&directory), &identity(), &mixed),
        Err(SoloError::ShareMismatch)
    ));
    assert!(!directory.exists());
}

#[test]
fn a_foreign_validator_key_is_refused_with_nothing_written() {
    let directory = tempfile::tempdir().unwrap();
    let (deployment, other) = (dealt(), dealt());
    let mixed = SoloDeployment::new(deployment.record(), other.keys().clone());

    assert!(matches!(
        adopt_solo(&config(directory.path()), &identity(), &mixed),
        Err(SoloError::Mismatch("validator key"))
    ));
    assert!(names(directory.path()).is_empty());
}

#[test]
fn another_deployment_with_the_same_identity_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    adopt_solo(&config(directory.path()), &identity(), &dealt()).unwrap();
    let stored = std::fs::read(directory.path().join(GENESIS_FILE)).unwrap();

    assert!(matches!(
        adopt_solo(&config(directory.path()), &identity(), &dealt()),
        Err(SoloError::Mismatch("validator key"))
    ));
    assert_eq!(
        std::fs::read(directory.path().join(GENESIS_FILE)).unwrap(),
        stored
    );
}

#[test]
fn validator_state_without_a_genesis_is_not_adopted_over() {
    let directory = tempfile::tempdir().unwrap();
    prepare_solo(&config(directory.path()), &identity()).unwrap();
    std::fs::remove_file(directory.path().join(GENESIS_FILE)).unwrap();

    assert!(matches!(
        adopt_solo(&config(directory.path()), &identity(), &dealt()),
        Err(SoloError::Incomplete(
            "validator state exists without a genesis"
        ))
    ));
    assert!(!directory.path().join(GENESIS_FILE).exists());
}

#[test]
fn a_directory_that_keeps_its_keys_in_files_exports_what_another_adopts() {
    let first = tempfile::tempdir().unwrap();
    let (created, _) = prepare_solo(&config(first.path()), &identity()).unwrap();

    let exported = export_solo(first.path()).unwrap();

    let second = tempfile::tempdir().unwrap();
    let (adopted, _) = adopt_solo(&config(second.path()), &identity(), &exported).unwrap();
    assert_eq!(adopted.epoch_info, created.epoch_info);
    assert_eq!(names(second.path()), [GENESIS_FILE]);
}

#[test]
fn key_material_is_absent_from_debug_output_and_errors() {
    let deployment = dealt();
    let printed = format!("{deployment:?} {:?}", deployment.keys());

    for secret in [deployment.keys().validator_key(), deployment.keys().share()] {
        assert!(!printed.contains(&hex::encode(&secret[secret.len() - 32..])));
    }
    let malformed = SoloKeys::decode(&deployment.keys().validator_key(), &[7; 5]).unwrap_err();
    assert_eq!(
        malformed.to_string(),
        "key material: consensus share does not decode"
    );
}
