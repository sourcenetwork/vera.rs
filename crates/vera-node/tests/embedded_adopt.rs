//! Opening an existing deployment with key material the host holds.

mod support;

use std::path::Path;

use serde_json::json;
use support::{block_on, config, finalize_a_write};
use vera_client::BlsSigner;
use vera_domain::ReceiptResponse;
use vera_node::{EmbedError, EmbeddedConfig, EmbeddedNode, SoloDeployment, SoloError, SoloKeys};

fn adopt(directory: &Path, deployment: SoloDeployment) -> EmbeddedConfig {
    let shared = config(directory, 0);
    let mut config = EmbeddedConfig::adopt(directory, deployment, shared.p2p_listen).unwrap();
    config.worker_threads = shared.worker_threads;
    config.max_blocking_threads = shared.max_blocking_threads;
    config.verification_threads = shared.verification_threads;
    config
}

fn files(directory: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// Fails if the directory names a key file or any file holds a secret, raw or in hexadecimal.
fn assert_no_key_material(directory: &Path, keys: &SoloKeys) {
    assert!(!directory.join("validator.key").exists());
    assert!(!directory.join("secrets.json").exists());
    let secrets = [keys.validator_key(), keys.share()];
    // The share's encoding starts with its index; the scalar alone is searched for too.
    let scalar = &secrets[1][secrets[1].len() - 32..];
    let needles: Vec<Vec<u8>> = secrets
        .iter()
        .map(|secret| secret.as_slice())
        .chain([scalar])
        .flat_map(|secret| [secret.to_vec(), hex::encode(secret).into_bytes()])
        .collect();
    let files = files(directory);
    assert!(files.len() > 1, "the node stored nothing but its genesis");
    for file in files {
        let content = std::fs::read(&file).unwrap();
        for needle in &needles {
            assert!(
                !content
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice()),
                "{} holds key material",
                file.display()
            );
        }
    }
}

#[test]
fn a_second_directory_opens_the_exported_deployment_from_its_genesis() {
    let first = tempfile::tempdir().unwrap();
    let chain_id = 9_421;
    let original = block_on(EmbeddedNode::start(config(first.path(), chain_id))).unwrap();
    let written = finalize_a_write(&original, &BlsSigner::new(60u64.into(), chain_id).unwrap());
    let exported = original.export().unwrap();
    let genesis = original.genesis().clone();
    let consensus_key = *original.consensus_key();
    block_on(original.stop()).unwrap();
    assert_eq!(
        exported.record(),
        std::fs::read(first.path().join("solo-genesis.json")).unwrap()
    );
    assert_eq!(
        *exported.keys().validator_key(),
        std::fs::read(first.path().join("validator.key")).unwrap()
    );

    let second = tempfile::tempdir().unwrap();
    let settings = adopt(second.path(), exported.clone());
    let adopted = block_on(EmbeddedNode::start(settings.clone())).unwrap();

    assert_eq!(adopted.genesis().chain_id, chain_id);
    assert_eq!(*adopted.consensus_key(), consensus_key);
    assert_eq!(
        adopted.genesis().validators[0].consensus_pubkey,
        genesis.validators[0].consensus_pubkey
    );
    assert_eq!(
        adopted.genesis().validators[0].address,
        genesis.validators[0].address
    );
    assert_eq!(adopted.genesis().epoch_info, genesis.epoch_info);
    // No state travels with the export: the first device's write is unknown here.
    let receipt: Option<ReceiptResponse> = block_on(
        adopted
            .rpc()
            .request("vera_getReceiptProof", vec![json!(written)]),
    )
    .unwrap();
    assert!(receipt.is_none());
    finalize_a_write(&adopted, &BlsSigner::new(61u64.into(), chain_id).unwrap());
    let again = adopted.export().unwrap();
    assert_eq!(again.record(), exported.record());
    assert_eq!(*again.keys().share(), *exported.keys().share());
    block_on(adopted.stop()).unwrap();
    assert_no_key_material(second.path(), exported.keys());

    let record = std::fs::read(second.path().join("solo-genesis.json")).unwrap();
    let restarted = block_on(EmbeddedNode::start(settings)).unwrap();
    finalize_a_write(&restarted, &BlsSigner::new(62u64.into(), chain_id).unwrap());
    block_on(restarted.stop()).unwrap();
    assert_eq!(
        std::fs::read(second.path().join("solo-genesis.json")).unwrap(),
        record
    );
    assert_no_key_material(second.path(), exported.keys());
}

#[test]
fn a_deployment_dealt_in_memory_runs_without_key_files() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9_422;
    let template = config(directory.path(), chain_id);
    let dealt = SoloDeployment::create(&template.genesis, template.p2p_listen).unwrap();
    let settings = adopt(directory.path(), dealt.clone());

    for seed in [63u64, 64] {
        let node = block_on(EmbeddedNode::start(settings.clone())).unwrap();
        finalize_a_write(&node, &BlsSigner::new(seed.into(), chain_id).unwrap());
        block_on(node.stop()).unwrap();
        assert_no_key_material(directory.path(), dealt.keys());
    }
}

#[test]
fn a_share_of_another_deployment_is_refused_before_anything_is_stored() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("node");
    let template = config(&directory, 9_423);
    let dealt = SoloDeployment::create(&template.genesis, template.p2p_listen).unwrap();
    let other = SoloDeployment::create(&template.genesis, template.p2p_listen).unwrap();
    let mixed = SoloDeployment::new(
        dealt.record(),
        SoloKeys::decode(&dealt.keys().validator_key(), &other.keys().share()).unwrap(),
    );

    let refused = block_on(EmbeddedNode::start(adopt(&directory, mixed)));

    assert!(matches!(
        refused,
        Err(EmbedError::Deployment(SoloError::ShareMismatch))
    ));
    assert!(!directory.exists());
}

#[test]
fn a_directory_holding_another_deployment_is_refused_and_kept() {
    let directory = tempfile::tempdir().unwrap();
    let held = config(directory.path(), 9_424);
    let node = block_on(EmbeddedNode::start(held.clone())).unwrap();
    let exported = node.export().unwrap();
    block_on(node.stop()).unwrap();
    let before = std::fs::read(directory.path().join("solo-genesis.json")).unwrap();

    let mut elsewhere = held.genesis.clone();
    elsewhere.chain_id = 9_425;
    let other_chain = SoloDeployment::create(&elsewhere, held.p2p_listen).unwrap();
    let other_validator = SoloDeployment::create(&held.genesis, held.p2p_listen).unwrap();
    for (foreign, difference) in [
        (other_chain, "chain identifier"),
        (other_validator, "validator key"),
    ] {
        let refused = block_on(EmbeddedNode::start(adopt(directory.path(), foreign)));
        let Err(EmbedError::Deployment(SoloError::Mismatch(found))) = refused else {
            panic!("a foreign deployment was opened");
        };
        assert_eq!(found, difference);
    }
    assert_eq!(
        std::fs::read(directory.path().join("solo-genesis.json")).unwrap(),
        before
    );

    let node = block_on(EmbeddedNode::start(adopt(directory.path(), exported))).unwrap();
    block_on(node.stop()).unwrap();
}
