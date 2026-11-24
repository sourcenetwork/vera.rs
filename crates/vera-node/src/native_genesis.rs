use std::{fs, path::Path};

use alloy_primitives::keccak256;
use anyhow::ensure;
use commonware_codec::{Decode as _, Encode as _};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, tokio};
use vera_backend::native::{self, NativeStateSet};
use vera_domain::Block;
use vera_genesis::VeraGenesis;
use vera_modules::ModuleState;

pub(super) fn fingerprint(genesis: &VeraGenesis) -> anyhow::Result<alloy_primitives::B256> {
    let mut bytes = b"vera/native-genesis/v3\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(genesis)?);
    Ok(keccak256(bytes))
}

/// Initialize the four journals once, with a durable intent for interrupted first boots.
pub(super) async fn load_or_create(
    context: &tokio::Context,
    data_dir: &Path,
    genesis: &VeraGenesis,
    cache: &CacheRef,
) -> anyhow::Result<Block> {
    genesis.simplex.validate().map_err(anyhow::Error::msg)?;
    let fingerprint = fingerprint(genesis)?;
    let path = data_dir.join("native-genesis.bin");
    if marker_exists(&path)? {
        let record = fs::read(&path)?;
        ensure!(
            record.get(..32) == Some(fingerprint.as_slice()),
            "native genesis configuration or storage format does not match this node"
        );
        let block = Block::decode_cfg(
            commonware_codec::Copying(&record[32..]),
            &crate::node::block_cfg(),
        )?;
        ensure!(
            block.timestamp == genesis.timestamp,
            "native genesis timestamp does not match configuration"
        );
        ensure!(
            block.receipt_commitment == vera_executor::receipt_commitment(0, &[]),
            "native genesis receipt commitment is invalid"
        );
        return Ok(block);
    }
    ensure!(
        !marker_exists(&data_dir.join("history"))?,
        "genesis record missing from a node with finalized history"
    );
    fs::create_dir_all(data_dir)?;
    let intent = data_dir.join("native-genesis.intent");
    let interrupted = marker_exists(&intent)?;
    if interrupted {
        ensure!(
            fs::read(&intent)? == fingerprint.as_slice(),
            "interrupted genesis has different configuration"
        );
    }
    let native = NativeStateSet::init(
        context.child("genesis_modules"),
        native::state_config(super::node::PARTITION_PREFIX, cache.clone()),
        interrupted.then(NativeStateSet::initial_sync_targets),
    )
    .await;
    if !interrupted {
        ensure!(
            native.committed_targets().await == NativeStateSet::initial_sync_targets(),
            "existing journals have no native genesis or initialization intent"
        );
        vera_cli::write_durable(&intent, fingerprint.as_slice())?;
    }
    let mut modules = ModuleState::default();
    if let Some(policy) = &genesis.operators {
        modules.vera.initialize_administration(policy.clone())?;
    }
    modules.vera.seed_validators(genesis.registry_members()?)?;
    if !genesis.policies.is_empty() {
        // Attribution and the policy ids: nothing else checks this DID; the
        // live `ring_policy` object/`creator` relation a ring actually needs
        // is granted separately, after boot.
        let creator = vera_identity::Did::new(vera_modules::acp::GENESIS_POLICY_CREATOR)?;
        modules
            .acp
            .initialize_policies(&creator, &genesis.policies)?;
    }
    if !genesis.placed_policies.is_empty() {
        ensure!(
            genesis.policies.is_empty(),
            "genesis seeds policies under the genesis creator or under chosen owners, not both"
        );
        modules
            .acp
            .initialize_placed_policies(&genesis.placed_policies)?;
    }
    if !genesis.node_demerits.is_empty() {
        modules
            .vera
            .initialize_node_demerits(&genesis.node_demerits)?;
    }
    let sealed = native::prepare(
        native.new_batches().await,
        modules.diff_from(&ModuleState::default()),
    )
    .await?;
    let module_root = native::state_root(&sealed);
    native.apply(sealed).await;
    ensure!(
        native.finalize().await.durable().await,
        "native genesis did not become durable"
    );
    let native_targets = native.committed_targets().await;
    #[cfg(feature = "fault-injection")]
    crate::crash::point(data_dir, "native-genesis");
    let native_targets = [
        &native_targets.0,
        &native_targets.1,
        &native_targets.2,
        &native_targets.3,
    ]
    .map(|target| vera_domain::DbTarget {
        root: target.root,
        floor: *target.range.start(),
        tip: *target.range.end(),
    });
    let mut block = vera_app::genesis_block(
        module_root,
        native_targets,
        vera_executor::receipt_commitment(0, &[]),
    );
    block.timestamp = genesis.timestamp;
    // The genesis block has no parent: its parent field binds the native schema
    // and consensus parameters into the deployment identity.
    block.parent = vera_domain::BlockId(fingerprint);
    let mut record = fingerprint.to_vec();
    record.extend_from_slice(&block.encode());
    vera_cli::write_durable(&path, &record)?;
    fs::remove_file(intent)?;
    fs::File::open(data_dir)?.sync_all()?;
    Ok(block)
}

fn marker_exists(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "node/genesis_tests.rs"]
mod tests;
