use std::{fs, io::Write as _, path::Path};

use alloy_primitives::keccak256;
use anyhow::{Context as _, ensure};
use commonware_codec::{Decode as _, Encode as _};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, tokio};
use vera_backend::{
    VeraStateSet,
    native::{self, NativeStateSet},
    state_set_config,
};
use vera_domain::Block;
use vera_genesis::VeraGenesis;
use vera_modules::ModuleState;

pub(super) fn fingerprint(genesis: &VeraGenesis) -> anyhow::Result<alloy_primitives::B256> {
    let mut bytes = b"vera/native-genesis/v2\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(genesis)?);
    Ok(keccak256(bytes))
}

/// Initialize all seven journals once, with a durable intent for interrupted first boots.
pub(super) async fn load_or_create(
    context: &tokio::Context,
    data_dir: &Path,
    genesis: &VeraGenesis,
    cache: &CacheRef,
) -> anyhow::Result<Block> {
    if let Some(parameters) = genesis.simplex {
        parameters.validate().map_err(anyhow::Error::msg)?;
    }
    let fingerprint = fingerprint(genesis)?;
    let path = data_dir.join("native-genesis.bin");
    if marker_exists(&path)? {
        let record = fs::read(&path)?;
        ensure!(
            record.get(..32) == Some(fingerprint.as_slice()),
            "native genesis configuration or storage format differs; an explicit migration is required"
        );
        let block = Block::decode_cfg(
            commonware_codec::Copying(&record[32..]),
            &crate::node::block_cfg(),
        )?;
        ensure!(
            block.native_targets.is_some(),
            "native genesis commitments missing"
        );
        ensure!(
            block.receipt_commitment == Some(vera_executor::receipt_commitment(0, &[])),
            "native genesis predates receipt commitments; an explicit migration is required"
        );
        return Ok(block);
    }
    ensure!(
        !marker_exists(&data_dir.join("genesis_block.bin"))?
            && !marker_exists(&data_dir.join("state"))?,
        "existing JMT state requires an explicit native-storage migration"
    );
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
    let execution = VeraStateSet::init(
        context.child("genesis_execution"),
        state_set_config(super::node::PARTITION_PREFIX, cache.clone()),
        interrupted.then(VeraStateSet::initial_sync_targets),
    )
    .await;
    let native = NativeStateSet::init(
        context.child("genesis_modules"),
        native::state_config(super::node::PARTITION_PREFIX, cache.clone()),
        interrupted.then(NativeStateSet::initial_sync_targets),
    )
    .await;
    if !interrupted {
        ensure!(
            execution.committed_targets().await == VeraStateSet::initial_sync_targets()
                && native.committed_targets().await == NativeStateSet::initial_sync_targets(),
            "existing journals have no native genesis or initialization intent"
        );
        persist(&intent, fingerprint.as_slice())?;
    }
    let (root, targets) = vera_app::apply_genesis(&execution, &genesis.to_genesis_state()?).await?;
    let mut modules = ModuleState::default();
    if let Some(policy) = &genesis.operators {
        modules.vera.initialize_administration(policy.clone())?;
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
    let mut block = vera_app::genesis_block(root, targets, module_root);
    if genesis.simplex.is_some() {
        // Bind consensus parameters into the network's authenticated genesis identity.
        block.prevrandao = fingerprint;
    }
    block.receipt_commitment = Some(vera_executor::receipt_commitment(0, &[]));
    block.native_targets = Some(
        [
            &native_targets.0,
            &native_targets.1,
            &native_targets.2,
            &native_targets.3,
        ]
        .map(|target| vera_domain::DbTarget {
            root: target.root,
            floor: *target.range.start(),
            tip: *target.range.end(),
        }),
    );
    let mut record = fingerprint.to_vec();
    record.extend_from_slice(&block.encode());
    persist(&path, &record)?;
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

fn persist(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    fs::File::open(path.parent().context("genesis directory missing")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "node/genesis_tests.rs"]
mod tests;
