use std::{collections::hash_map::RandomState, hash::BuildHasher};

use bytes::Bytes;
use commonware_codec::RangeCfg;
use commonware_cryptography::Sha256;
use commonware_glue::stateful::db::{
    DatabaseSet, ManagedDb, Merkleized as _, ReadGuard, Shared, Unmerkleized as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    journal::contiguous::variable,
    merkle::{full, mmr},
    qmdb::current::{VariableConfig, ordered::variable::Db},
    translator::Translator,
};
use commonware_utils::{NZU64, NZUsize, bitmap::Readable as _};
use futures::{FutureExt as _, StreamExt as _};
use vera_modules::{
    ModuleState,
    kv_store::InMemoryKvStore,
    module_state::{ModuleChanges, combine_module_roots},
};

use crate::{BackendError, Ctx};

/// Bounded peer transport for native operation-log synchronization.
pub mod p2p;

mod sync_proof;
pub use sync_proof::SyncProof;

pub use vera_permission::current::{MAX_KEY_BYTES, MAX_VALUE_BYTES};

mod record;
pub use record::record_proof_at;
mod prefix;
pub use prefix::{prefix_page_at, prefix_proof_at};
mod policy;
pub use policy::{policy_prefix_page_at, policy_prefix_proof_at};

mod permission;
pub use permission::{permission_proof, permission_proof_at};

/// Prefix bytes retained by the index; 64-byte prefixes end inside ACP policy IDs.
pub const INDEX_PREFIX_BYTES: usize = 256;

/// Ordered index prefix. Longer shared prefixes remain distinct but scan one bucket.
#[derive(Clone, Debug, Default)]
pub struct KeyPrefix(RandomState);

impl Translator for KeyPrefix {
    type Key = [u8; INDEX_PREFIX_BYTES];
    fn transform(&self, key: &[u8]) -> Self::Key {
        let mut prefix = [0; INDEX_PREFIX_BYTES];
        let len = key.len().min(prefix.len());
        prefix[..len].copy_from_slice(&key[..len]);
        prefix
    }
}

impl BuildHasher for KeyPrefix {
    type Hasher = <RandomState as BuildHasher>::Hasher;
    fn build_hasher(&self) -> Self::Hasher {
        self.0.build_hasher()
    }
}

/// One ordered module partition with current-state and operation-log commitments.
pub type NativeDbFor<E> = Db<mmr::Family, E, Vec<u8>, Bytes, Sha256, KeyPrefix, 32, Sequential>;
/// The native partition database over the production tokio context.
pub type NativeDb = NativeDbFor<Ctx>;
type Operation = <NativeDb as commonware_storage::qmdb::sync::Database>::Op;

pub(crate) fn operation_config() -> <Operation as commonware_codec::Read>::Cfg {
    (
        (RangeCfg::new(0..=MAX_KEY_BYTES), ()),
        RangeCfg::new(0..=MAX_VALUE_BYTES),
    )
}
/// ACP, bulletin, identity and native sequence partitions over any qualifying context.
pub type NativeSetFor<E> = (
    Shared<NativeDbFor<E>>,
    Shared<NativeDbFor<E>>,
    Shared<NativeDbFor<E>>,
    Shared<NativeDbFor<E>>,
);
/// ACP, bulletin, identity and native sequence partitions.
pub type NativeStateSet = (
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
);
/// Operation-log targets for the four native namespaces.
pub type NativeTargets = <NativeStateSet as DatabaseSet<Ctx>>::SyncTargets;
/// Pending native records based on one parent revision.
pub type NativeUnmerkleized = <NativeStateSet as DatabaseSet<Ctx>>::Unmerkleized;
/// Sealed native records with authenticated current-state roots.
pub type NativeMerkleized = <NativeStateSet as DatabaseSet<Ctx>>::Merkleized;
/// Configuration for the four ordered partitions.
pub type NativeConfig = <NativeStateSet as DatabaseSet<Ctx>>::Config;

#[cfg(test)]
mod fault_tests;
#[cfg(test)]
mod faulty_ctx;

/// Acquire partition readers without holding partial guards across a writer wait.
pub async fn read_partitions<T>(databases: [&Shared<T>; 4]) -> [ReadGuard<'_, T>; 4] {
    loop {
        let attempt = (|| {
            Ok::<_, usize>([
                databases[0].read().now_or_never().ok_or(0usize)?,
                databases[1].read().now_or_never().ok_or(1usize)?,
                databases[2].read().now_or_never().ok_or(2usize)?,
                databases[3].read().now_or_never().ok_or(3usize)?,
            ])
        })();
        match attempt {
            Ok(readers) => return readers,
            // All partial guards are gone. Wait only on the busy partition,
            // then retry the complete set because other partitions may have changed.
            Err(busy) => drop(databases[busy].read().await),
        }
    }
}

/// Configure independent journals for the four native namespaces.
pub fn state_config(prefix: &str, cache: CacheRef) -> NativeConfig {
    (
        config(prefix, "acp", cache.clone()),
        config(prefix, "bulletin", cache.clone()),
        config(prefix, "vera", cache.clone()),
        config(prefix, "nonces", cache),
    )
}

fn config(prefix: &str, module: &str, cache: CacheRef) -> <NativeDb as ManagedDb<Ctx>>::Config {
    let prefix = format!("{prefix}-native-{module}");
    VariableConfig {
        merkle_config: full::Config {
            journal_partition: format!("{prefix}-mmr"),
            metadata_partition: format!("{prefix}-mmr-meta"),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: variable::Config {
            partition: format!("{prefix}-log"),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: operation_config(),
            page_cache: cache,
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
        },
        grafted_metadata_partition: format!("{prefix}-graft"),
        translator: KeyPrefix::default(),
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// Stage and seal ordered logical changes without modifying committed records.
pub async fn prepare<E>(
    batches: <NativeSetFor<E> as DatabaseSet<E>>::Unmerkleized,
    changes: ModuleChanges,
) -> Result<<NativeSetFor<E> as DatabaseSet<E>>::Merkleized, BackendError>
where
    E: commonware_runtime::Spawner
        + commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::BufferPooler,
{
    for entries in &changes {
        if entries.iter().any(|(key, value)| {
            key.len() > MAX_KEY_BYTES || value.as_ref().is_some_and(|v| v.len() > MAX_VALUE_BYTES)
        }) {
            return Err(BackendError::InvalidModuleChange(
                "native record exceeds storage limits",
            ));
        }
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(BackendError::InvalidModuleChange(
                "native change keys must be unique and ordered",
            ));
        }
    }
    let [acp, bulletin, vera, nonces] = changes;
    futures::try_join!(
        seal(batches.0, acp),
        seal(batches.1, bulletin),
        seal(batches.2, vera),
        seal(batches.3, nonces)
    )
}

async fn seal<E>(
    mut batch: <NativeDbFor<E> as ManagedDb<E>>::Unmerkleized,
    entries: Vec<(Vec<u8>, Option<Vec<u8>>)>,
) -> Result<<NativeDbFor<E> as ManagedDb<E>>::Merkleized, BackendError>
where
    E: commonware_runtime::Spawner
        + commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::BufferPooler,
{
    for (key, value) in entries {
        batch = batch.write(key, value.map(Bytes::from));
    }
    batch
        .merkleize()
        .await
        .map_err(|e| BackendError::Storage(e.to_string()))
}

/// Combine current-state roots; operation-log sync targets are a separate commitment.
pub fn state_root(batches: &NativeMerkleized) -> alloy_primitives::B256 {
    combine_module_roots(&[
        batches.0.root().0,
        batches.1.root().0,
        batches.2.root().0,
        batches.3.root().0,
    ])
}

/// Rebuild module query state while the caller excludes concurrent apply/rewind operations.
pub async fn load_modules(set: &NativeStateSet) -> Result<ModuleState, BackendError> {
    let (acp, bulletin, vera, nonces) =
        futures::try_join!(load(&set.0), load(&set.1), load(&set.2), load(&set.3))?;
    let modules = ModuleState::from_stores([acp, bulletin, vera, nonces]);
    modules
        .acp
        .validate_restored_state()
        .map_err(|e| BackendError::Storage(e.to_string()))?;
    modules
        .bulletin
        .validate_storage_keys()
        .map_err(|e| BackendError::Storage(e.to_string()))?;
    modules
        .vera
        .validate_restored_tokens()
        .map_err(|e| BackendError::Storage(e.to_string()))?;
    Ok(modules)
}

async fn load(db: &Shared<NativeDb>) -> Result<InMemoryKvStore, BackendError> {
    let db = db.read().await;
    let end = db.bounds().end;
    let db = &*db;
    let records = futures::stream::try_unfold(
        (db.sync_boundary(), Vec::new().into_iter()),
        move |(mut next, mut pending)| async move {
            loop {
                if let Some(record) = pending.next() {
                    return Ok(Some((record, (next, pending))));
                }
                if next >= end {
                    return Ok(None);
                }
                // The public log reader also returns a proof; avoid materializing index buckets.
                let (_, operations) = db
                    .ops_historical_proof(end, next, NZU64!(32))
                    .await
                    .map_err(|e| BackendError::Storage(e.to_string()))?;
                let mut active = Vec::new();
                for operation in operations {
                    let live = db.bitmap().get_bit(*next);
                    next = next.saturating_add(1);
                    if !live {
                        continue;
                    }
                    match operation {
                        Operation::Update(record) => active.push((record.key, record.value)),
                        Operation::CommitFloor(_, _) => {}
                        Operation::Delete(_) => {
                            return Err(BackendError::Storage(
                                "active deletion in native operation log".into(),
                            ));
                        }
                    }
                }
                pending = active.into_iter();
            }
        },
    );
    InMemoryKvStore::try_from_stream(records.boxed()).await
}

#[cfg(test)]
mod proof_read_tests;

#[cfg(test)]
mod read_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn partial_partition_reads_never_hold_up_other_writers() {
        let databases = std::array::from_fn::<_, 4, _>(|_| Shared::new("query-test", ()));
        for blocked in 0..4 {
            let (slot, database) = databases[blocked].write().await;
            let readers = read_partitions(databases.each_ref());
            tokio::pin!(readers);
            assert!(futures::poll!(&mut readers).is_pending());
            for (index, partition) in databases.iter().enumerate() {
                if index != blocked {
                    let (other, value) =
                        tokio::time::timeout(Duration::from_secs(1), partition.write())
                            .await
                            .unwrap();
                    other.put(value);
                }
            }
            slot.put(database);
            let guards = futures::poll!(&mut readers);
            assert!(guards.is_ready(), "reader must resume without publication");
        }
    }
}
