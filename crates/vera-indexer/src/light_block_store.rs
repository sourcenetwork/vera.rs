//! In-memory index of the public Commonware artifacts needed by light clients.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    num::NonZeroU64,
    sync::Arc,
};

use parking_lot::RwLock;

/// Maximum number of finalizations retained in the hot proof cache.
pub const MAX_CACHED_FINALIZATIONS: usize = 1024;
/// Maximum number of cached epoch verifier records, including genesis.
pub const MAX_CACHED_EPOCHS: usize = 128;
const MAX_EPOCH_PAYLOAD_BYTES: usize = 8 << 20;

#[derive(Debug, Default)]
struct EpochCache {
    entries: BTreeMap<u64, StoredEpochMaterial>,
    payload_bytes: usize,
}

const MAX_FINALIZATION_PAYLOAD_BYTES: usize = 64 << 20;

#[derive(Debug, Default)]
struct FinalizationCache {
    entries: HashMap<[u8; 32], Arc<StoredFinalization>>,
    order: VecDeque<[u8; 32]>,
    payload_bytes: usize,
}

/// An encoded Simplex finalization and the epoch whose key verifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFinalization {
    /// Consensus epoch.
    pub epoch: u64,
    /// Canonical `Finalization<ConsensusScheme, ConsensusDigest>` bytes.
    pub bytes: Vec<u8>,
    /// Canonical Vera block bytes authenticated by this finalization.
    pub block: Vec<u8>,
}

impl StoredFinalization {
    const fn payload_capacity(&self) -> usize {
        self.bytes.capacity().saturating_add(self.block.capacity())
    }
}

/// Canonical public verifier material for one DKG epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpochMaterial {
    /// Canonical `EpochMaterial<MinSig>` bytes.
    pub bytes: Vec<u8>,
}

/// Resident proof-cache entries and encoded buffer capacity, excluding map overhead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LightBlockStats {
    /// Number of cached finalizations.
    pub finalizations: usize,
    /// Capacity of cached certificate and block buffers.
    pub finalization_bytes: usize,
    /// Number of cached epoch verifier records.
    pub epochs: usize,
    /// Capacity of cached epoch verifier buffers.
    pub epoch_bytes: usize,
}

/// In-memory index of finalizations and their epoch verifier material.
///
/// Finalizations are keyed by consensus digest (SHA-256 of the block ID),
/// while verifier material is keyed by epoch. Both artifacts are public and
/// can be reconstructed from marshal storage and finalized epoch-boundary
/// blocks after restart. Finalizations are a FIFO cache capped at 1,024 entries
/// and 64 MiB of vector capacity; callers must fall back to durable history on
/// a miss. Epoch material retains genesis and recent epochs within 128 records
/// and 8 MiB of vector capacity; older material is in finalized boundary records.
#[derive(Debug)]
pub struct LightBlockIndex {
    finalizations: RwLock<FinalizationCache>,
    epoch_material: RwLock<EpochCache>,
    epoch_length: NonZeroU64,
}

impl LightBlockIndex {
    /// Create an empty light-block artifact index.
    #[must_use]
    pub fn new(epoch_length: NonZeroU64) -> Self {
        Self {
            finalizations: RwLock::new(FinalizationCache::default()),
            epoch_material: RwLock::new(EpochCache::default()),
            epoch_length,
        }
    }

    /// Read each cache's counters without scanning entries or cloning proof payloads.
    #[must_use]
    pub fn stats(&self) -> LightBlockStats {
        let finalizations = self.finalizations.read();
        let epochs = self.epoch_material.read();
        LightBlockStats {
            finalizations: finalizations.entries.len(),
            finalization_bytes: finalizations.payload_bytes,
            epochs: epochs.entries.len(),
            epoch_bytes: epochs.payload_bytes,
        }
    }

    /// The deployment's fixed epoch length, used to locate historical verifier material.
    #[must_use]
    pub const fn epoch_length(&self) -> NonZeroU64 {
        self.epoch_length
    }

    /// Cache an encoded finalization after persisting it in durable history.
    /// Oversized payloads are not retained; older entries may be evicted.
    pub fn insert_finalization(&self, digest: [u8; 32], finalization: StoredFinalization) {
        let bytes = finalization.payload_capacity();
        if bytes > MAX_FINALIZATION_PAYLOAD_BYTES {
            return;
        }
        let mut cache = self.finalizations.write();
        if let Some(previous) = cache.entries.remove(&digest) {
            cache.payload_bytes -= previous.payload_capacity();
            cache.order.retain(|key| key != &digest);
        }
        while cache.entries.len() >= MAX_CACHED_FINALIZATIONS
            || cache.payload_bytes > MAX_FINALIZATION_PAYLOAD_BYTES - bytes
        {
            let oldest = cache.order.pop_front().expect("cache eviction order");
            let removed = cache.entries.remove(&oldest).expect("cached finalization");
            cache.payload_bytes -= removed.payload_capacity();
        }
        cache.payload_bytes += bytes;
        cache.order.push_back(digest);
        cache.entries.insert(digest, Arc::new(finalization));
    }

    /// Retrieve an encoded finalization by proposal payload digest, sharing
    /// the cached buffers instead of copying them.
    #[must_use]
    pub fn get_finalization(&self, digest: &[u8; 32]) -> Option<Arc<StoredFinalization>> {
        self.finalizations.read().entries.get(digest).cloned()
    }

    /// Store public verifier material for an epoch.
    pub fn insert_epoch_material(&self, epoch: u64, material: StoredEpochMaterial) {
        let bytes = material.bytes.capacity();
        if bytes > MAX_EPOCH_PAYLOAD_BYTES {
            return;
        }
        let mut cache = self.epoch_material.write();
        let genesis_bytes = cache
            .entries
            .get(&0)
            .map_or(0, |material| material.bytes.capacity());
        if epoch != 0 && bytes > MAX_EPOCH_PAYLOAD_BYTES - genesis_bytes {
            return;
        }
        if let Some(previous) = cache.entries.remove(&epoch) {
            cache.payload_bytes -= previous.bytes.capacity();
        }
        while cache.entries.len() >= MAX_CACHED_EPOCHS
            || cache.payload_bytes > MAX_EPOCH_PAYLOAD_BYTES - bytes
        {
            let Some(oldest) = cache.entries.range(1..).next().map(|(&epoch, _)| epoch) else {
                return;
            };
            let removed = cache
                .entries
                .remove(&oldest)
                .expect("cached epoch material");
            cache.payload_bytes -= removed.bytes.capacity();
        }
        cache.payload_bytes += bytes;
        cache.entries.insert(epoch, material);
    }

    /// Retrieve public verifier material for an epoch.
    #[must_use]
    pub fn get_epoch_material(&self, epoch: u64) -> Option<StoredEpochMaterial> {
        self.epoch_material.read().entries.get(&epoch).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_finalization() {
        let index = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
        let digest = [0xAA; 32];
        let finalization = StoredFinalization {
            epoch: 7,
            bytes: vec![0x11; 131],
            block: vec![0x33; 256],
        };

        index.insert_finalization(digest, finalization.clone());
        assert_eq!(
            index.get_finalization(&digest).as_deref(),
            Some(&finalization)
        );
    }

    #[test]
    fn finalization_cache_bounds_capacity_and_replacements() {
        let index = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
        let entry = |capacity| StoredFinalization {
            epoch: 0,
            bytes: Vec::with_capacity(capacity),
            block: vec![],
        };
        for _ in 0..MAX_CACHED_FINALIZATIONS + 1 {
            index.insert_finalization([1; 32], entry(8));
        }
        {
            let cache = index.finalizations.read();
            assert_eq!(cache.entries.len(), 1);
            assert_eq!(cache.order.len(), 1);
            assert_eq!(cache.payload_bytes, 8);
        }
        index.insert_finalization([1; 32], entry(16));
        assert_eq!(index.finalizations.read().payload_bytes, 16);
        index.insert_finalization([2; 32], entry(MAX_FINALIZATION_PAYLOAD_BYTES));
        assert!(index.get_finalization(&[1; 32]).is_none());
        assert_eq!(
            index.finalizations.read().payload_bytes,
            MAX_FINALIZATION_PAYLOAD_BYTES
        );
        index.insert_finalization([3; 32], entry(1));
        assert!(index.get_finalization(&[2; 32]).is_none());
        index.insert_finalization([4; 32], entry(MAX_FINALIZATION_PAYLOAD_BYTES + 1));
        assert!(index.get_finalization(&[4; 32]).is_none());
        assert!(index.get_finalization(&[3; 32]).is_some());
        assert_eq!(index.finalizations.read().payload_bytes, 1);
        assert_eq!(
            index.stats(),
            LightBlockStats {
                finalizations: 1,
                finalization_bytes: 1,
                ..Default::default()
            }
        );
        for number in 0..MAX_CACHED_FINALIZATIONS {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&(number as u64).to_be_bytes());
            index.insert_finalization(digest, entry(0));
        }
        let cache = index.finalizations.read();
        assert_eq!(cache.entries.len(), MAX_CACHED_FINALIZATIONS);
        assert_eq!(cache.order.len(), MAX_CACHED_FINALIZATIONS);
        assert_eq!(cache.payload_bytes, 0);
        assert!(!cache.entries.contains_key(&[3; 32]));
    }

    #[test]
    fn missing_finalization_returns_none() {
        assert!(
            LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap())
                .get_finalization(&[0xFF; 32])
                .is_none()
        );
    }

    #[test]
    fn insert_and_get_epoch_material() {
        let index = LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap());
        let material = StoredEpochMaterial {
            bytes: vec![0x22; 423],
        };

        index.insert_epoch_material(3, material.clone());
        assert_eq!(index.get_epoch_material(3), Some(material));
    }

    #[test]
    fn epoch_cache_preserves_genesis_and_bounds_payload_capacity() {
        let index = LightBlockIndex::new(NonZeroU64::new(20).unwrap());
        let material = |capacity| StoredEpochMaterial {
            bytes: Vec::with_capacity(capacity),
        };
        index.insert_epoch_material(0, material(16));
        for epoch in 1..=MAX_CACHED_EPOCHS as u64 {
            index.insert_epoch_material(epoch, material(1));
        }
        assert!(index.get_epoch_material(0).is_some());
        assert!(index.get_epoch_material(1).is_none());
        assert_eq!(index.epoch_material.read().entries.len(), MAX_CACHED_EPOCHS);
        let before = index.epoch_material.read().payload_bytes;
        index.insert_epoch_material(999, material(MAX_EPOCH_PAYLOAD_BYTES));
        assert!(index.get_epoch_material(999).is_none());
        assert_eq!(index.epoch_material.read().payload_bytes, before);
        index.insert_epoch_material(999, material(MAX_EPOCH_PAYLOAD_BYTES - 16));
        assert_eq!(
            index.epoch_material.read().payload_bytes,
            MAX_EPOCH_PAYLOAD_BYTES
        );
        assert_eq!(index.epoch_material.read().entries.len(), 2);
        index.insert_epoch_material(999, material(8));
        assert_eq!(index.epoch_material.read().payload_bytes, 24);
        assert_eq!(
            index.stats(),
            LightBlockStats {
                epochs: 2,
                epoch_bytes: 24,
                ..Default::default()
            }
        );
    }

    #[test]
    fn missing_epoch_material_returns_none() {
        assert!(
            LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap())
                .get_epoch_material(99)
                .is_none()
        );
    }
}
