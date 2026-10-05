//! Module-level KV store trait and in-memory implementation.

use std::collections::{BTreeMap, HashSet};

use bytes::Bytes;
use futures::{TryStream, TryStreamExt as _};
use imbl::{OrdMap, ordmap::DiffItem};

/// Maximum record key accepted by native storage and its proof codecs.
pub const NATIVE_MAX_KEY_BYTES: usize = 64 << 10;
/// Maximum record value accepted by native storage and its proof codecs.
pub const NATIVE_MAX_VALUE_BYTES: usize = 1 << 20;

/// Key-value store abstraction for module state.
///
/// Each module holds a single `impl ModuleKvStore` instead of raw `HashMap`s.
/// `prefix_scan` returns keys in sorted order, enabling sub-prefix iteration.
pub trait ModuleKvStore: Clone + std::fmt::Debug + Default + Send + Sync {
    /// Read a value by key.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Write a key-value pair.
    fn put(&mut self, key: &[u8], value: Vec<u8>);

    /// Delete a key.
    fn delete(&mut self, key: &[u8]);

    /// Return all key-value pairs whose key starts with `prefix`, in sorted order.
    fn prefix_scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Check whether a key exists.
    fn has(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }
}

/// Ordered in-memory KV store with shared snapshots.
///
/// Tracks dirty keys modified since the last `reset_dirty()` call (or clone).
/// Writes copy the affected tree path and share unchanged values. Each clone
/// starts with an empty dirty set so only that execution's mutations are captured.
#[derive(Debug, Default)]
pub struct InMemoryKvStore {
    data: OrdMap<Vec<u8>, Bytes>,
    dirty: HashSet<Vec<u8>>,
}

impl Clone for InMemoryKvStore {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            dirty: HashSet::new(),
        }
    }
}

impl InMemoryKvStore {
    /// Borrow a value from this immutable view.
    pub fn get_ref(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.get(key).map(Bytes::as_ref)
    }

    /// Borrow ordered prefix entries without materializing the entire result.
    pub fn prefix_iter<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.data
            .range(prefix.to_vec()..)
            .take_while(move |(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.as_slice(), value.as_ref()))
    }

    /// Borrow ordered prefix entries starting strictly after a caller-provided key.
    pub fn prefix_iter_after<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&[u8]>,
    ) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let start = match after {
            Some(key) if key >= prefix => Excluded(key.to_vec()),
            _ => Included(prefix.to_vec()),
        };
        self.data
            .range((start, Unbounded))
            .take_while(move |(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.as_slice(), value.as_ref()))
    }

    /// Construct a store from raw key-value pairs (e.g. loaded from RocksDB raw_kv CF).
    pub fn from_pairs(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        Self {
            data: pairs
                .into_iter()
                .map(|(key, value)| (key, Bytes::from(value)))
                .collect(),
            dirty: HashSet::new(),
        }
    }

    /// Load owned records incrementally, without recording execution changes.
    /// Returns no store if the stream fails; duplicate keys keep the last value.
    pub async fn try_from_stream<S>(records: S) -> Result<Self, S::Error>
    where
        S: TryStream<Ok = (Vec<u8>, Bytes)>,
    {
        Ok(Self {
            data: records.try_collect().await?,
            dirty: HashSet::new(),
        })
    }

    /// Serialize the entire store contents to a Borsh byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        let entries: BTreeMap<_, _> = self
            .data
            .iter()
            .map(|(key, value)| (key, value.as_ref()))
            .collect();
        borsh::to_vec(&entries).expect("BTreeMap serialization cannot fail")
    }

    /// Reconstruct a store from Borsh-serialized bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, borsh::io::Error> {
        let data: BTreeMap<Vec<u8>, Vec<u8>> = borsh::from_slice(bytes)?;
        Ok(Self::from_pairs(data.into_iter().collect()))
    }

    /// Whether two snapshots share the same map root.
    pub fn shares_values_with(&self, other: &Self) -> bool {
        self.data.ptr_eq(&other.data)
    }

    /// Check whether the store contains any entries.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns each dirty key and its current value (`None` if deleted).
    pub fn dirty_entries(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.dirty
            .iter()
            .map(|k| {
                let val = self.data.get(k).map(|value| value.to_vec());
                (k.clone(), val)
            })
            .collect()
    }

    /// Clear the dirty set.
    pub fn reset_dirty(&mut self) {
        self.dirty.clear();
    }

    /// Whether all final record changes fit native key and value limits.
    ///
    /// Borrows changed entries without copying their keys or values. Comparing map
    /// snapshots includes changes across nested clones that reset dirty tracking.
    /// Unchanged records and removed values are not writes and are not checked.
    pub fn changes_fit_native_bounds(&self, base: &Self) -> bool {
        base.data.diff(&self.data).all(|change| match change {
            DiffItem::Add(key, value)
            | DiffItem::Update {
                new: (key, value), ..
            } => key.len() <= NATIVE_MAX_KEY_BYTES && value.len() <= NATIVE_MAX_VALUE_BYTES,
            DiffItem::Remove(key, _) => key.len() <= NATIVE_MAX_KEY_BYTES,
        })
    }

    /// Compute the diff between `self` and `base`, returning all changed/added/deleted keys.
    ///
    /// Each entry is `(key, Some(value))` for additions/updates, `(key, None)` for deletions.
    /// This captures ALL mutations regardless of clone boundaries, making it safe to use
    /// when intermediate clones reset the dirty set (e.g. the precompile clone path).
    pub fn diff_from(&self, base: &Self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        base.data
            .diff(&self.data)
            .map(|change| match change {
                DiffItem::Add(key, value)
                | DiffItem::Update {
                    new: (key, value), ..
                } => (key.clone(), Some(value.to_vec())),
                DiffItem::Remove(key, _) => (key.clone(), None),
            })
            .collect()
    }
}

impl ModuleKvStore for InMemoryKvStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_ref(key).map(<[u8]>::to_vec)
    }

    fn has(&self, key: &[u8]) -> bool {
        self.data.contains_key(key)
    }

    fn put(&mut self, key: &[u8], value: Vec<u8>) {
        self.dirty.insert(key.to_vec());
        self.data.insert(key.to_vec(), Bytes::from(value));
    }

    fn delete(&mut self, key: &[u8]) {
        self.dirty.insert(key.to_vec());
        self.data.remove(key);
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.prefix_iter(prefix)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key1", b"val1".to_vec());
        assert_eq!(store.get(b"key1").unwrap(), b"val1");
    }

    #[test]
    fn get_missing() {
        let store = InMemoryKvStore::default();
        assert!(store.get(b"missing").is_none());
    }

    #[test]
    fn delete_key() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key1", b"val1".to_vec());
        store.delete(b"key1");
        assert!(store.get(b"key1").is_none());
    }

    #[test]
    fn has_key() {
        let mut store = InMemoryKvStore::default();
        assert!(!store.has(b"key1"));
        store.put(b"key1", b"val1".to_vec());
        assert!(store.has(b"key1"));
    }

    #[test]
    fn prefix_scan_returns_sorted() {
        let mut store = InMemoryKvStore::default();
        store.put(b"acp/policy/2", b"p2".to_vec());
        store.put(b"acp/policy/1", b"p1".to_vec());
        store.put(b"acp/other/x", b"ox".to_vec());
        store.put(b"bulletin/ns/1", b"ns1".to_vec());

        let results = store.prefix_scan(b"acp/policy/");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, b"acp/policy/1");
        assert_eq!(results[1].0, b"acp/policy/2");
    }

    #[test]
    fn prefix_scan_empty() {
        let store = InMemoryKvStore::default();
        assert!(store.prefix_scan(b"any/").is_empty());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key1", b"val1".to_vec());
        store.put(b"key2", b"val2".to_vec());

        let bytes = store.serialize();
        let restored = InMemoryKvStore::deserialize(&bytes).unwrap();

        assert_eq!(restored.get(b"key1").unwrap(), b"val1");
        assert_eq!(restored.get(b"key2").unwrap(), b"val2");
    }

    #[test]
    fn serialize_empty_store() {
        let store = InMemoryKvStore::default();
        assert!(store.is_empty());
        let bytes = store.serialize();
        let restored = InMemoryKvStore::deserialize(&bytes).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn clone_isolation() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key", b"val".to_vec());
        let mut fork = store.clone();
        assert!(store.shares_values_with(&fork));
        assert!(store.diff_from(&fork).is_empty());
        fork.put(b"key", b"new".to_vec());
        assert!(!store.shares_values_with(&fork));
        assert_eq!(store.get(b"key").unwrap(), b"val");
        assert_eq!(fork.get(b"key").unwrap(), b"new");
    }

    #[test]
    fn large_forks_preserve_snapshot_and_replay_diffs() {
        let mut base = InMemoryKvStore::default();
        for key in 0_u32..2_048 {
            base.put(&key.to_be_bytes(), key.to_le_bytes().to_vec());
        }
        base.reset_dirty();
        let original = base.serialize();
        let mut fork = base.clone();
        let mut expected: BTreeMap<_, _> = base.prefix_scan(b"").into_iter().collect();
        for key in 0_u32..3_072 {
            let bytes = key.to_be_bytes();
            if key % 3 == 0 {
                fork.delete(&bytes);
                expected.remove(bytes.as_slice());
            } else {
                let value = (key + 1).to_le_bytes().to_vec();
                fork.put(&bytes, value.clone());
                expected.insert(bytes.to_vec(), value);
            }
        }
        let mut abandoned = fork.clone();
        for key in 0_u32..3_072 {
            abandoned.delete(&key.to_be_bytes());
        }
        assert!(abandoned.is_empty());
        drop(abandoned);
        assert_eq!(base.serialize(), original);
        assert!(base.dirty_entries().is_empty());
        assert_eq!(
            fork.prefix_scan(b""),
            expected.into_iter().collect::<Vec<_>>()
        );
        let mut replayed = base.clone();
        for (key, value) in fork.diff_from(&base) {
            match value {
                Some(value) => replayed.put(&key, value),
                None => replayed.delete(&key),
            }
        }
        assert_eq!(replayed.serialize(), fork.serialize());
        let restored = InMemoryKvStore::deserialize(&fork.serialize()).unwrap();
        assert!(restored.diff_from(&fork).is_empty());
    }

    #[test]
    fn dirty_tracks_puts() {
        let mut store = InMemoryKvStore::default();
        store.put(b"a", b"1".to_vec());
        store.put(b"b", b"2".to_vec());
        let dirty = store.dirty_entries();
        assert_eq!(dirty.len(), 2);
        assert!(
            dirty
                .iter()
                .any(|(k, v)| k == b"a" && v.as_deref() == Some(b"1".as_slice()))
        );
        assert!(
            dirty
                .iter()
                .any(|(k, v)| k == b"b" && v.as_deref() == Some(b"2".as_slice()))
        );
    }

    #[test]
    fn dirty_tracks_deletes() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key", b"val".to_vec());
        store.reset_dirty();
        store.delete(b"key");
        let dirty = store.dirty_entries();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0], (b"key".to_vec(), None));
    }

    #[test]
    fn clone_resets_dirty() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key", b"val".to_vec());
        assert!(!store.dirty_entries().is_empty());
        let fork = store.clone();
        assert!(fork.dirty_entries().is_empty());
        assert_eq!(fork.get(b"key").unwrap(), b"val");
    }

    #[test]
    fn reset_dirty_clears() {
        let mut store = InMemoryKvStore::default();
        store.put(b"a", b"1".to_vec());
        store.put(b"b", b"2".to_vec());
        assert_eq!(store.dirty_entries().len(), 2);
        store.reset_dirty();
        assert!(store.dirty_entries().is_empty());
        assert_eq!(store.get(b"a").unwrap(), b"1");
    }

    #[test]
    fn diff_from_captures_adds_updates_deletes() {
        let mut base = InMemoryKvStore::default();
        base.put(b"keep", b"same".to_vec());
        base.put(b"update", b"old".to_vec());
        base.put(b"delete", b"gone".to_vec());

        let mut current = base.clone();
        current.put(b"update", b"new".to_vec());
        current.delete(b"delete");
        current.put(b"add", b"fresh".to_vec());

        let diff = current.diff_from(&base);
        assert_eq!(diff.len(), 3);
        assert!(
            diff.iter()
                .any(|(k, v)| k == b"update" && v.as_deref() == Some(b"new".as_slice()))
        );
        assert!(diff.iter().any(|(k, v)| k == b"delete" && v.is_none()));
        assert!(
            diff.iter()
                .any(|(k, v)| k == b"add" && v.as_deref() == Some(b"fresh".as_slice()))
        );
    }

    #[test]
    fn from_pairs_no_dirty() {
        let store = InMemoryKvStore::from_pairs(vec![
            (b"k1".to_vec(), b"v1".to_vec()),
            (b"k2".to_vec(), b"v2".to_vec()),
        ]);
        assert!(store.dirty_entries().is_empty());
        assert_eq!(store.get(b"k1").unwrap(), b"v1");
        assert_eq!(store.get(b"k2").unwrap(), b"v2");
    }

    #[test]
    fn streamed_load_keeps_owned_values_and_stops_on_error() {
        futures::executor::block_on(async {
            let value = Bytes::from(vec![7; 4096]);
            let mut store = InMemoryKvStore::try_from_stream(futures::stream::iter([
                Ok::<_, &str>((b"shared".to_vec(), value.clone())),
                Ok((b"replace".to_vec(), Bytes::from_static(b"old"))),
                Ok((b"replace".to_vec(), Bytes::from_static(b"new"))),
            ]))
            .await
            .unwrap();
            assert_eq!(store.get_ref(b"shared").unwrap().as_ptr(), value.as_ptr());
            assert_eq!(store.get_ref(b"replace"), Some(b"new".as_slice()));
            assert!(store.dirty_entries().is_empty());
            assert_eq!(
                store.serialize(),
                InMemoryKvStore::from_pairs(vec![
                    (b"shared".to_vec(), value.to_vec()),
                    (b"replace".to_vec(), b"new".to_vec()),
                ])
                .serialize()
            );
            let snapshot = store.clone();
            store.put(b"replace", b"changed".to_vec());
            assert_eq!(snapshot.get_ref(b"replace"), Some(b"new".as_slice()));
            assert_eq!(
                store.dirty_entries(),
                vec![(b"replace".to_vec(), Some(b"changed".to_vec()))]
            );

            let mut consumed = 0;
            let records = futures::stream::iter([
                Ok((b"valid".to_vec(), value)),
                Err("damaged record"),
                Ok((b"unread".to_vec(), Bytes::new())),
            ])
            .inspect_ok(|_| consumed += 1);
            assert_eq!(
                InMemoryKvStore::try_from_stream(records).await.unwrap_err(),
                "damaged record"
            );
            assert_eq!(consumed, 1);
            assert_eq!(snapshot.get_ref(b"replace"), Some(b"new".as_slice()));
            let empty = InMemoryKvStore::try_from_stream(futures::stream::empty::<
                Result<(Vec<u8>, Bytes), &str>,
            >())
            .await
            .unwrap();
            assert!(empty.is_empty());
            assert!(empty.dirty_entries().is_empty());
        });
    }
}

#[cfg(test)]
#[path = "kv_store/limits_tests.rs"]
mod limits_tests;
