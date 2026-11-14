//! Snapshot and delta compatibility with an independent ordered-map model.

use std::collections::{BTreeMap, BTreeSet};

use vera_modules::kv_store::{InMemoryKvStore, ModuleKvStore as _};

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

fn assert_snapshot(store: &InMemoryKvStore, model: &Model) {
    assert_eq!(store.serialize(), borsh::to_vec(model).unwrap());
    assert_eq!(
        store.prefix_scan(b""),
        model
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>()
    );
}

fn assert_delta(
    store: &InMemoryKvStore,
    base: &InMemoryKvStore,
    model: &Model,
    base_model: &Model,
) {
    let keys: BTreeSet<_> = model.keys().chain(base_model.keys()).collect();
    let expected: Vec<_> = keys
        .into_iter()
        .filter(|key| model.get(*key) != base_model.get(*key))
        .map(|key| (key.clone(), model.get(key).cloned()))
        .collect();
    let mut actual = store.diff_from(base);
    actual.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(actual, expected);
}

#[test]
fn snapshots_preserve_the_existing_borsh_format() {
    let model = Model::from([
        (vec![], vec![]),
        (vec![0], vec![1, 2]),
        (vec![0, 0xff], vec![3]),
        (vec![0xff; 32], vec![4; 256]),
    ]);
    let store = InMemoryKvStore::deserialize(&borsh::to_vec(&model).unwrap()).unwrap();
    assert_snapshot(&store, &model);
}

#[test]
fn single_key_deltas_survive_shared_tree_boundaries() {
    for size in [64u32, 128, 1024] {
        let base = InMemoryKvStore::from_pairs(
            (0..size)
                .map(|key| (key.to_be_bytes().to_vec(), key.to_le_bytes().to_vec()))
                .collect(),
        );
        for key in 0..size {
            let key = key.to_be_bytes().to_vec();
            let mut fork = base.clone();
            let value = size.to_le_bytes().to_vec();
            fork.put(&key, value.clone());
            assert_eq!(fork.diff_from(&base), [(key.clone(), Some(value))]);
            fork.delete(&key);
            assert_eq!(fork.diff_from(&base), [(key, None)]);
        }
    }
}

#[test]
fn deltas_and_sibling_snapshots_match_an_independent_map() {
    let model: Model = (0..1024u32)
        .map(|i| (i.to_be_bytes().to_vec(), i.to_le_bytes().to_vec()))
        .collect();
    let store = InMemoryKvStore::from_pairs(model.clone().into_iter().collect());
    let mut branches = vec![(store, model)];
    for branch in 1..9u32 {
        let (mut store, mut model) = branches[(branch as usize - 1) / 2].clone();
        for operation in 0..64u32 {
            let key = ((branch * 113 + operation * 37) % 1280)
                .to_be_bytes()
                .to_vec();
            if operation % 3 == 0 {
                store.delete(&key);
                model.remove(&key);
            } else {
                let value = (branch * 64 + operation).to_le_bytes().to_vec();
                store.put(&key, value.clone());
                model.insert(key, value);
            }
        }
        store.put(b"transient", b"discard".to_vec());
        store.delete(b"transient");
        assert_snapshot(&store, &model);
        for (base, base_model) in &branches {
            assert_snapshot(base, base_model);
            assert_delta(&store, base, &model, base_model);
            assert_delta(base, &store, base_model, &model);
        }
        branches.push((store, model));
    }
}
