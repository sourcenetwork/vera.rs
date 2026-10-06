use super::*;
use vera_domain::{
    ModuleId, ModuleStateProof, RelationPrefixProof, RelationProofLimits,
    verify_relation_prefix_proof,
};
use vera_modules::{kv_store::ModuleKvStore, module_state::state_root_from_jmt};
use vera_state::ModuleStateTree;

const PREFIX: &[u8] = b"relationship/v5/p//rel/document/report/blocked/";
const LIMITS: RelationProofLimits = RelationProofLimits {
    records: 32,
    bytes: 1 << 20,
};

fn fixture() -> InMemoryKvStore {
    InMemoryKvStore::from_pairs(
        [
            [PREFIX, b"alice"].concat(),
            [PREFIX, b"nested/bob"].concat(),
            [PREFIX, b"carol"].concat(),
            b"relationship/v5/p//rel/document/other/reader/dan".to_vec(),
        ]
        .into_iter()
        .map(|key| (key, br#"{"archived":false}"#.to_vec()))
        .collect(),
    )
}

fn prepare(
    tree: &ModuleStateTree,
    parent: &TreeSnapshot,
    before: &InMemoryKvStore,
    after: &InMemoryKvStore,
) -> TreeSnapshot {
    let mut entries = after.diff_from(before);
    index_relationships(parent, after, &mut entries).unwrap();
    tree.prepare(parent, entries).unwrap()
}

fn count(view: &TreeSnapshot, prefix: &[u8]) -> u64 {
    view.get(&relation_count_key(prefix))
        .unwrap()
        .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
        .unwrap_or(0)
}

fn record(tree: &ModuleStateTree, key: &[u8], height: u64) -> ModuleStateProof {
    let (value, proof, root) = tree.prove_at_height(key, height).unwrap();
    ModuleStateProof::new(
        ModuleId::Acp,
        height,
        key,
        value.as_deref(),
        &proof,
        root.0,
        [root.0; 4],
    )
}

fn witness(
    tree: &ModuleStateTree,
    store: &InMemoryKvStore,
    height: u64,
    prefix: &[u8],
) -> RelationPrefixProof {
    RelationPrefixProof {
        version: record(tree, RELATION_INDEX_VERSION_KEY, height),
        count: record(tree, &relation_count_key(prefix), height),
        records: store
            .prefix_iter(prefix)
            .map(|(key, _)| record(tree, key, height))
            .collect(),
    }
}

fn root(tree: &ModuleStateTree, height: u64) -> alloy_primitives::B256 {
    state_root_from_jmt(&[tree.root_at_height(height).unwrap().0; 4])
}

#[test]
fn activation_preserves_legacy_roots_and_counts_archived_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut tree = ModuleStateTree::open(dir.path()).unwrap();
    let before = fixture();
    let legacy = tree
        .prepare(
            &tree.snapshot().unwrap(),
            before.diff_from(&InMemoryKvStore::default()),
        )
        .unwrap();
    tree.commit_prepared(1, &legacy).unwrap();
    let old_root = root(&tree, 1);
    let mut after = before.clone();
    after.put(
        &[PREFIX, b"alice"].concat(),
        br#"{"archived":true}"#.to_vec(),
    );
    let activated = prepare(&tree, &legacy, &before, &after);
    assert_eq!(count(&activated, PREFIX), 3);
    assert_eq!(tree.get(RELATION_INDEX_VERSION_KEY).unwrap(), None);
    tree.commit_prepared(2, &activated).unwrap();
    assert_eq!(root(&tree, 1), old_root);
    assert_ne!(root(&tree, 2), old_root);
    assert_eq!(tree.load_all().unwrap(), after.prefix_scan(b""));
    assert!(
        verify_relation_prefix_proof(
            old_root,
            1,
            PREFIX,
            &witness(&tree, &before, 1, PREFIX),
            LIMITS
        )
        .is_err()
    );
    let proof = witness(&tree, &after, 2, PREFIX);
    assert_eq!(
        verify_relation_prefix_proof(root(&tree, 2), 2, PREFIX, &proof, LIMITS).unwrap(),
        after.prefix_scan(PREFIX)
    );
    let empty_prefix = b"relationship/v5/p//rel/document/absent/reader/";
    assert!(
        verify_relation_prefix_proof(
            root(&tree, 2),
            2,
            empty_prefix,
            &witness(&tree, &after, 2, empty_prefix),
            LIMITS
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn counts_follow_selected_forks_and_recover_with_their_records() {
    let dir = tempfile::tempdir().unwrap();
    let baseline;
    {
        let mut tree = ModuleStateTree::open(dir.path()).unwrap();
        let empty = InMemoryKvStore::default();
        let initial = fixture();
        let first = prepare(&tree, &tree.snapshot().unwrap(), &empty, &initial);
        tree.commit_prepared(1, &first).unwrap();
        let mut a = initial.clone();
        a.delete(&[PREFIX, b"alice"].concat());
        let mut b = initial.clone();
        b.put(&[PREFIX, b"eve"].concat(), b"value".to_vec());
        let fork_a = prepare(&tree, &first, &initial, &a);
        let fork_b = prepare(&tree, &first, &initial, &b);
        assert_eq!(count(&first, PREFIX), 3);
        assert_eq!(count(&fork_a, PREFIX), 2);
        assert_eq!(count(&fork_b, PREFIX), 4);
        let second = prepare(&tree, &fork_a, &a, &empty);
        assert_eq!(count(&second, PREFIX), 0);
        tree.commit_prepared(2, &fork_a).unwrap();
        assert!(tree.commit_prepared(2, &fork_b).is_err());
        baseline = root(&tree, 2);
        tree.commit_prepared(3, &second).unwrap();
        let older = witness(&tree, &a, 2, PREFIX);
        assert_eq!(
            verify_relation_prefix_proof(baseline, 2, PREFIX, &older, LIMITS).unwrap(),
            a.prefix_scan(PREFIX)
        );
        assert!(verify_relation_prefix_proof(root(&tree, 3), 3, PREFIX, &older, LIMITS).is_err());
        assert_eq!(tree.get(&relation_count_key(PREFIX)).unwrap(), None);
    }
    let mut tree = ModuleStateTree::open(dir.path()).unwrap();
    assert_eq!(count(&tree.snapshot().unwrap(), PREFIX), 0);
    tree.rewind_to_height(2).unwrap();
    assert_eq!(root(&tree, 2), baseline);
    assert_eq!(count(&tree.snapshot().unwrap(), PREFIX), 2);
    let recovered = InMemoryKvStore::from_pairs(tree.load_all().unwrap());
    assert_eq!(recovered.prefix_scan(PREFIX).len(), 2);
    assert_eq!(
        verify_relation_prefix_proof(
            baseline,
            2,
            PREFIX,
            &witness(&tree, &recovered, 2, PREFIX),
            LIMITS
        )
        .unwrap(),
        recovered.prefix_scan(PREFIX)
    );
}

#[test]
fn counts_match_raw_scans_after_updates_and_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let mut tree = ModuleStateTree::open(dir.path()).unwrap();
    let mut store = InMemoryKvStore::default();
    for step in 0..48u64 {
        let before = store.clone();
        let key = [PREFIX, format!("nested/{:02}", step % 7).as_bytes()].concat();
        if step % 3 == 0 {
            store.delete(&key);
        } else {
            store.put(&key, vec![step as u8]);
        }
        let next = prepare(&tree, &tree.snapshot().unwrap(), &before, &store);
        tree.commit_prepared(step + 1, &next).unwrap();
        for prefix in [
            b"relationship/v5/".as_slice(),
            PREFIX,
            [PREFIX, b"nested/"].concat().as_slice(),
        ] {
            assert_eq!(count(&next, prefix), store.prefix_scan(prefix).len() as u64);
        }
    }
}

#[test]
fn proof_verification_rejects_omissions_replacements_and_wrong_revisions() {
    let dir = tempfile::tempdir().unwrap();
    let mut tree = ModuleStateTree::open(dir.path()).unwrap();
    let store = fixture();
    let first = prepare(
        &tree,
        &tree.snapshot().unwrap(),
        &InMemoryKvStore::default(),
        &store,
    );
    tree.commit_prepared(1, &first).unwrap();
    let proof = witness(&tree, &store, 1, PREFIX);
    let verify = |p: &RelationPrefixProof| {
        verify_relation_prefix_proof(root(&tree, 1), 1, PREFIX, p, LIMITS)
    };
    assert_eq!(verify(&proof).unwrap(), store.prefix_scan(PREFIX));
    for index in 0..proof.records.len() {
        let mut omitted = proof.clone();
        omitted.records.remove(index);
        assert!(verify(&omitted).is_err());
    }
    let mut altered = proof.clone();
    altered.records[1] = altered.records[0].clone();
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.records.reverse();
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.records[0] = record(
        &tree,
        b"relationship/v5/p//rel/document/other/reader/dan",
        1,
    );
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.records[0].value = None;
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.count = record(&tree, &relation_count_key(b"relationship/v5/"), 1);
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.version = record(&tree, b"missing", 1);
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.records[0].height = 2;
    assert!(verify(&altered).is_err());
    altered = proof.clone();
    altered.records[0].module = ModuleId::Vera;
    assert!(verify(&altered).is_err());
    for limits in [
        RelationProofLimits {
            records: 2,
            ..LIMITS
        },
        RelationProofLimits { bytes: 1, ..LIMITS },
    ] {
        assert!(verify_relation_prefix_proof(root(&tree, 1), 1, PREFIX, &proof, limits).is_err());
    }
    let mut changed = store.clone();
    changed.put(&[PREFIX, b"alice"].concat(), b"changed".to_vec());
    let second = prepare(&tree, &first, &store, &changed);
    tree.commit_prepared(2, &second).unwrap();
    altered = witness(&tree, &changed, 2, PREFIX);
    altered.records[0] = proof.records[0].clone();
    altered.records[0].height = 2;
    assert!(verify_relation_prefix_proof(root(&tree, 2), 2, PREFIX, &altered, LIMITS).is_err());
}

#[test]
fn invalid_index_state_and_reserved_writes_do_not_prepare_partial_updates() {
    let dir = tempfile::tempdir().unwrap();
    let mut tree = ModuleStateTree::open(dir.path()).unwrap();
    let store = fixture();
    let first = prepare(
        &tree,
        &tree.snapshot().unwrap(),
        &InMemoryKvStore::default(),
        &store,
    );
    tree.commit_prepared(1, &first).unwrap();
    for bad in [
        vec![(RELATION_INDEX_VERSION_KEY.to_vec(), None)],
        vec![(b"same".to_vec(), None), (b"same".to_vec(), None)],
    ] {
        let mut entries = bad.clone();
        assert!(index_relationships(&first, &store, &mut entries).is_err());
        assert_eq!(entries, bad);
    }
    for bytes in [vec![1], u64::MAX.to_be_bytes().to_vec()] {
        tree.put(&relation_count_key(PREFIX), Some(bytes)).unwrap();
        let mut updated = store.clone();
        updated.put(&[PREFIX, b"added"].concat(), b"value".to_vec());
        let mut entries = updated.diff_from(&store);
        let before = entries.clone();
        assert!(index_relationships(&tree.snapshot().unwrap(), &updated, &mut entries).is_err());
        assert_eq!(entries, before);
    }
    tree.put(RELATION_INDEX_VERSION_KEY, Some(vec![1])).unwrap();
    assert!(index_relationships(&tree.snapshot().unwrap(), &store, &mut vec![]).is_err());
}
