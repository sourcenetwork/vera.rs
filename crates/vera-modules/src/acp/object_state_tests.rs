use super::*;
use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn canonical_keys_preserve_boundaries_and_native_size_bound() {
    let point = key("policy-1", "file/雪", "report/child");
    assert_eq!(
        decode_key(&point).unwrap(),
        ("policy-1".into(), "file/雪".into(), "report/child".into())
    );
    assert_eq!(
        parse_key("policy-1", &point).unwrap(),
        ("file/雪".into(), "report/child".into())
    );
    assert!(parse_key("policy", &point).is_err());
    assert!(!point.starts_with(&policy_prefix("policy")));
    assert_ne!(key("policy-1", "a/b", "c"), key("policy-1", "a", "b/c"));
    for malformed in [
        b"object_state//66/61".as_slice(),
        b"object_state/policy/6/61",
        b"object_state/policy/6A/61",
        b"object_state/policy/ff/61",
        b"object_state/policy/66/61/",
        b"object_state/policy/66",
        b"object_state/policy/66/\xff",
        b"relationship/v5/policy/66/61",
    ] {
        assert!(decode_key(malformed).is_err());
    }
    let store = InMemoryKvStore::default();
    let overhead = key("p", "r", "").len();
    let object = "x".repeat((NATIVE_MAX_KEY_BYTES - overhead) / 2);
    assert!(NATIVE_MAX_KEY_BYTES - key("p", "r", &object).len() <= 1);
    assert_eq!(read(&store, "p", "r", &object).unwrap(), 0);
    let excessive = format!("{object}x");
    assert!(
        read(&Unavailable, "p", "r", &excessive)
            .unwrap_err()
            .to_string()
            .contains("key exceeds")
    );
    assert!(decode_key(&key("p", "r", &excessive)).is_err());
    assert!(read(&store, "policy/other", "r", "o").is_err());
}

#[test]
fn absent_state_is_zero_and_advancement_is_prepared_without_mutation() {
    let mut store = InMemoryKvStore::default();
    assert_eq!(
        read(&store, "policy-1", "group", "unregistered").unwrap(),
        0
    );
    let before = store.serialize();
    let (next, change) = prepare_advance(&store, "policy-1", "group", "unregistered").unwrap();
    assert_eq!(next, 1);
    assert_eq!(store.serialize(), before);
    assert_eq!(change.1.as_deref(), Some(1u64.to_be_bytes().as_slice()));
    store.apply_records(vec![change]).unwrap();
    assert_eq!(
        read(&store, "policy-1", "group", "unregistered").unwrap(),
        1
    );
    assert_eq!(
        prepare_advance(&store, "policy-1", "group", "unregistered")
            .unwrap()
            .0,
        2
    );
    assert!(
        store
            .prefix_scan(super::super::keys::POLICY_PREFIX)
            .is_empty()
    );
    assert!(
        store
            .prefix_scan(super::super::keys::RELATIONSHIP_PREFIX)
            .is_empty()
    );
}

#[test]
fn malformed_zero_and_overflow_fail_without_preparing_or_changing_state() {
    for bytes in [
        vec![],
        vec![1],
        vec![1; 7],
        vec![1; 9],
        0u64.to_be_bytes().to_vec(),
    ] {
        let mut store = InMemoryKvStore::default();
        store.put(&key("policy", "file", "one"), bytes);
        let before = store.serialize();
        assert!(read(&store, "policy", "file", "one").is_err());
        assert!(prepare_advance(&store, "policy", "file", "one").is_err());
        assert_eq!(store.serialize(), before);
    }
    let mut store = InMemoryKvStore::default();
    store.put(
        &key("policy", "file", "one"),
        u64::MAX.to_be_bytes().to_vec(),
    );
    let before = store.serialize();
    assert_eq!(read(&store, "policy", "file", "one").unwrap(), u64::MAX);
    assert!(prepare_advance(&store, "policy", "file", "one").is_err());
    assert_eq!(store.serialize(), before);
}

struct Unavailable;
impl RecordStore for Unavailable {
    fn read_record(&self, _: &[u8]) -> Result<Option<Vec<u8>>> {
        Err(invalid("missing point proof"))
    }
    fn scan_records(&self, _: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        panic!("object state must not scan")
    }
}

#[test]
fn owner_is_stable_and_missing_nonowner_proof_is_not_initial_state() {
    let owner = Relationship::new("file", "one", "owner", acp::Subject::Wildcard);
    assert_eq!(for_relationship(&Unavailable, "policy", &owner).unwrap(), 0);
    let mut grant = owner.clone();
    grant.relation = "reader".into();
    assert!(for_relationship(&Unavailable, "policy", &grant).is_err());
    let mut store = InMemoryKvStore::default();
    store.put(&key("policy", "file", "one"), 7u64.to_be_bytes().to_vec());
    assert_eq!(for_relationship(&store, "policy", &owner).unwrap(), 0);
    assert_eq!(for_relationship(&store, "policy", &grant).unwrap(), 7);
}

struct WriteDenied(AtomicUsize);
impl RecordStore for WriteDenied {
    fn read_record(&self, _: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn scan_records(&self, _: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        panic!("object state must not scan")
    }
    fn prepare_write(&self, _: &[u8], _: Option<&[u8]>) -> Result<RecordChange> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(invalid("write budget exhausted"))
    }
}

#[test]
fn advancement_reserves_the_write_and_propagates_budget_failure() {
    let store = WriteDenied(AtomicUsize::new(0));
    let error = prepare_advance(&store, "policy", "file", "one").unwrap_err();
    assert!(error.to_string().contains("write budget exhausted"));
    assert_eq!(store.0.load(Ordering::Relaxed), 1);
}
