use super::*;

#[test]
fn native_bounds_accept_exact_adds_and_reject_one_byte_over() {
    let base = InMemoryKvStore::default();
    for (key_bytes, value_bytes, fits) in [
        (NATIVE_MAX_KEY_BYTES, NATIVE_MAX_VALUE_BYTES, true),
        (NATIVE_MAX_KEY_BYTES + 1, NATIVE_MAX_VALUE_BYTES, false),
        (NATIVE_MAX_KEY_BYTES, NATIVE_MAX_VALUE_BYTES + 1, false),
    ] {
        let mut candidate = base.clone();
        candidate.put(&vec![1; key_bytes], vec![2; value_bytes]);
        assert_eq!(candidate.changes_fit_native_bounds(&base), fits);
    }
}

#[test]
fn native_bounds_check_updated_values_and_removed_keys() {
    let key = vec![1; NATIVE_MAX_KEY_BYTES];
    let base = InMemoryKvStore::from_pairs(vec![(key.clone(), vec![0])]);
    for (value_bytes, fits) in [
        (NATIVE_MAX_VALUE_BYTES, true),
        (NATIVE_MAX_VALUE_BYTES + 1, false),
    ] {
        let mut candidate = base.clone();
        candidate.put(&key, vec![2; value_bytes]);
        assert_eq!(candidate.changes_fit_native_bounds(&base), fits);
    }
    for (key_bytes, fits) in [
        (NATIVE_MAX_KEY_BYTES, true),
        (NATIVE_MAX_KEY_BYTES + 1, false),
    ] {
        let key = vec![3; key_bytes];
        // Deletion encodes the key, not the old value.
        let base =
            InMemoryKvStore::from_pairs(vec![(key.clone(), vec![4; NATIVE_MAX_VALUE_BYTES + 1])]);
        let mut candidate = base.clone();
        candidate.delete(&key);
        assert_eq!(candidate.changes_fit_native_bounds(&base), fits);
    }
}

#[test]
fn native_bounds_retain_changes_across_nested_clones() {
    let base = InMemoryKvStore::from_pairs(vec![(b"existing".to_vec(), vec![1])]);
    for added in [false, true] {
        let key: &[u8] = if added { b"added" } else { b"existing" };
        let mut first = base.clone();
        first.put(key, vec![2; NATIVE_MAX_VALUE_BYTES + 1]);
        let mut nested = first.clone();
        nested.put(b"other", vec![3]);
        let candidate = nested.clone();
        assert!(candidate.dirty_entries().is_empty());
        assert!(!candidate.changes_fit_native_bounds(&base));
        assert_eq!(base.get_ref(b"existing"), Some(&[1][..]));
        assert!(!base.has(b"added"));
    }
}

#[test]
fn native_bounds_ignore_unchanged_state_and_discarded_intermediate_writes() {
    let mut base = InMemoryKvStore::default();
    for id in 0u32..512 {
        base.put(&id.to_be_bytes(), id.to_le_bytes().to_vec());
    }
    // This helper checks a transition; validating retained state is separate.
    base.put(b"unchanged", vec![5; NATIVE_MAX_VALUE_BYTES + 1]);
    let mut first = base.clone();
    first.put(b"temporary", vec![6; NATIVE_MAX_VALUE_BYTES + 1]);
    let mut candidate = first.clone();
    candidate.delete(b"temporary");
    candidate.put(b"bounded", vec![7]);
    candidate.delete(&0u32.to_be_bytes());
    assert!(candidate.changes_fit_native_bounds(&base));
    assert!(base.clone().changes_fit_native_bounds(&base));
    assert_eq!(base.get_ref(&0u32.to_be_bytes()), Some(&[0; 4][..]));
    assert_eq!(
        candidate.get_ref(b"unchanged").unwrap().as_ptr(),
        base.get_ref(b"unchanged").unwrap().as_ptr(),
    );
}
