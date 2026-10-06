//! Authenticated cardinalities for complete ACP relationship enumeration.

use sha2::{Digest, Sha256};

/// Authenticated format marker, excluded from module record loading.
pub const RELATION_INDEX_VERSION_KEY: &[u8] = b"\0vera/relationship_index/version";
/// Index format activated by deterministic execution, for the current relationship namespace.
pub const RELATION_INDEX_VERSION: &[u8] = &[4];
const COUNT_NAMESPACE: &[u8] = b"\0vera/relationship_index/count/";
const RELATIONSHIP_PREFIX: &[u8] = b"relationship/v5/";

/// Whether this prefix has an authenticated count in format 4.
pub fn is_relation_prefix(prefix: &[u8]) -> bool {
    prefix.starts_with(RELATIONSHIP_PREFIX) && prefix.ends_with(b"/")
}

/// Count key for an exact raw relationship prefix.
pub fn relation_count_key(prefix: &[u8]) -> Vec<u8> {
    [COUNT_NAMESPACE, Sha256::digest(prefix).as_slice()].concat()
}

/// Every supported prefix containing this record.
///
/// Counting delimiter ancestors also covers malformed keys with extra separators;
/// interpreting fields here could omit records that a raw prefix scan returns.
pub fn relation_prefixes(key: &[u8]) -> impl Iterator<Item = &[u8]> {
    key.iter().enumerate().filter_map(move |(index, byte)| {
        let prefix = &key[..=index];
        (*byte == b'/' && is_relation_prefix(prefix)).then_some(prefix)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cardinalities_cover_incarnation_prefixes_only_in_the_current_namespace() {
        assert_eq!(RELATION_INDEX_VERSION, &[4]);
        let key = b"relationship/v5/policy/0000000000000001/0000000000000000/v3/66/61/000000000000000a/72/hash";
        let prefixes: Vec<_> = relation_prefixes(key).collect();
        assert!(prefixes.contains(&b"relationship/v5/policy/0000000000000001/0000000000000000/v3/66/61/000000000000000a/".as_slice()));
        assert!(prefixes.iter().all(|prefix| is_relation_prefix(prefix)));
        for legacy in [
            b"relationship/v3/policy/".as_slice(),
            b"relationship/v4/policy/",
        ] {
            assert!(!is_relation_prefix(legacy));
            assert_eq!(relation_prefixes(legacy).count(), 0);
        }
        assert_ne!(
            relation_count_key(b"relationship/v5/policy/pair/v3/66/61/0000000000000000/"),
            relation_count_key(b"relationship/v5/policy/pair/v3/66/61/0000000000000001/")
        );
    }
}
