//! Bulletin module key prefixes and builders.
//!
//! Composite components escape percent signs and literal pipes before mapping
//! slashes to pipes. Ordinary namespace keys retain their original encoding.

use sha2::{Digest, Sha256};

fn sanitize_key_part(part: &str) -> String {
    part.replace('%', "%25")
        .replace('|', "%7C")
        .replace('/', "|")
}

/// Singleton key for the module's ACP policy ID.
pub const POLICY_ID_KEY: &[u8] = b"policy_id";
/// Post storage prefix.
pub const POST_PREFIX: &[u8] = b"post/";
/// Namespace storage prefix.
pub const NAMESPACE_PREFIX: &[u8] = b"namespace/";
/// Collaborator storage prefix.
pub const COLLABORATOR_PREFIX: &[u8] = b"collaborator/";
/// Module parameters key.
pub const PARAMS_KEY: &[u8] = b"p_bulletin";

/// Accept a short namespace name or its stored identifier.
pub fn namespace_id(namespace: &str) -> String {
    if namespace.starts_with("bulletin/") {
        namespace.to_owned()
    } else {
        format!("bulletin/{namespace}")
    }
}

/// Post key: `prefix + sanitize(namespace_id) + "/" + sanitize(post_id)`.
pub fn post_key(namespace_id: &str, post_id: &str) -> Vec<u8> {
    let mut key = Vec::from(POST_PREFIX);
    key.extend_from_slice(sanitize_key_part(namespace_id).as_bytes());
    key.push(b'/');
    key.extend_from_slice(sanitize_key_part(post_id).as_bytes());
    key
}

/// Collaborator key: `prefix + sanitize(namespace_id) + "/" + sanitize(did)`.
pub fn collaborator_key(namespace_id: &str, collaborator_did: &str) -> Vec<u8> {
    let mut key = Vec::from(COLLABORATOR_PREFIX);
    key.extend_from_slice(sanitize_key_part(namespace_id).as_bytes());
    key.push(b'/');
    key.extend_from_slice(sanitize_key_part(collaborator_did).as_bytes());
    key
}

/// Namespace key: `prefix + namespace_id`.
pub fn namespace_key(namespace_id: &str) -> Vec<u8> {
    let mut key = Vec::from(NAMESPACE_PREFIX);
    key.extend_from_slice(namespace_id.as_bytes());
    key
}

/// Collaborator iteration prefix: `prefix + sanitize(namespace_id) + "/"`.
pub fn collaborator_prefix(namespace_id: &str) -> Vec<u8> {
    let mut key = Vec::from(COLLABORATOR_PREFIX);
    key.extend_from_slice(sanitize_key_part(namespace_id).as_bytes());
    key.push(b'/');
    key
}

/// Post iteration prefix: `prefix + sanitize(namespace_id) + "/"`.
pub fn post_prefix(namespace_id: &str) -> Vec<u8> {
    let mut key = Vec::from(POST_PREFIX);
    key.extend_from_slice(sanitize_key_part(namespace_id).as_bytes());
    key.push(b'/');
    key
}

/// Deterministic post ID: `hex(SHA-256(namespace_id + payload))`.
pub fn generate_post_id(namespace_id: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace_id.as_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsanitize_key_part(part: &str) -> String {
        part.replace('|', "/")
            .replace("%7C", "|")
            .replace("%25", "%")
    }

    #[test]
    fn sanitized_parts_roundtrip() {
        for part in ["bulletin/my-ns", "abc123", "a%7Cb", "日本|語"] {
            assert_eq!(unsanitize_key_part(&sanitize_key_part(part)), part);
        }
    }

    #[test]
    fn sanitization_prevents_collision() {
        let key_a = post_key("ns/a", "post1");
        let key_b = post_key("ns", "a/post1");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn reserved_components_are_distinct_and_roundtrip() {
        let components = [
            "a/b",
            "a|b",
            "a%7Cb",
            "a%257Cb",
            "a%25b",
            "a%b",
            "日本/語|%",
        ];
        let mut posts = std::collections::HashSet::new();
        let mut collaborators = std::collections::HashSet::new();
        for namespace in components {
            for id in components {
                let post = post_key(namespace, id);
                assert!(post.starts_with(&post_prefix(namespace)));
                assert!(posts.insert(post));
                let collaborator = collaborator_key(namespace, id);
                assert!(collaborator.starts_with(&collaborator_prefix(namespace)));
                assert!(collaborators.insert(collaborator));
            }
        }
        assert_eq!(post_key("bulletin/team", "id"), b"post/bulletin|team/id");
    }

    #[test]
    fn namespace_key_format() {
        let key = namespace_key("bulletin/test");
        assert_eq!(key, b"namespace/bulletin/test");
    }

    #[test]
    fn generate_post_id_deterministic() {
        let a = generate_post_id("bulletin/ns1", b"payload");
        let b = generate_post_id("bulletin/ns1", b"payload");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn generate_post_id_changes_with_input() {
        let a = generate_post_id("bulletin/ns1", b"payload-a");
        let b = generate_post_id("bulletin/ns1", b"payload-b");
        assert_ne!(a, b);

        let c = generate_post_id("bulletin/ns1", b"payload-a");
        let d = generate_post_id("bulletin/ns2", b"payload-a");
        assert_ne!(c, d);
    }

    #[test]
    fn borsh_roundtrip_namespace() {
        use borsh::BorshDeserialize;

        use crate::bulletin::types::Namespace;
        use crate::types::Timestamp;

        let ns = Namespace {
            id: "bulletin/test".into(),
            creator: "0xABCD".into(),
            owner_did: "did:key:z6Mk".into(),
            created_at: Timestamp {
                seconds: 100,
                block_height: 10,
            },
        };
        let encoded = borsh::to_vec(&ns).unwrap();
        let decoded = Namespace::try_from_slice(&encoded).unwrap();
        assert_eq!(ns, decoded);
    }

    #[test]
    fn borsh_roundtrip_post() {
        use borsh::BorshDeserialize;

        use crate::bulletin::types::Post;

        let post = Post {
            id: "abc123".into(),
            namespace: "bulletin/ns1".into(),
            creator_did: "did:key:z6Mk".into(),
            payload: vec![1, 2, 3],
            proof: vec![4, 5, 6],
        };
        let encoded = borsh::to_vec(&post).unwrap();
        let decoded = Post::try_from_slice(&encoded).unwrap();
        assert_eq!(post, decoded);
    }

    #[test]
    fn borsh_roundtrip_bulletin_actor() {
        use borsh::BorshDeserialize;
        use vera_identity::Did;

        use crate::bulletin::types::BulletinActor;

        let actor = BulletinActor(
            Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
        );
        let encoded = borsh::to_vec(&actor).unwrap();
        let decoded = BulletinActor::try_from_slice(&encoded).unwrap();
        assert_eq!(actor, decoded);
    }
}
