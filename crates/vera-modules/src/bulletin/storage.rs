use super::{
    BulletinModule, Result,
    error::BulletinError,
    keys,
    types::{Collaborator, Namespace, Post},
};

fn decode<T: borsh::BorshDeserialize>(bytes: &[u8]) -> Result<T> {
    borsh::from_slice(bytes)
        .map_err(|e| BulletinError::State(format!("invalid bulletin record: {e}")))
}

impl BulletinModule {
    pub(super) fn get_record<T: borsh::BorshDeserialize>(
        &self,
        key: &[u8],
        record_key: impl FnOnce(&T) -> Vec<u8>,
    ) -> Result<Option<T>> {
        let Some(bytes) = self.store.get_ref(key) else {
            return Ok(None);
        };
        let record = decode(bytes)?;
        if record_key(&record) != key {
            return Err(BulletinError::State(
                "bulletin key does not match its record".into(),
            ));
        }
        Ok(Some(record))
    }

    /// Reject malformed records and legacy keys before publishing restored native state.
    pub fn validate_storage_keys(&self) -> Result<()> {
        for prefix in [
            keys::NAMESPACE_PREFIX,
            keys::POST_PREFIX,
            keys::COLLABORATOR_PREFIX,
        ] {
            for (key, value) in self.store.prefix_iter(prefix) {
                let expected = if prefix == keys::POST_PREFIX {
                    let post: Post = decode(value)?;
                    keys::post_key(&post.namespace, &post.id)
                } else if prefix == keys::COLLABORATOR_PREFIX {
                    let collaborator: Collaborator = decode(value)?;
                    keys::collaborator_key(&collaborator.namespace, &collaborator.did)
                } else {
                    let namespace: Namespace = decode(value)?;
                    keys::namespace_key(&namespace.id)
                };
                if key != expected {
                    return Err(BulletinError::State(
                        "bulletin key does not match its record".into(),
                    ));
                }
            }
        }
        self.get_policy_id()?;
        self.get_params()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletin::types::BulletinParams;
    use crate::kv_store::ModuleKvStore;
    use crate::{kv_store::InMemoryKvStore, types::Timestamp};

    #[test]
    fn point_reads_reject_corruption_and_wrong_identity_without_changing_state() {
        let namespace = Namespace {
            id: "bulletin/other".into(),
            creator: "signer".into(),
            owner_did: "owner".into(),
            created_at: Timestamp {
                seconds: 1,
                block_height: 1,
            },
        };
        let post = Post {
            id: "other".into(),
            namespace: "bulletin/ns".into(),
            creator_did: "owner".into(),
            payload: vec![1],
            proof: vec![],
        };
        let collaborator = Collaborator {
            did: "other".into(),
            namespace: "bulletin/ns".into(),
        };
        for malformed in [true, false] {
            let encode = |value: Vec<u8>| if malformed { vec![255] } else { value };
            let module = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![
                (
                    keys::namespace_key("bulletin/ns"),
                    encode(borsh::to_vec(&namespace).unwrap()),
                ),
                (
                    keys::post_key("bulletin/ns", "id"),
                    encode(borsh::to_vec(&post).unwrap()),
                ),
                (
                    keys::collaborator_key("bulletin/ns", "reader"),
                    encode(borsh::to_vec(&collaborator).unwrap()),
                ),
            ]));
            let before = module.store().serialize();
            assert!(matches!(
                module.query_namespace("ns"),
                Err(BulletinError::State(_))
            ));
            assert!(matches!(
                module.has_namespace("bulletin/ns"),
                Err(BulletinError::State(_))
            ));
            assert!(matches!(
                module.get_post("bulletin/ns", "id"),
                Err(BulletinError::State(_))
            ));
            assert!(matches!(
                module.get_collaborator("bulletin/ns", "reader"),
                Err(BulletinError::State(_))
            ));
            assert_eq!(module.store().serialize(), before);
        }
    }

    #[test]
    fn restored_keys_reject_legacy_aliases_without_rewriting_records() {
        for namespace in ["bulletin/a/b", "bulletin/a|b", "bulletin/a%7Cb"] {
            let post = Post {
                id: "id".into(),
                namespace: namespace.into(),
                creator_did: "owner".into(),
                payload: vec![1],
                proof: vec![2],
            };
            let collaborator = Collaborator {
                did: "reader".into(),
                namespace: namespace.into(),
            };
            for (prefix, id, value, current) in [
                (
                    keys::POST_PREFIX,
                    "id",
                    borsh::to_vec(&post).unwrap(),
                    keys::post_key(namespace, "id"),
                ),
                (
                    keys::COLLABORATOR_PREFIX,
                    "reader",
                    borsh::to_vec(&collaborator).unwrap(),
                    keys::collaborator_key(namespace, "reader"),
                ),
            ] {
                let module = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
                    current,
                    value.clone(),
                )]));
                module.validate_storage_keys().unwrap();
                let mut old_key = prefix.to_vec();
                old_key
                    .extend_from_slice(format!("{}/{id}", namespace.replace('/', "|")).as_bytes());
                let module =
                    BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(old_key, value)]));
                let before = module.store().serialize();
                assert_eq!(
                    module.validate_storage_keys().is_ok(),
                    !namespace.contains(['|', '%'])
                );
                assert_eq!(module.store().serialize(), before);
            }
        }
        let corrupt = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
            b"post/bad/id".to_vec(),
            vec![255; 8],
        )]));
        assert!(corrupt.validate_storage_keys().is_err());
    }

    #[test]
    fn restored_records_require_complete_encoding_and_matching_identity() {
        let namespace = Namespace {
            id: "bulletin/ns".into(),
            creator: "signer".into(),
            owner_did: "owner".into(),
            created_at: Timestamp {
                seconds: 1,
                block_height: 1,
            },
        };
        let post = Post {
            id: "id".into(),
            namespace: namespace.id.clone(),
            creator_did: "owner".into(),
            payload: vec![1],
            proof: vec![2],
        };
        let collaborator = Collaborator {
            did: "reader".into(),
            namespace: namespace.id.clone(),
        };
        for (key, value) in [
            (
                keys::namespace_key(&namespace.id),
                borsh::to_vec(&namespace).unwrap(),
            ),
            (
                keys::post_key(&post.namespace, &post.id),
                borsh::to_vec(&post).unwrap(),
            ),
            (
                keys::collaborator_key(&collaborator.namespace, &collaborator.did),
                borsh::to_vec(&collaborator).unwrap(),
            ),
            (
                keys::PARAMS_KEY.to_vec(),
                borsh::to_vec(&BulletinParams::default()).unwrap(),
            ),
        ] {
            let restored = |bytes| {
                BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(key.clone(), bytes)]))
            };
            restored(value.clone()).validate_storage_keys().unwrap();
            for length in 0..value.len() {
                assert!(
                    restored(value[..length].to_vec())
                        .validate_storage_keys()
                        .is_err()
                );
            }
            let mut trailing = value;
            trailing.push(0);
            assert!(restored(trailing).validate_storage_keys().is_err());
        }
        let wrong_namespace = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
            keys::namespace_key("bulletin/other"),
            borsh::to_vec(&namespace).unwrap(),
        )]));
        assert!(wrong_namespace.validate_storage_keys().is_err());
    }

    #[test]
    fn restored_policy_id_rejects_empty_and_invalid_utf8() {
        BulletinModule::default().validate_storage_keys().unwrap();
        for bytes in [vec![], vec![255]] {
            let mut module = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
                keys::POLICY_ID_KEY.to_vec(),
                bytes,
            )]));
            assert!(module.validate_storage_keys().is_err());
            let mut acp = crate::acp::AcpModule::new();
            let before = module.store.serialize();
            let acp_before = acp.store().serialize();
            assert!(module.ensure_policy(&mut acp).is_err());
            assert_eq!(module.store.serialize(), before);
            assert_eq!(acp.store().serialize(), acp_before);
        }
        let mut module = BulletinModule::default();
        assert!(module.query_params().is_ok());
        module.store.put(keys::PARAMS_KEY, vec![0]);
        assert!(module.query_params().is_err());
        assert!(module.validate_storage_keys().is_err());
    }
}
