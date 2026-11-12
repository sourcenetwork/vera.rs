//! Typed bulletin reads authenticated against caller-provided consensus trust.

use alloy_primitives::{B256, Bytes};
use borsh::BorshDeserialize;
use vera_domain::ConsensusPublicKey;
use vera_modules::bulletin::keys;
pub use vera_modules::bulletin::types::{Collaborator, Namespace, Post};
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PAGE_RESPONSE_BYTES, PrefixPageRequest, PrefixPageResponse,
    RECORD_PROOF_BYTES, current::MAX_KEY_BYTES,
};

use crate::{ClientError, VeraClient};

/// A value or certified absence at one revision.
#[derive(Clone, Debug)]
pub struct BulletinRecord<T> {
    /// Selected finalized revision.
    pub revision: u64,
    /// Selected revision's timestamp.
    pub timestamp: u64,
    /// Decoded value, or certified absence.
    pub value: Option<T>,
}

/// A bounded page at one revision; later pages may select newer state.
#[derive(Clone, Debug)]
pub struct BulletinPage<T> {
    /// Selected finalized revision.
    pub revision: u64,
    /// Selected revision's timestamp.
    pub timestamp: u64,
    /// Consecutive records in storage-key order.
    pub records: Vec<T>,
    /// Inclusive lower bound for another page, or the end of this prefix.
    pub continuation: Option<Bytes>,
}

fn namespace_id(namespace: &str) -> Result<String, ClientError> {
    let prefix_len = if namespace.starts_with("bulletin/") {
        0
    } else {
        "bulletin/".len()
    };
    if namespace.len() > MAX_KEY_BYTES - keys::NAMESPACE_PREFIX.len() - prefix_len {
        return Err(vera_permission::PermissionError::Limit.into());
    }
    Ok(keys::namespace_id(namespace))
}

fn decode<T: BorshDeserialize>(
    value: &[u8],
    valid: impl FnOnce(&T) -> bool,
) -> Result<T, ClientError> {
    let record = T::try_from_slice(value)
        .map_err(|_| ClientError::InvalidResponse("invalid bulletin record encoding"))?;
    if !valid(&record) {
        return Err(ClientError::InvalidResponse(
            "bulletin record differs from selection",
        ));
    }
    Ok(record)
}

fn decode_policy_id(value: &[u8]) -> Result<B256, ClientError> {
    if value.len() != 64
        || !value
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(ClientError::InvalidResponse(
            "invalid bulletin policy identifier",
        ));
    }
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id)
        .map_err(|_| ClientError::InvalidResponse("invalid bulletin policy identifier"))?;
    Ok(B256::from(id))
}

impl VeraClient {
    /// Discover the bulletin's ACP policy, with certified absence before initialization.
    pub async fn read_bulletin_policy_id(
        &self,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinRecord<B256>, ClientError> {
        let response = self
            .read_current_record(
                ModuleId::Bulletin,
                keys::POLICY_ID_KEY,
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode_policy_id(bytes))
            .transpose()?;
        Ok(BulletinRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }
    /// Read a namespace by its unprefixed name, including certified absence.
    pub async fn read_bulletin_namespace(
        &self,
        namespace: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinRecord<Namespace>, ClientError> {
        let namespace = namespace_id(namespace)?;
        self.bulletin_record(
            keys::namespace_key(&namespace),
            minimum,
            trusted,
            |record: &Namespace| record.id == namespace,
        )
        .await
    }

    /// Read a post and check its namespace, identifier and content hash.
    pub async fn read_bulletin_post(
        &self,
        namespace: &str,
        id: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinRecord<Post>, ClientError> {
        let namespace = namespace_id(namespace)?;
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ClientError::InvalidResponse(
                "invalid bulletin post identifier",
            ));
        }
        self.bulletin_record(
            keys::post_key(&namespace, id),
            minimum,
            trusted,
            |record: &Post| {
                record.namespace == namespace
                    && record.id == id
                    && keys::generate_post_id(&namespace, &record.payload) == id
            },
        )
        .await
    }

    /// Read one collaborator record; absence means no stored collaborator grant.
    /// Any accepted spelling of the collaborator's key selects its one record.
    pub async fn read_bulletin_collaborator(
        &self,
        namespace: &str,
        did: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinRecord<Collaborator>, ClientError> {
        let namespace = namespace_id(namespace)?;
        if did.len() > MAX_KEY_BYTES {
            return Err(vera_permission::PermissionError::Limit.into());
        }
        let did = &*vera_modules::actor::canonical_str(did);
        self.bulletin_record(
            keys::collaborator_key(&namespace, did),
            minimum,
            trusted,
            |record: &Collaborator| record.namespace == namespace && record.did == did,
        )
        .await
    }

    /// List namespaces in certified storage-key order. Use no cursor for the first page.
    pub async fn list_bulletin_namespaces(
        &self,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinPage<Namespace>, ClientError> {
        self.bulletin_page(
            keys::NAMESPACE_PREFIX.to_vec(),
            cursor,
            limit,
            minimum,
            trusted,
            |key, record: &Namespace| {
                record.id.starts_with("bulletin/") && keys::namespace_key(&record.id) == key
            },
        )
        .await
    }

    /// List posts in a namespace. Carry the prior revision forward to prevent regression.
    pub async fn list_bulletin_posts(
        &self,
        namespace: &str,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinPage<Post>, ClientError> {
        let namespace = namespace_id(namespace)?;
        self.bulletin_page(
            keys::post_prefix(&namespace),
            cursor,
            limit,
            minimum,
            trusted,
            |key, record: &Post| {
                record.namespace == namespace
                    && keys::post_key(&namespace, &record.id) == key
                    && keys::generate_post_id(&namespace, &record.payload) == record.id
            },
        )
        .await
    }

    /// List stored collaborator grants. Namespace ownership is a separate record.
    pub async fn list_bulletin_collaborators(
        &self,
        namespace: &str,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<BulletinPage<Collaborator>, ClientError> {
        let namespace = namespace_id(namespace)?;
        self.bulletin_page(
            keys::collaborator_prefix(&namespace),
            cursor,
            limit,
            minimum,
            trusted,
            |key, record: &Collaborator| {
                record.namespace == namespace
                    && keys::collaborator_key(&namespace, &record.did) == key
            },
        )
        .await
    }

    async fn bulletin_record<T: BorshDeserialize>(
        &self,
        key: Vec<u8>,
        minimum: u64,
        trusted: &ConsensusPublicKey,
        valid: impl FnOnce(&T) -> bool,
    ) -> Result<BulletinRecord<T>, ClientError> {
        let response = self
            .read_current_record(
                ModuleId::Bulletin,
                &key,
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        Ok(BulletinRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value: response
                .record
                .value
                .as_ref()
                .map(|value| decode(value, valid))
                .transpose()?,
        })
    }

    async fn bulletin_page<T: BorshDeserialize>(
        &self,
        prefix: Vec<u8>,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
        valid: impl Fn(&[u8], &T) -> bool,
    ) -> Result<BulletinPage<T>, ClientError> {
        let prefix = Bytes::from(prefix);
        let request = PrefixPageRequest {
            module: ModuleId::Bulletin,
            start: cursor.unwrap_or_else(|| prefix.clone()),
            prefix,
            limit,
        };
        request.validate()?;
        let response: PrefixPageResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPrefixPageProof",
                serde_json::json!([request, minimum]),
                PAGE_RESPONSE_BYTES,
            )
            .await?;
        let page = response.verify(&request, minimum, trusted, PAGE_PROOF_BYTES)?;
        let records = page
            .entries
            .iter()
            .map(|entry| decode(&entry.value, |record| valid(&entry.key, record)))
            .collect::<Result<_, _>>()?;
        Ok(BulletinPage {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            records,
            continuation: page.continuation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_selection_accepts_returned_ids_and_bounds_encoded_keys() {
        assert_eq!(
            namespace_id("a/b").unwrap(),
            namespace_id("bulletin/a/b").unwrap()
        );
        let short = "x".repeat(MAX_KEY_BYTES - keys::NAMESPACE_PREFIX.len() - "bulletin/".len());
        let full = format!("bulletin/{short}");
        assert_eq!(namespace_id(&short).unwrap(), namespace_id(&full).unwrap());
        assert!(namespace_id(&(short + "x")).is_err());
        assert!(namespace_id(&(full + "x")).is_err());
    }

    #[test]
    fn bulletin_policy_identifier_requires_canonical_encoding() {
        assert_eq!(
            decode_policy_id(&[b'a'; 64]).unwrap(),
            B256::repeat_byte(0xaa)
        );
        for bytes in [
            vec![],
            vec![b'a'; 63],
            vec![b'a'; 65],
            vec![b'A'; 64],
            vec![0xff; 64],
        ] {
            assert!(decode_policy_id(&bytes).is_err());
        }
    }

    #[test]
    fn bulletin_decoding_rejects_wrong_selection_and_trailing_bytes() {
        let record = Collaborator {
            did: "did:key:reader".into(),
            namespace: "bulletin/team".into(),
        };
        let mut bytes = borsh::to_vec(&record).unwrap();
        assert!(decode::<Collaborator>(&bytes, |c| c.namespace == "bulletin/other").is_err());
        assert_eq!(
            decode::<Collaborator>(&bytes, |c| c == &record).unwrap(),
            record
        );
        bytes.push(0);
        assert!(decode::<Collaborator>(&bytes, |_| true).is_err());
    }
}
