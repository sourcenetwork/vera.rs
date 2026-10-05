//! Bounded enumeration of current policy and relationship records.
use super::*;
use serde::{Deserialize, Serialize};

/// A page from one module snapshot. A cursor does not certify or pin a revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordPage<T> {
    /// Matching records in storage-key order.
    pub records: Vec<T>,
    /// Last inspected key, supplied unchanged to retrieve the next page.
    pub next: Option<Vec<u8>>,
}

/// Relationship selectors and an exclusive continuation cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipPageRequest {
    /// Object, relation and subject constraints.
    pub selector: RelationshipSelector,
    /// Cursor from the preceding page, or none for the first page.
    #[serde(default)]
    pub after: Option<Vec<u8>>,
}

impl AcpModule {
    /// Enumerate policies with at most 128 records and 1 MiB inspected per page.
    pub fn query_policies_page(&self, after: Option<&[u8]>) -> Result<RecordPage<PolicyRecord>> {
        self.record_page(keys::POLICY_PREFIX, after, |key, value| {
            let record: PolicyRecord = serde_json::from_slice(value)
                .map_err(|error| AcpError::State(format!("invalid policy: {error}")))?;
            if record.policy.id.len() != 64
                || !record
                    .policy
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || keys::policy_key(&record.policy.id) != key
            {
                return Err(AcpError::State("policy key mismatch".into()));
            }
            Ok(Some(record))
        })
    }

    /// Enumerate matching live relationships, bounding inspected records even for empty results.
    pub fn query_relationships_page(
        &self,
        policy_id: &str,
        request: &RelationshipPageRequest,
    ) -> Result<RecordPage<RelationshipRecord>> {
        self.query_policy(policy_id)?;
        self.record_page(
            &Self::relationship_query_prefix(policy_id, &request.selector),
            request.after.as_deref(),
            |key, value| {
                let record: RelationshipRecord = serde_json::from_slice(value)
                    .map_err(|error| AcpError::State(format!("invalid relationship: {error}")))?;
                if record.policy_id != policy_id
                    || keys::relationship_key(
                        policy_id,
                        &keys::relationship_storage_key(&record.relationship),
                    ) != key
                {
                    return Err(AcpError::State("relationship key mismatch".into()));
                }
                Ok(
                    (!record.archived && self.matches_selector(&record, &request.selector))
                        .then_some(record),
                )
            },
        )
    }

    fn record_page<T>(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        decode: impl Fn(&[u8], &[u8]) -> Result<Option<T>>,
    ) -> Result<RecordPage<T>> {
        if after.is_some_and(|key| key.len() > 64 << 10 || !key.starts_with(prefix)) {
            return Err(AcpError::InvalidAccessRequest {
                reason: "invalid page cursor".into(),
            });
        }
        let mut page = RecordPage {
            records: Vec::new(),
            next: None,
        };
        let mut bytes = 0usize;
        let mut previous = None;
        for (count, (key, value)) in self.store.prefix_iter_after(prefix, after).enumerate() {
            let size = key.len().saturating_add(value.len());
            if size > 1 << 20 {
                return Err(AcpError::State("record exceeds page budget".into()));
            }
            bytes = bytes.saturating_add(size);
            if count == 128 || bytes > 1 << 20 {
                page.next = previous;
                break;
            }
            if let Some(record) = decode(key, value)? {
                page.records.push(record);
            }
            previous = Some(key.to_vec());
        }
        Ok(page)
    }
}
