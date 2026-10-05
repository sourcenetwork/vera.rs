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

    /// Enumerate matching live relationships with bounded planning, including empty results.
    /// Planning permits 256 directory reads, 256 buckets and 1 MiB of directory/prefix bytes;
    /// each page separately inspects at most 128 records and 1 MiB of row bytes.
    pub fn query_relationships_page(
        &self,
        policy_id: &str,
        request: &RelationshipPageRequest,
    ) -> Result<RecordPage<RelationshipRecord>> {
        let policy = self.query_policy(policy_id)?;
        let after = request.after.as_deref();
        if after.is_some_and(|key| {
            key.len() > 64 << 10 || !key.starts_with(&keys::relationship_policy_prefix(policy_id))
        }) {
            return Err(AcpError::InvalidAccessRequest {
                reason: "invalid page cursor".into(),
            });
        }
        let mut page = RecordPage {
            records: Vec::new(),
            next: None,
        };
        let mut bytes = 0usize;
        let mut count = 0usize;
        let mut previous = None;
        for prefix in self.relationship_query_prefixes(&policy, &request.selector)? {
            if after.is_some_and(|key| key >= prefix.as_slice() && !key.starts_with(&prefix)) {
                continue;
            }
            let cursor = after.filter(|key| key.starts_with(&prefix));
            for (key, value) in self.store.prefix_iter_after(&prefix, cursor) {
                let size = key.len().saturating_add(value.len());
                if size > 1 << 20 {
                    return Err(AcpError::State("record exceeds page budget".into()));
                }
                if count == 128 || bytes.saturating_add(size) > 1 << 20 {
                    page.next = previous;
                    return Ok(page);
                }
                bytes += size;
                count += 1;
                let record = Self::decode_current_relationship(&policy, key, value)?;
                if !record.archived && self.matches_selector(&record, &request.selector) {
                    page.records.push(record);
                }
                previous = Some(key.to_vec());
            }
        }
        Ok(page)
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
