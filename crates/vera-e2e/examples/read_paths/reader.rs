//! The read paths under comparison and the reader that runs one of them.

use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum Query {
    PolicyCall,
    PolicyVerified,
    RelationshipsCall,
    RelationshipsVerified50,
    RelationshipsVerified128,
    AccessCall,
    AccessVerified,
    PostsCall,
    PostsVerified,
    PolicyFetchOnly,
    PolicyVerifyOnly,
    AccessFetchOnly,
    AccessVerifyOnly,
    CertificateVerifyOnly,
}

pub(super) const QUERIES: [Query; 14] = [
    Query::PolicyCall,
    Query::PolicyVerified,
    Query::RelationshipsCall,
    Query::RelationshipsVerified50,
    Query::RelationshipsVerified128,
    Query::AccessCall,
    Query::AccessVerified,
    Query::PostsCall,
    Query::PostsVerified,
    Query::PolicyFetchOnly,
    Query::PolicyVerifyOnly,
    Query::AccessFetchOnly,
    Query::AccessVerifyOnly,
    Query::CertificateVerifyOnly,
];

pub(super) struct Reader {
    pub(super) client: VeraClient,
    pub(super) trusted: ConsensusPublicKey,
    pub(super) seeded: Seeded,
    pub(super) request: AccessRequest,
    pub(super) record: RecordResponse,
    pub(super) permission: PermissionResponse,
}

impl Reader {
    /// Runs one read and returns how many records it produced, as a correctness check.
    pub(super) async fn read(&self, query: Query) -> Result<usize, ClientError> {
        let policy = self.seeded.policy;
        let minimum = self.seeded.minimum;
        let trusted = &self.trusted;
        Ok(match query {
            Query::PolicyCall => usize::from(
                !self
                    .client
                    .get_policy(FixedBytes(policy.0))
                    .await?
                    .is_empty(),
            ),
            Query::PolicyVerified => usize::from(
                self.client
                    .read_policy(policy, minimum, trusted)
                    .await?
                    .value
                    .is_some(),
            ),
            Query::RelationshipsCall => self
                .client
                .get_relationships_page(
                    FixedBytes(policy.0),
                    &RelationshipPageRequest {
                        selector: Default::default(),
                        after: None,
                    },
                )
                .await?
                .records
                .len(),
            Query::RelationshipsVerified50 | Query::RelationshipsVerified128 => {
                let limit = if matches!(query, Query::RelationshipsVerified50) {
                    50
                } else {
                    128
                };
                self.client
                    .read_relationship_page(policy, None, limit, minimum, trusted)
                    .await?
                    .records
                    .len()
            }
            Query::AccessCall => usize::from(
                self.client
                    .verify_access_request(
                        FixedBytes(policy.0),
                        vec!["document".into()],
                        vec!["doc".into()],
                        vec!["read".into()],
                        &self.seeded.actor,
                    )
                    .await?,
            ),
            Query::AccessVerified => usize::from(
                self.client
                    .verify_current_access(
                        &hex::encode(policy),
                        &self.request,
                        minimum,
                        trusted,
                        PERMISSION_LIMITS,
                    )
                    .await?
                    .1,
            ),
            Query::PostsCall => {
                let bytes = self.client.get_namespace_posts(NAMESPACE).await?;
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
                    .map(|posts| posts.len())
                    .unwrap_or(usize::MAX)
            }
            Query::PostsVerified => self
                .client
                .list_bulletin_posts(NAMESPACE, None, 50, minimum, trusted)
                .await?
                .records
                .len(),
            Query::PolicyFetchOnly => usize::from(
                fetch_record(&self.client, policy, minimum)
                    .await?
                    .record
                    .value
                    .is_some(),
            ),
            Query::PolicyVerifyOnly => {
                self.record.verify(
                    ModuleId::Acp,
                    &policy_key(policy),
                    minimum,
                    trusted,
                    RECORD_PROOF_BYTES,
                )?;
                1
            }
            Query::AccessFetchOnly => {
                self.client
                    .current_permission_response(
                        &hex::encode(policy),
                        &self.request,
                        minimum,
                        PERMISSION_LIMITS,
                    )
                    .await?;
                1
            }
            Query::CertificateVerifyOnly => {
                vera_domain::verify_light_block(&self.record.revision, trusted)?;
                1
            }
            Query::AccessVerifyOnly => usize::from(self.permission.verify(
                &hex::encode(policy),
                &self.request,
                minimum,
                trusted,
                PERMISSION_LIMITS,
            )?),
        })
    }
}

/// The record request `read_policy` sends, without verifying the response.
pub(super) async fn fetch_record(
    client: &VeraClient,
    policy: B256,
    minimum: u64,
) -> Result<RecordResponse, ClientError> {
    client
        .rpc_call_typed(
            "vera_getCurrentRecordProof",
            serde_json::json!([
                ModuleId::Acp,
                alloy_primitives::Bytes::from(policy_key(policy)),
                minimum
            ]),
        )
        .await
}

pub(super) fn policy_key(policy: B256) -> Vec<u8> {
    vera_modules::acp::keys::policy_key(&hex::encode(policy))
}

pub(super) const fn expected(query: Query) -> usize {
    match query {
        Query::PolicyCall | Query::PolicyVerified | Query::AccessCall | Query::AccessVerified => 1,
        Query::RelationshipsCall | Query::RelationshipsVerified128 => RELATIONSHIPS + 1,
        Query::RelationshipsVerified50 => 50,
        Query::PostsCall | Query::PostsVerified => POSTS,
        Query::PolicyFetchOnly
        | Query::PolicyVerifyOnly
        | Query::AccessFetchOnly
        | Query::AccessVerifyOnly
        | Query::CertificateVerifyOnly => 1,
    }
}
