//! Recording a deployment's certified terms in the deployment that anchors it,
//! and reading where its chain of anchors stands.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall as _;
use vera_domain::{ConsensusPublicKey, ModuleId, TermCertificate};
use vera_modules::vera::anchors::{
    AnchorError, DeploymentRecord, Lineage, TermRecord, abi::IAnchor, deployment_key, term_key,
    term_of_key, term_prefix,
};
use vera_permission::{MAX_PAGE_RECORDS, PAGE_PROOF_BYTES, PrefixPageRequest, RECORD_PROOF_BYTES};

use super::{AnchoringError, deployment_id};
use crate::{BlsSigner, ClientError, VeraClient, client::ANCHOR_ADDRESS};

/// Encode the term change of the deployment whose consensus key is `key`.
pub fn encode_term_change(
    key: &ConsensusPublicKey,
    certificate: &TermCertificate,
) -> Result<Bytes, ClientError> {
    Ok(IAnchor::changeTermCall {
        deployment: deployment_id(key),
        certificate: serde_json::to_vec(certificate)?.into(),
    }
    .abi_encode()
    .into())
}

impl VeraClient {
    /// Submit `certificate`, a term of the deployment with consensus key
    /// `key`, to this deployment. Returns the submission identifier;
    /// [`Self::await_anchor`] waits for its receipt.
    ///
    /// Once recorded, the deployment's anchors continue from the
    /// certificate's cut in its term, and the anchors above the cut are
    /// superseded.
    pub async fn submit_term_change(
        &self,
        submitter: &BlsSigner,
        key: &ConsensusPublicKey,
        certificate: &TermCertificate,
    ) -> Result<B256, ClientError> {
        self.submit_native(
            submitter,
            ANCHOR_ADDRESS,
            encode_term_change(key, certificate)?,
        )
        .await
    }

    /// Read up to `limit` terms of `deployment` this deployment recorded,
    /// starting at term `from`, in term order, verified against its `trusted`
    /// key at a revision of at least `minimum_height`.
    ///
    /// The page's proof shows no term between its entries. A later page is
    /// read at a later revision, so pass the returned `revision` as its
    /// minimum; a term record never changes once recorded, so the pages
    /// together are every term up to the last page's revision.
    pub async fn read_anchor_terms(
        &self,
        deployment: &B256,
        from: u64,
        limit: u16,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<TermPage, ClientError> {
        let prefix = term_prefix(deployment);
        let request = PrefixPageRequest {
            module: ModuleId::Vera,
            start: term_key(deployment, from).into(),
            prefix: prefix.into(),
            limit: limit.clamp(1, MAX_PAGE_RECORDS),
        };
        let (response, page) = self
            .verified_prefix_page(&request, minimum_height, trusted, PAGE_PROOF_BYTES)
            .await?;
        let entries = page
            .entries
            .iter()
            .map(|entry| TermRecord::decode(deployment, &entry.key, &entry.value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(AnchoringError::from)?;
        let next = page
            .continuation
            .map(|key| {
                term_of_key(deployment, &key)
                    .ok_or(ClientError::InvalidResponse("term continuation"))
            })
            .transpose()?;
        Ok(TermPage {
            entries,
            next,
            revision: response.revision.height,
        })
    }

    /// Read every term of `deployment` above `term`, page by page, verified
    /// like [`Self::read_anchor_terms`].
    ///
    /// [`super::VerifiedSnapshot::ensure_kept`] needs the terms above the
    /// snapshot anchor's own term: a term at or below it was recorded before
    /// the anchor and cannot void it.
    pub async fn read_anchor_terms_above(
        &self,
        deployment: &B256,
        term: u64,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Vec<TermRecord>, ClientError> {
        let mut terms = Vec::new();
        let Some(mut from) = term.checked_add(1) else {
            return Ok(terms);
        };
        let mut minimum = minimum_height;
        loop {
            let page = self
                .read_anchor_terms(deployment, from, MAX_PAGE_RECORDS, minimum, trusted)
                .await?;
            terms.extend(page.entries);
            match page.next {
                Some(next) if next > from => (from, minimum) = (next, page.revision),
                Some(_) => return Err(ClientError::InvalidResponse("term continuation")),
                None => return Ok(terms),
            }
        }
    }

    /// Read where the chain of anchors of `deployment` stands: its latest
    /// anchor and the term certified last, verified against this
    /// deployment's `trusted` key at a revision of at least `minimum_height`.
    /// [`Lineage::tip`] is the block its next anchor must descend from.
    ///
    /// It reads three records whatever the number of terms: the registration,
    /// which names the term certified last, that term's record, and the latest
    /// anchor.
    pub async fn read_anchor_lineage(
        &self,
        deployment: &B256,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Lineage, ClientError> {
        let registration = self
            .read_current_record(
                ModuleId::Vera,
                &deployment_key(deployment),
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let certified = registration
            .record
            .value
            .as_ref()
            .map(|value| DeploymentRecord::decode(deployment, value))
            .transpose()
            .map_err(AnchoringError::from)?
            .map_or(0, |registered| registered.term);
        let revision = registration.revision.height.max(minimum_height);
        let term = match certified {
            0 => None,
            certified => {
                let key = term_key(deployment, certified);
                let evidence = self
                    .read_current_record(
                        ModuleId::Vera,
                        &key,
                        revision,
                        trusted,
                        RECORD_PROOF_BYTES,
                    )
                    .await?;
                let value = evidence
                    .record
                    .value
                    .as_ref()
                    .ok_or(AnchoringError::Record(AnchorError::MalformedRecord))?;
                Some(TermRecord::decode(deployment, &key, value).map_err(AnchoringError::from)?)
            }
        };
        let latest = self
            .read_latest_anchor(deployment, revision, trusted)
            .await?
            .record;
        Ok(Lineage { latest, term })
    }
}

/// Consecutive terms of one deployment, proven at one finalized revision of
/// the deployment that recorded them.
#[derive(Clone, Debug)]
pub struct TermPage {
    /// The terms, in term order.
    pub entries: Vec<TermRecord>,
    /// Term the next page starts at, or `None` when the deployment had no
    /// later term at `revision`.
    pub next: Option<u64>,
    /// Height of the revision the page was read at.
    pub revision: u64,
}
