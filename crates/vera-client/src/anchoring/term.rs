//! Recording a deployment's certified terms in the deployment that anchors it,
//! and reading where its chain of anchors stands.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall as _;
use vera_domain::{ConsensusPublicKey, ModuleId, TermCertificate};
use vera_modules::vera::anchors::{Lineage, TermRecord, abi::IAnchor, term_prefix};
use vera_permission::RECORD_PROOF_BYTES;

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

    /// Read every term of `deployment` this deployment recorded, in term
    /// order, verified against its `trusted` key at a revision of at least
    /// `minimum_height`. [`super::VerifiedSnapshot::ensure_kept`] checks a
    /// snapshot against them.
    pub async fn read_anchor_terms(
        &self,
        deployment: &B256,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Vec<TermRecord>, ClientError> {
        let prefix = term_prefix(deployment);
        let response = self
            .read_current_prefix(
                ModuleId::Vera,
                &prefix,
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let evidence = response.verify(
            ModuleId::Vera,
            &prefix,
            minimum_height,
            &self.established(trusted),
            RECORD_PROOF_BYTES,
        )?;
        evidence
            .entries
            .iter()
            .map(|entry| {
                TermRecord::decode(deployment, &entry.key, &entry.value)
                    .map_err(|error| AnchoringError::from(error).into())
            })
            .collect()
    }

    /// Read where the chain of anchors of `deployment` stands: its latest
    /// anchor and the term certified last, each verified against this
    /// deployment's `trusted` key at a revision of at least `minimum_height`.
    /// [`Lineage::tip`] is the block its next anchor must descend from.
    pub async fn read_anchor_lineage(
        &self,
        deployment: &B256,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Lineage, ClientError> {
        let terms = self
            .read_anchor_terms(deployment, minimum_height, trusted)
            .await?;
        let latest = self
            .read_latest_anchor(deployment, minimum_height, trusted)
            .await?
            .record;
        Ok(Lineage {
            latest,
            term: terms.into_iter().next_back(),
        })
    }
}
