//! Anchoring a baby's revision in the parent and keeping the parent's evidence of it.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use alloy_primitives::B256;
use alloy_sol_types::SolEvent as _;
use commonware_codec::Encode as _;
use vera_client::{
    BlsSigner, ClientError, ReceiptResponse, RefusalKind, VeraClient,
    administration::AdministrativeCommand,
    anchoring::{
        AnchorRecord, AnchorSubmitterGrant, AnchoredSnapshot, AnchoringError,
        DeploymentRegistration, deployment_id,
    },
};
use vera_domain::{ConsensusPublicKey, LightBlock, TermCertificate, verify_finalized_block};
use vera_modules::vera::anchors::abi::IAnchor;

use super::administration;
use super::baby::Baby;

pub(crate) const DEADLINE: Duration = Duration::from_secs(90);

/// The parent, the only key a reader trusts it by, and its operators' next
/// administrative sequence.
pub(crate) struct Parent {
    pub(crate) client: VeraClient,
    pub(crate) key: ConsensusPublicKey,
    pub(crate) sequence: AtomicU64,
}

/// One accepted anchor with the parent's certified receipt of it.
pub(crate) struct Anchored {
    pub(crate) snapshot: AnchoredSnapshot,
    pub(crate) record: AnchorRecord,
    pub(crate) submission: B256,
    /// Height of the parent's revision that recorded the anchor.
    pub(crate) parent_height: u64,
    /// That revision's finalized timestamp.
    pub(crate) parent_time: u64,
}

impl Parent {
    /// Apply one administrative command approved by the parent's operators.
    async fn administer(&self, command: AdministrativeCommand) {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        let approved = administration::approve(&self.client, command, sequence).await;
        let operator = BlsSigner::random(self.client.chain_id().await.unwrap()).unwrap();
        let receipt = self
            .client
            .native_apply_administration(&operator, &approved)
            .await
            .unwrap();
        assert!(receipt.success, "the parent's operators approve the change");
    }

    /// Register `baby` with its key, genesis block and operator policy.
    pub(crate) async fn register(&self, baby: &Baby) {
        let registration = DeploymentRegistration {
            consensus_key: hex::encode(baby.key.encode()),
            genesis_id: administration::genesis_id(&baby.client).await.0,
            operators: super::baby::operators(),
        };
        self.administer(AdministrativeCommand::RegisterDeployment(registration))
            .await;
    }

    /// Grant `relay` the right to submit for `baby`, `quota` times a day.
    pub(crate) async fn grant(&self, baby: &Baby, relay: &BlsSigner, quota: u32) {
        let grant = AnchorSubmitterGrant {
            deployment: deployment_id(&baby.key).0,
            submitter: relay.did().to_owned(),
            quota,
        };
        self.administer(AdministrativeCommand::SetAnchorSubmitter(grant))
            .await;
    }

    /// Capture `policy` on `baby`, anchor that revision, and keep the receipt.
    pub(crate) async fn anchor_policy(
        &self,
        baby: &Baby,
        relay: &BlsSigner,
        policy: &str,
    ) -> Anchored {
        let captured = baby
            .client
            .capture_policy_snapshot(policy, 0, &baby.key)
            .await
            .unwrap();
        let submission = self.submit(relay, baby, &captured.revision).await;
        let parent_height = self
            .client
            .await_anchor(submission, &self.key, DEADLINE)
            .await
            .unwrap();
        let deployment = deployment_id(&baby.key);
        let latest = self
            .client
            .read_latest_anchor(&deployment, parent_height, &self.key)
            .await
            .unwrap();
        let record = latest.record.expect("the anchor is recorded");
        let snapshot = AnchoredSnapshot {
            policy: policy.to_owned(),
            revision: captured.revision,
            proof: captured.proof,
            anchor: latest.evidence,
        };
        let (event, parent_time) = self.anchored_event(submission).await;
        assert_eq!(event.deployment.0, deployment.0);
        assert_eq!(
            (event.sequence, event.height, event.blockHash.0),
            (record.sequence, record.height, record.block_hash.0),
        );
        assert_eq!(record.anchored_at, parent_height);
        Anchored {
            snapshot,
            record,
            submission,
            parent_height,
            parent_time,
        }
    }

    /// The `RevisionAnchored` event of an accepted anchor and the finalized time
    /// of the parent's revision that recorded it, from its certified receipt.
    pub(crate) async fn anchored_event(
        &self,
        submission: B256,
    ) -> (IAnchor::RevisionAnchored, u64) {
        let response: ReceiptResponse = self
            .client
            .read_receipt(submission, &self.key)
            .await
            .unwrap()
            .expect("the parent retains the anchor's receipt");
        let receipt = response.verify(submission, &self.key).unwrap();
        assert!(receipt.refusal.is_none());
        let [log] = receipt.logs() else {
            panic!("an accepted anchor emits one event");
        };
        let event = IAnchor::RevisionAnchored::decode_log_data(&log.data).unwrap();
        let block = verify_finalized_block(&response.revision, &self.key).unwrap();
        (event, block.timestamp)
    }

    /// Submit `revision` of `baby` with the proof its node gives that the
    /// deployment's latest anchor is an ancestor of the revision.
    async fn submit(&self, relay: &BlsSigner, baby: &Baby, revision: &LightBlock) -> B256 {
        self.try_submit(relay, baby, revision).await.unwrap()
    }

    /// As [`Self::submit`], returning the node's refusal to admit the request.
    pub(crate) async fn try_submit(
        &self,
        relay: &BlsSigner,
        baby: &Baby,
        revision: &LightBlock,
    ) -> Result<B256, ClientError> {
        let lineage = self
            .client
            .read_anchor_lineage(&deployment_id(&baby.key), 0, &self.key)
            .await
            .unwrap();
        let proof = baby
            .client
            .anchor_proof(lineage.tip(), revision.height)
            .await
            .unwrap();
        self.client
            .submit_anchor(relay, revision, &baby.key, proof.as_ref())
            .await
    }

    /// Submit `revision` of `baby` and return the refusal, if any.
    pub(crate) async fn try_anchor(
        &self,
        relay: &BlsSigner,
        baby: &Baby,
        revision: &LightBlock,
    ) -> Result<B256, RefusalKind> {
        let submission = self.submit(relay, baby, revision).await;
        self.outcome(submission).await
    }

    /// Report `baby`'s revision at `height` as a fork of `latest` and return the refusal, if any.
    pub(crate) async fn try_report_fork(
        &self,
        relay: &BlsSigner,
        baby: &Baby,
        height: u64,
        latest: &AnchorRecord,
    ) -> Result<B256, RefusalKind> {
        let submission = baby
            .client
            .report_fork(
                &self.client,
                relay,
                height,
                &baby.key,
                (latest.height, latest.block_hash),
            )
            .await
            .unwrap();
        self.outcome(submission).await
    }

    /// Submit a term certificate of `baby` and return the refusal, if any.
    pub(crate) async fn try_change_term(
        &self,
        relay: &BlsSigner,
        baby: &Baby,
        certificate: &TermCertificate,
    ) -> Result<B256, RefusalKind> {
        let submission = self
            .client
            .submit_term_change(relay, &baby.key, certificate)
            .await
            .unwrap();
        self.outcome(submission).await
    }

    async fn outcome(&self, submission: B256) -> Result<B256, RefusalKind> {
        match self
            .client
            .await_anchor(submission, &self.key, DEADLINE)
            .await
        {
            Ok(_) => Ok(submission),
            Err(ClientError::Anchoring(AnchoringError::Refused(refusal))) => Err(refusal.kind),
            Err(error) => panic!("anchor neither recorded nor refused: {error}"),
        }
    }
}
