use super::*;
use alloy_primitives::B256;
use commonware_consensus::types::Height;
use commonware_cryptography::Digestible as _;
use commonware_storage::merkle::{Location, mmr};
use commonware_utils::NZUsize;
use vera_domain::{ConsensusPublicKey, LightBlock, verify_finalized_block};

/// A fixed synchronization selection authenticated against an independent consensus key.
#[derive(Clone, Debug)]
pub struct OrderedCheckpoint {
    anchor: Anchor<Digest>,
    targets: OrderedTargets,
    module_root: B256,
}

impl OrderedCheckpoint {
    /// Authenticate finality, native log roots and ranges before opening destination storage.
    /// Callers select a sufficiently recent revision and supply its trusted consensus key.
    pub fn verify(
        light: &LightBlock,
        trusted_key: &ConsensusPublicKey,
        proof: &native::SyncProof,
    ) -> Result<Self, AppError> {
        let block = verify_finalized_block(light, trusted_key)
            .map_err(|e| AppError::Execution(e.to_string()))?;
        if !<OrderedState as crate::ApplicationState>::accepts(&block) {
            return Err(AppError::RootMismatch("native checkpoint commitments"));
        }
        let native = proof.verify(block.module_state_root)?;
        if let Some(targets) = &block.native_targets
            && *targets
                != [&native.0, &native.1, &native.2, &native.3]
                    .map(crate::targets::target_from_sync)
        {
            return Err(AppError::RootMismatch("native checkpoint targets"));
        }
        let db = &block.db_targets;
        for target in [&db.accounts, &db.storage, &db.code] {
            if target.floor >= target.tip || !Location::<mmr::Family>::new(target.tip).is_valid() {
                return Err(AppError::Execution("invalid execution sync range".into()));
            }
        }
        let root = vera_qmdb::StateRoot::compute(
            B256::from(db.accounts.root.0),
            B256::from(db.storage.root.0),
            B256::from(db.code.root.0),
        );
        if root != block.state_root.0 {
            return Err(AppError::RootMismatch("execution targets"));
        }
        let execution = crate::sync_targets(db);
        Ok(Self {
            anchor: Anchor {
                height: Height::new(block.height),
                round: block.context.round,
                digest: block.digest(),
            },
            targets: (
                execution.0,
                execution.1,
                execution.2,
                native.0,
                native.1,
                native.2,
                native.3,
                Some(Digest::from(block.module_state_root.0)),
            ),
            module_root: block.module_state_root,
        })
    }

    /// The authenticated revision selected for synchronization.
    pub const fn anchor(&self) -> &Anchor<Digest> {
        &self.anchor
    }
}

impl OrderedState {
    /// Synchronize a fixed verified revision and check its current-state roots before publication.
    /// Later revisions can be replayed after this handoff; this call does not move its selection.
    pub async fn sync_checkpoint<R: Send + 'static>(
        context: Ctx,
        config: OrderedConfig,
        sources: R,
        checkpoint: OrderedCheckpoint,
        sync_config: SyncEngineConfig,
    ) -> Result<(Self, Anchor<Digest>), String>
    where
        OrderedDatabases: StateSyncSet<Ctx, R, Digest, Error = String>,
    {
        let (_updates, updates_rx) = ring::channel(NZUsize!(1));
        let (databases, reached) = Box::pin(OrderedDatabases::sync(
            context,
            config.databases,
            sources,
            checkpoint.anchor,
            checkpoint.targets,
            updates_rx,
            sync_config,
        ))
        .await?;
        let root = Self::module_root(&databases).await;
        if root != checkpoint.module_root || reached != checkpoint.anchor {
            return Err("synchronized state differs from verified checkpoint".into());
        }
        if let Some(handoff) = config.sync_handoff {
            handoff(reached).await?;
        }
        let state = Self::hydrate(databases, config.executor)
            .await
            .map_err(|e| e.to_string())?;
        Ok((state, reached))
    }
}

impl OrderedConfig {
    /// Rewind to verified targets and validate their native current-state root before publication.
    #[must_use]
    pub const fn recover_checkpoint(mut self, checkpoint: OrderedCheckpoint) -> Self {
        self.recovery = Some(checkpoint.targets);
        self.marshal_recovery = false;
        self
    }
}
