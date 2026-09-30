//! Ordered module persistence with query-state publication after database transitions.

use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    Anchor, AttachableResolverSet, Barrier, DatabaseSet, Shared, StateSyncSet, SyncEngineConfig,
    TipUpdate,
};
use commonware_storage::qmdb::sync::Target;
use commonware_utils::channel::ring;
use commonware_utils::non_empty_range;
use vera_backend::{
    AccountsDb, CodeDb, Ctx, StorageDb, VeraConfig,
    native::{self, NativeConfig, NativeDb, NativeStateSet},
};
use vera_domain::Tx;
use vera_executor::{BlockContext, ExecutionOutcome, ModuleSnapshot, VeraExecutor};

use crate::{AppError, execute_block};

type SyncHandoff = Box<
    dyn FnOnce(Anchor<Digest>) -> futures::future::BoxFuture<'static, Result<(), String>> + Send,
>;

/// Execution and ordered native partitions, coordinated by Commonware as one set.
pub type OrderedDatabases = (
    Shared<AccountsDb>,
    Shared<StorageDb>,
    Shared<CodeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<commitment::Commitment>,
);
type Pending = <OrderedDatabases as DatabaseSet<Ctx>>::Unmerkleized;
type Sealed = <OrderedDatabases as DatabaseSet<Ctx>>::Merkleized;
type Config = <OrderedDatabases as DatabaseSet<Ctx>>::Config;
/// Seven operation-log targets selected by one authenticated revision.
pub type OrderedTargets = <OrderedDatabases as DatabaseSet<Ctx>>::SyncTargets;

mod commitment;
#[cfg(feature = "fault-injection")]
mod faults;
pub use commitment::Commitment;
mod checkpoint;
pub use checkpoint::OrderedCheckpoint;

/// Storage configuration and the trusted startup recovery selection.
pub struct OrderedConfig {
    databases: Config,
    executor: VeraExecutor,
    recovery: Option<OrderedTargets>,
    marshal_recovery: bool,
    sync_handoff: Option<SyncHandoff>,
}

impl std::fmt::Debug for OrderedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedConfig")
            .field("recovery", &self.recovery)
            .finish_non_exhaustive()
    }
}

impl OrderedConfig {
    /// Finish dependent durable recovery before synced databases reach the processor.
    /// The callback receives the final selected anchor, which may advance during transfer.
    #[must_use]
    pub fn with_sync_handoff<F, Fut>(mut self, handoff: F) -> Self
    where
        F: FnOnce(Anchor<Digest>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        self.sync_handoff = Some(Box::new(move |anchor| Box::pin(handoff(anchor))));
        self
    }

    /// Let the stateful actor align journals to marshal's durable anchor before publication.
    /// The in-memory commitment starts unset, forcing its startup target comparison to rewind.
    #[must_use]
    pub const fn recover_from_marshal(mut self) -> Self {
        self.recovery = None;
        self.marshal_recovery = true;
        self
    }

    /// Recover existing journals to targets authenticated by the caller before publication.
    /// Sync uses the targets supplied to `StateSyncSet::sync` instead of this startup selection.
    #[must_use]
    pub const fn recover_to(mut self, targets: OrderedTargets) -> Self {
        self.recovery = Some(targets);
        self.marshal_recovery = false;
        self
    }
}

/// Pending storage and logical module state from the same parent.
pub struct OrderedPending {
    databases: Pending,
    modules: ModuleSnapshot,
}

/// Sealed storage and the corresponding logical module state.
#[derive(Clone)]
pub struct OrderedSealed {
    databases: Sealed,
    modules: ModuleSnapshot,
    height: u64,
}

/// Ordered storage lifecycle for native execution, independent of application callbacks.
///
/// Database mutations must not overlap, as required by `DatabaseSet`. Queries over
/// logical modules keep the previous snapshot until all partition mutations finish.
#[derive(Clone)]
pub struct OrderedState {
    databases: OrderedDatabases,
    executor: VeraExecutor,
}

impl std::fmt::Debug for OrderedPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedPending").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OrderedSealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedSealed")
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OrderedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedState")
            .field("deployment", &self.executor.chain_id())
            .finish_non_exhaustive()
    }
}

impl OrderedSealed {
    /// Operation-log targets authenticated by the revision that selects these batches.
    pub fn sync_targets(&self) -> <OrderedState as DatabaseSet<Ctx>>::SyncTargets {
        let db = &self.databases;
        let execution = crate::sync_targets(&crate::db_targets_from_merkleized(&(
            db.0.clone(),
            db.1.clone(),
            db.2.clone(),
        )));
        let native =
            |batch: &<NativeDb as commonware_glue::stateful::db::ManagedDb<Ctx>>::Merkleized| {
                Target::new(
                    batch.ops_root(),
                    non_empty_range!(batch.sync_boundary(), batch.bounds().tip.size),
                )
            };
        (
            execution.0,
            execution.1,
            execution.2,
            native(&db.3),
            native(&db.4),
            native(&db.5),
            native(&db.6),
            db.7.0,
        )
    }
}

#[cfg(test)]
mod tests;

/// Configure execution and native journals alongside an executor without JMT trees.
pub fn ordered_config(
    execution: VeraConfig,
    native: NativeConfig,
    executor: VeraExecutor,
) -> OrderedConfig {
    OrderedConfig {
        databases: (
            execution.0,
            execution.1,
            execution.2,
            native.0,
            native.1,
            native.2,
            native.3,
            (),
        ),
        executor,
        recovery: None,
        marshal_recovery: false,
        sync_handoff: None,
    }
}

impl OrderedState {
    /// Shared execution partitions for admission, indexing and peer serving.
    pub fn execution_databases(&self) -> vera_backend::VeraStateSet {
        (
            self.databases.0.clone(),
            self.databases.1.clone(),
            self.databases.2.clone(),
        )
    }

    /// Shared ordered module partitions for verified reads and peer serving.
    pub fn native_databases(&self) -> NativeStateSet {
        (
            self.databases.3.clone(),
            self.databases.4.clone(),
            self.databases.5.clone(),
            self.databases.6.clone(),
        )
    }

    /// Open fresh storage, or rewind existing journals before publishing query state.
    ///
    /// Unanchored existing state is rejected. A failed partition rewind is fatal,
    /// matching Commonware's `DatabaseSet` recovery contract.
    pub async fn open(context: Ctx, config: OrderedConfig) -> Result<Self, AppError> {
        if config.marshal_recovery {
            return Err(AppError::Execution(
                "marshal recovery requires the stateful actor".into(),
            ));
        }
        if config.executor.module_trees().is_some() {
            return Err(AppError::Execution(
                "ordered storage cannot attach JMT trees".into(),
            ));
        }
        let databases = Box::pin(OrderedDatabases::init(
            context,
            config.databases,
            config.recovery.clone(),
        ))
        .await;
        match config.recovery {
            Some(targets) => {
                if databases.committed_targets().await != targets {
                    return Err(AppError::RootMismatch("ordered recovery targets"));
                }
            }
            None if databases.committed_targets().await
                != OrderedDatabases::initial_sync_targets() =>
            {
                return Err(AppError::Execution(
                    "existing ordered state requires an authenticated recovery target".into(),
                ));
            }
            None => {}
        }
        Self::restore(databases, config.executor).await
    }

    async fn restore(
        databases: OrderedDatabases,
        executor: VeraExecutor,
    ) -> Result<Self, AppError> {
        Self::check_module_root(&databases).await?;
        Self::hydrate(databases, executor).await
    }

    async fn hydrate(
        databases: OrderedDatabases,
        executor: VeraExecutor,
    ) -> Result<Self, AppError> {
        let set = Self {
            databases,
            executor,
        };
        set.reload().await?;
        Ok(set)
    }

    async fn check_module_root(databases: &OrderedDatabases) -> Result<(), AppError> {
        let expected = databases.7.read().await.0;
        match expected {
            Some(root) if Self::module_root(databases).await.0 == root.0 => Ok(()),
            None if databases.committed_targets().await
                == OrderedDatabases::initial_sync_targets() =>
            {
                Ok(())
            }
            _ => Err(AppError::RootMismatch("ordered recovery module root")),
        }
    }

    async fn module_root(databases: &OrderedDatabases) -> alloy_primitives::B256 {
        vera_modules::module_state::combine_module_roots(&[
            databases.3.read().await.root().0,
            databases.4.read().await.root().0,
            databases.5.read().await.root().0,
            databases.6.read().await.root().0,
        ])
    }

    async fn reload(&self) -> Result<(), AppError> {
        let db = &self.databases;
        let native: NativeStateSet = (db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone());
        let modules = native::load_modules(&native).await?;
        self.executor.set_base_modules(modules);
        Ok(())
    }

    /// Execute and seal a branch without changing applied storage or query maps.
    pub async fn execute(
        &self,
        parent: OrderedPending,
        context: &BlockContext,
        txs: &[Tx],
    ) -> Result<(OrderedSealed, ExecutionOutcome), AppError> {
        Self::execute_on(&self.executor, parent, context, txs).await
    }

    pub(crate) async fn execute_on(
        executor: &VeraExecutor,
        parent: OrderedPending,
        context: &BlockContext,
        txs: &[Tx],
    ) -> Result<(OrderedSealed, ExecutionOutcome), AppError> {
        let (accounts, storage, code, acp, bulletin, vera, nonces, _) = parent.databases;
        // Ordered storage supplies the module commitment after execution.
        let execution_context = context.clone().with_receipt_only();
        let mut executed = execute_block(
            executor,
            (accounts, storage, code),
            &execution_context,
            txs,
            parent.modules.clone(),
        )
        .await?;
        let native = native::prepare(
            (acp, bulletin, vera, nonces),
            executed.modules.changes_from(&parent.modules),
        )
        .await?;
        executed.outcome.module_state_root = native::state_root(&native);
        if context
            .expected_module_state_root
            .is_some_and(|root| root != executed.outcome.module_state_root)
        {
            return Err(AppError::RootMismatch("ordered module state"));
        }
        let execution = executed.merkleized;
        Ok((
            OrderedSealed {
                databases: (
                    execution.0,
                    execution.1,
                    execution.2,
                    native.0,
                    native.1,
                    native.2,
                    native.3,
                    commitment::Commitment(Some(Digest::from(
                        executed.outcome.module_state_root.0,
                    ))),
                ),
                modules: executed.modules,
                height: context.header.number,
            },
            executed.outcome,
        ))
    }
}

impl DatabaseSet<Ctx> for OrderedState {
    type Unmerkleized = OrderedPending;
    type Merkleized = OrderedSealed;
    type Readers = <OrderedDatabases as DatabaseSet<Ctx>>::Readers;
    type Config = OrderedConfig;
    type SyncTargets = OrderedTargets;

    async fn init(
        context: Ctx,
        mut config: Self::Config,
        expected: Option<Self::SyncTargets>,
    ) -> Self {
        if config.marshal_recovery {
            assert!(
                config.executor.module_trees().is_none(),
                "ordered storage cannot attach JMT trees"
            );
            let databases =
                Box::pin(OrderedDatabases::init(context, config.databases, expected)).await;
            return Self::restore(databases, config.executor)
                .await
                .expect("restore authenticated module state");
        }
        if let Some(expected) = expected {
            if let Some(configured) = &config.recovery {
                assert_eq!(
                    configured, &expected,
                    "conflicting ordered recovery targets"
                );
            }
            config.recovery = Some(expected);
        }
        Box::pin(Self::open(context, config))
            .await
            .expect("recover ordered module state")
    }

    fn initial_sync_targets() -> Self::SyncTargets {
        OrderedDatabases::initial_sync_targets()
    }

    async fn new_batches(&self) -> OrderedPending {
        OrderedPending {
            databases: self.databases.new_batches().await,
            modules: self
                .executor
                .snapshot()
                .expect("capture ordered module state"),
        }
    }

    fn fork_batches(parent: &OrderedSealed) -> OrderedPending {
        OrderedPending {
            databases: OrderedDatabases::fork_batches(&parent.databases),
            modules: parent.modules.clone(),
        }
    }

    fn matches_sync_targets(batches: &OrderedSealed, targets: &Self::SyncTargets) -> bool {
        OrderedDatabases::matches_sync_targets(&batches.databases, targets)
    }

    fn readers(&self) -> Self::Readers {
        self.databases.readers()
    }

    async fn apply(&self, batches: OrderedSealed) {
        let started = (tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
            || tracing::enabled!(target: "vera_publication_diagnostics", tracing::Level::DEBUG))
        .then(std::time::Instant::now);
        #[cfg(feature = "fault-injection")]
        let changed = batches
            .modules
            .changes_from(&self.executor.snapshot().expect("capture committed modules"))
            .iter()
            .any(|changes| !changes.is_empty());
        #[cfg(feature = "fault-injection")]
        Box::pin(self.apply_with_faults(batches.databases, batches.height, changed)).await;
        #[cfg(not(feature = "fault-injection"))]
        Box::pin(self.databases.apply(batches.databases)).await;
        let applied = started.map(|started| started.elapsed());
        self.executor
            .commit_snapshot(batches.height, batches.modules)
            .expect("publish applied module state");
        if let Some((started, applied)) = started.zip(applied) {
            let publication = started.elapsed() - applied;
            tracing::debug!(target: "vera_diagnostics", height = batches.height,
                database_apply_us = applied.as_micros(),
                publication_us = publication.as_micros(),
                "finalized state apply");
            tracing::debug!(target: "vera_publication_diagnostics", height = batches.height,
                database_apply_us = applied.as_micros(),
                publication_us = publication.as_micros(),
                "finalized state apply");
        }
    }

    async fn finalize(&self) -> Barrier {
        let started = tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
            .then(std::time::Instant::now);
        let barrier = Box::pin(self.databases.finalize()).await;
        if let Some(started) = started {
            tracing::debug!(target: "vera_diagnostics", sync_start_us = started.elapsed().as_micros(),
                "finalized state synchronization started");
        }
        barrier
    }

    async fn prune(&self, targets: &Self::SyncTargets) {
        self.databases.prune(targets).await;
        tracing::info!(target: "vera_storage", "pruned state journals");
    }

    async fn committed_targets(&self) -> Self::SyncTargets {
        self.databases.committed_targets().await
    }
}

impl<R: Send + 'static> StateSyncSet<Ctx, R, Digest> for OrderedState
where
    OrderedDatabases: StateSyncSet<Ctx, R, Digest, Error = String>,
{
    type Error = String;

    async fn sync(
        context: Ctx,
        config: Self::Config,
        sources: R,
        anchor: Anchor<Digest>,
        targets: Self::SyncTargets,
        tip_updates: ring::Receiver<TipUpdate<Digest, Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> Result<(Self, Anchor<Digest>), String> {
        if config.executor.module_trees().is_some() {
            return Err("ordered storage cannot attach JMT trees".into());
        }
        tracing::debug!(target: "vera_diagnostics", height = %anchor.height,
            "snapshot database transfer started");
        let (databases, anchor) = Box::pin(OrderedDatabases::sync(
            context,
            config.databases,
            sources,
            anchor,
            targets,
            tip_updates,
            sync_config,
        ))
        .await?;
        tracing::debug!(target: "vera_diagnostics", height = %anchor.height,
            "snapshot database transfer completed");
        Self::check_module_root(&databases)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(handoff) = config.sync_handoff {
            tracing::debug!(target: "vera_diagnostics", height = %anchor.height,
                "snapshot history handoff started");
            handoff(anchor).await?;
            tracing::debug!(target: "vera_diagnostics", height = %anchor.height,
                "snapshot history handoff completed");
        }
        let state = Self::hydrate(databases, config.executor)
            .await
            .map_err(|e| e.to_string())?;
        tracing::debug!(target: "vera_diagnostics", height = %anchor.height,
            "snapshot query state hydrated");
        Ok((state, anchor))
    }
}

impl<R0, R1, R2, R3, R4, R5, R6> AttachableResolverSet<OrderedState>
    for (R0, R1, R2, R3, R4, R5, R6, ())
where
    Self: AttachableResolverSet<OrderedDatabases>,
{
    async fn attach_databases(&self, state: OrderedState) {
        <Self as AttachableResolverSet<OrderedDatabases>>::attach_databases(self, state.databases)
            .await;
    }
}
