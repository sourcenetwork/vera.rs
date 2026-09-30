use std::convert::Infallible;

use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    AttachableResolver, BatchContext, InitError, ManagedDb, Merkleized, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized,
};
use commonware_runtime::Handle;
use commonware_utils::channel::{fallible::AsyncFallibleExt as _, mpsc};
use futures::future::{Either, pending, select};
use vera_backend::Ctx;

/// The module root selected by the same coordinator generation as the seven logs.
/// This is not a database: OrderedState checks the rebuilt records against this root
/// before publishing them. Startup reconstructs the selection from its durable anchor.
#[derive(Clone, Debug)]
pub struct Commitment(pub(super) Option<Digest>);

impl Unmerkleized for Commitment {
    type Merkleized = Self;
    type Error = Infallible;
    async fn merkleize(self) -> Result<Self, Infallible> {
        Ok(self)
    }
}

impl Merkleized for Commitment {
    type Digest = Digest;
    type Unmerkleized = Self;
    fn root(&self) -> Digest {
        self.0.unwrap_or(Digest::from([0; 32]))
    }
    fn new_batch(&self) -> Self {
        self.clone()
    }
}

impl ManagedDb<Ctx> for Commitment {
    type Unmerkleized = Self;
    type Merkleized = Self;
    type Config = ();
    type SyncTarget = Option<Digest>;
    type Error = Infallible;

    async fn init(
        _: Ctx,
        _: (),
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Infallible, Self::SyncTarget>> {
        Ok(Self(expected.flatten()))
    }
    fn initial_sync_target() -> Self::SyncTarget {
        None
    }
    fn new_batch(context: BatchContext<'_, Self>) -> Self {
        context.into_parts().0.clone()
    }
    fn matches_sync_target(batch: &Self, target: &Self::SyncTarget) -> bool {
        batch.0 == *target
    }
    async fn apply(self, batch: Self) -> Result<Self, Infallible> {
        Ok(batch)
    }
    async fn finalize(self) -> Result<(Self, Handle<()>), Infallible> {
        Ok((self, Handle::ready(Ok(()))))
    }
    fn sync_target(&self) -> Self::SyncTarget {
        self.0
    }
}

impl AttachableResolver<Commitment> for () {
    async fn attach_database(&self, _: Shared<Commitment>) {}
}

impl StateSyncDb<Ctx, ()> for Commitment {
    type SyncError = Infallible;
    async fn sync_db(
        _: Ctx,
        _: (),
        _: (),
        mut target: Self::SyncTarget,
        mut updates: mpsc::Receiver<Self::SyncTarget>,
        mut finish: Option<mpsc::Receiver<()>>,
        reached: Option<mpsc::Sender<Self::SyncTarget>>,
        _: SyncEngineConfig,
    ) -> Result<Self, Infallible> {
        loop {
            if let Some(sender) = &reached {
                sender.send_lossy(target).await;
            }
            let completed = async {
                match &mut finish {
                    Some(receiver) => {
                        receiver.recv().await;
                    }
                    None => pending().await,
                }
            };
            match select(Box::pin(updates.recv()), Box::pin(completed)).await {
                Either::Left((Some(next), _)) => target = next,
                Either::Left((None, _)) | Either::Right(_) => return Ok(Self(target)),
            }
        }
    }
}
