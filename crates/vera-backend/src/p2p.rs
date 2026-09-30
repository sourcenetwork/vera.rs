use bytes::BufMut;
use commonware_codec::{Codec, EncodeSize, Error, RangeCfg, Read, Write};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{AttachableResolver, Shared, p2p};
use commonware_storage::{
    merkle::mmr,
    qmdb::{
        self,
        sync::{Feedback, Request, Response, ServeError, Source, source},
    },
};
use commonware_utils::NZU64;
use std::num::NonZeroU64;

use crate::{AccountsDb, CodeDb, StorageDb, native::NativeDb};

/// A persisted partition with a bounded operation codec for peer messages.
pub trait Partition:
    Source<
        Family = mmr::Family,
        Digest = Digest,
        Error = qmdb::Error<mmr::Family>,
        Op: Codec + Clone + std::fmt::Debug + Send + Sync,
    > + Sized
    + 'static
{
    /// Decode limits for one operation, including commit metadata.
    fn operation_config() -> <Self::Op as Read>::Cfg;

    /// Servable journal span: items below `start` are pruned.
    fn bounds(&self) -> std::ops::Range<commonware_storage::merkle::Location<mmr::Family>>;

    /// Reject local records that cannot be decoded by a peer.
    fn accepts(operation: &Self::Op) -> bool;
}

impl Partition for NativeDb {
    fn bounds(&self) -> std::ops::Range<commonware_storage::merkle::Location<mmr::Family>> {
        self.bounds()
    }
    fn operation_config() -> <Self::Op as Read>::Cfg {
        crate::native::operation_config()
    }
    fn accepts(operation: &Self::Op) -> bool {
        use crate::native::{MAX_KEY_BYTES, MAX_VALUE_BYTES};
        use commonware_storage::qmdb::any::operation::Operation;
        match operation {
            Operation::Update(record) => {
                record.key.len() <= MAX_KEY_BYTES
                    && record.next_key.len() <= MAX_KEY_BYTES
                    && record.value.len() <= MAX_VALUE_BYTES
            }
            Operation::Delete(key) => key.len() <= MAX_KEY_BYTES,
            Operation::CommitFloor(metadata, _) => {
                metadata.as_ref().is_none_or(|v| v.len() <= MAX_VALUE_BYTES)
            }
        }
    }
}

impl Partition for AccountsDb {
    fn bounds(&self) -> std::ops::Range<commonware_storage::merkle::Location<mmr::Family>> {
        self.bounds()
    }
    fn operation_config() -> <Self::Op as Read>::Cfg {
        ((), ())
    }
    fn accepts(_: &Self::Op) -> bool {
        true
    }
}

impl Partition for StorageDb {
    fn bounds(&self) -> std::ops::Range<commonware_storage::merkle::Location<mmr::Family>> {
        self.bounds()
    }
    fn operation_config() -> <Self::Op as Read>::Cfg {
        ((), ())
    }
    fn accepts(_: &Self::Op) -> bool {
        true
    }
}

/// Maximum bytecode or code-partition commit metadata accepted over peer transport.
/// Existing local journals retain their original decoding configuration.
pub const MAX_CODE_BYTES: usize = 1 << 20;

impl Partition for CodeDb {
    fn bounds(&self) -> std::ops::Range<commonware_storage::merkle::Location<mmr::Family>> {
        self.bounds()
    }
    fn operation_config() -> <Self::Op as Read>::Cfg {
        ((), (RangeCfg::new(0..=MAX_CODE_BYTES), ()))
    }
    fn accepts(operation: &Self::Op) -> bool {
        use commonware_storage::qmdb::any::operation::Operation;
        match operation {
            Operation::Update(record) => record.1.len() <= MAX_CODE_BYTES,
            Operation::CommitFloor(metadata, _) => {
                metadata.as_ref().is_none_or(|v| v.len() <= MAX_CODE_BYTES)
            }
            Operation::Delete(_) => true,
        }
    }
}

mod serve;

/// Maximum operation count requested or served by a partition resolver.
pub const MAX_FETCH_OPS: NonZeroU64 = NZU64!(64);
/// Required network message limit, including the resolver's framing.
pub const MAX_MESSAGE_BYTES: u32 = 4 * 1024 * 1024;
/// Response payload budget, leaving room for the resolver's framing.
pub const MAX_RESPONSE_BYTES: usize = MAX_MESSAGE_BYTES as usize - 1024;

/// Persisted operation bytes decoded with the partition's peer limits.
pub struct WireOperation<DB: Partition>(pub(crate) DB::Op);

impl<DB: Partition> Clone for WireOperation<DB> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<DB: Partition> std::fmt::Debug for WireOperation<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<DB: Partition> Write for WireOperation<DB> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<DB: Partition> EncodeSize for WireOperation<DB> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<DB: Partition> Read for WireOperation<DB> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl commonware_codec::Buf, (): &()) -> Result<Self, Error> {
        DB::Op::read_cfg(buf, &DB::operation_config()).map(Self)
    }
}

/// Serving handle for Commonware's peer resolver actor.
pub struct WireDatabase<DB: Partition>(Shared<DB>);

impl<DB: Partition> std::fmt::Debug for WireDatabase<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireDatabase").finish_non_exhaustive()
    }
}

impl<DB: Partition> WireDatabase<DB> {
    /// Wrap an existing database; serving retains its read lock through proof generation.
    pub fn new(db: Shared<DB>) -> Shared<Self> {
        Shared::new("partition_resolver", Self(db))
    }
}

impl<DB: Partition> Source for WireDatabase<DB> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = WireOperation<DB>;
    type Error = ServeError<mmr::Family>;

    async fn serve(&self, request: Request<Self::Family>) -> source::Result<Self> {
        let db = self.0.read().await;
        let request = bounded(request);
        let response = match serve::response(&*db, request).await {
            Ok(response) => response,
            Err(error) => {
                let bounds = db.bounds();
                if matches!(
                    &error,
                    commonware_storage::qmdb::Error::Journal(
                        commonware_storage::journal::Error::ItemPruned(_)
                    )
                ) {
                    tracing::debug!(
                        ?request,
                        frontier = *bounds.start,
                        tip = *bounds.end,
                        "qmdb serve pruned"
                    );
                    return Ok((
                        Response::Pruned {
                            frontier: bounds.start,
                        },
                        None,
                    ));
                }
                tracing::warn!(
                    ?request,
                    ?error,
                    frontier = *bounds.start,
                    tip = *bounds.end,
                    "qmdb serve rejected"
                );
                return Err(ServeError::Database(error));
            }
        };
        Ok((map(response, WireOperation), None))
    }
}

/// Commonware mailbox whose operation codec applies partition record limits.
pub type WireMailbox<DB> = p2p::Mailbox<WireDatabase<DB>, mmr::Family, WireOperation<DB>, Digest>;

/// Partition sync source retaining Commonware's retries, cancellation and validation feedback.
pub struct Resolver<DB: Partition>(WireMailbox<DB>);

impl<DB: Partition> Clone for Resolver<DB> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<DB: Partition> std::fmt::Debug for Resolver<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl<DB: Partition> Resolver<DB> {
    /// Use an actor configured to serve at least [`MAX_FETCH_OPS`] operations per response.
    /// Its network must enforce [`MAX_MESSAGE_BYTES`] and a bounded receive backlog.
    pub const fn new(mailbox: WireMailbox<DB>) -> Self {
        Self(mailbox)
    }
}

impl<DB: Partition> Source for Resolver<DB> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = DB::Op;
    type Error = p2p::ResponseDropped;

    async fn serve(&self, request: Request<Self::Family>) -> source::Result<Self> {
        let (response, feedback) = self.0.serve(bounded(request)).await?;
        Ok((
            map(response, |op| op.0),
            feedback.map(translate_feedback::<DB>),
        ))
    }
}

fn translate_feedback<DB: Partition>(
    feedback: Feedback<Response<mmr::Family, WireOperation<DB>, Digest>>,
) -> Feedback<Response<mmr::Family, DB::Op, Digest>> {
    use commonware_utils::channel::{mpsc, oneshot};

    let (verdict, mut verdict_rx) = oneshot::channel();
    let (translated, receiver) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut feedback = feedback;
        loop {
            match verdict_rx.await {
                Ok(true) => {
                    feedback.accept();
                    break;
                }
                Ok(false) => {}
                Err(_) => break,
            }
            // Closing the translated request must also cancel a pending retry.
            let next = tokio::select! {
                () = translated.closed() => break,
                next = feedback.reject() => next,
            };
            let Some((response, next_feedback)) = next else {
                break;
            };
            let (verdict, next_verdict_rx) = oneshot::channel();
            if translated
                .send((map(response, |op| op.0), verdict))
                .await
                .is_err()
            {
                break;
            }
            feedback = next_feedback;
            verdict_rx = next_verdict_rx;
        }
    });
    Feedback::new(verdict, receiver)
}

impl<DB: Partition> AttachableResolver<DB> for Resolver<DB> {
    async fn attach_database(&self, db: Shared<DB>) {
        self.0.attach_database(WireDatabase::new(db));
    }
}

fn bounded(mut request: Request<mmr::Family>) -> Request<mmr::Family> {
    if let Request::Operations { max_ops, .. } = &mut request {
        *max_ops = (*max_ops).min(MAX_FETCH_OPS);
    }
    request
}

fn map<A, B>(
    response: Response<mmr::Family, A, Digest>,
    convert: impl Fn(A) -> B,
) -> Response<mmr::Family, B, Digest> {
    match response {
        Response::Operations { proof, operations } => Response::Operations {
            proof,
            operations: operations.into_iter().map(convert).collect(),
        },
        Response::Pruned { frontier } => Response::Pruned { frontier },
        Response::Boundary {
            proof,
            op,
            pinned_nodes,
        } => Response::Boundary {
            proof,
            op: convert(op),
            pinned_nodes,
        },
    }
}

#[cfg(test)]
mod tests;
