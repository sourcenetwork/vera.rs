//! What the consensus archive holds above a block a term may build on.

use commonware_consensus::{
    marshal::{
        Identifier,
        core::{Mailbox, Variant},
    },
    simplex::scheme::Scheme,
    types::Height,
};

pub(crate) use super::actor::Archived;

/// What marshal holds as finalized at `height`.
///
/// Marshal stores a block and its finalization certificate separately, and
/// a node stopped between the two keeps a certificate without its block.
pub(crate) async fn archived<S, V>(marshal: Mailbox<S, V>, height: u64) -> Archived
where
    V: Variant,
    S: Scheme<V::Commitment>,
{
    let height = Height::new(height);
    if marshal
        .get_block(Identifier::Height(height))
        .await
        .is_some()
    {
        Archived::Block
    } else if marshal.get_finalization(height).await.is_some() {
        Archived::Certificate
    } else {
        Archived::Nothing
    }
}
