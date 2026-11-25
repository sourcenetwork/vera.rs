use commonware_consensus::marshal::ancestry;
use commonware_cryptography::{Digested, Digestible as _};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::{NZU16, NZUsize};
use vera_app::ordered_state::{OrderedConfig, OrderedState, ordered_config};
use vera_backend::{Ctx, native};
use vera_domain::{Block, DbTarget};
use vera_executor::VeraExecutor;
use vera_modules::module_state::combine_module_roots;

pub(super) fn state_config(_context: &Ctx, prefix: &str, executor: VeraExecutor) -> OrderedConfig {
    let cache = CacheRef::new(NZU16!(4084), NZUsize!(128));
    ordered_config(native::state_config(prefix, cache), executor)
}

/// The genesis block over the state's committed partitions.
pub(super) async fn genesis(state: &OrderedState) -> Block {
    let committed = state.committed_targets().await;
    let native = [committed.0, committed.1, committed.2, committed.3];
    let partitions = state.native_databases();
    let [a, b, h, n] =
        native::read_partitions([&partitions.0, &partitions.1, &partitions.2, &partitions.3]).await;
    let module_root = combine_module_roots(&[a.root().0, b.root().0, h.root().0, n.root().0]);
    vera_app::genesis_block(
        module_root,
        native.each_ref().map(|target| DbTarget {
            root: target.root,
            floor: *target.range.start(),
            tip: *target.range.end(),
        }),
        vera_executor::receipt_commitment(0, &[]),
    )
}

pub(super) fn block_ancestry<const N: usize>(blocks: [Block; N]) -> impl ancestry::Ancestry<Block> {
    ancestry::from_iter(blocks.map(|block| {
        let digest = block.digest();
        Digested::precomputed(block, digest)
    }))
}
