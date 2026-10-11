use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::{NZU16, NZUsize};
use vera_app::ordered_state::{OrderedConfig, OrderedState, ordered_config};
use vera_backend::{Ctx, native, state_set_config};
use vera_domain::{Block, DbTarget};
use vera_executor::VeraExecutor;
use vera_genesis::GenesisState;
use vera_modules::module_state::combine_module_roots;

pub(super) fn state_config(context: &Ctx, prefix: &str, executor: VeraExecutor) -> OrderedConfig {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(128));
    ordered_config(
        state_set_config(prefix, cache.clone()),
        native::state_config(prefix, cache),
        executor,
    )
}

pub(super) async fn genesis(state: &OrderedState, allocation: &GenesisState) -> Block {
    let (root, targets) = vera_app::apply_genesis(&state.execution_databases(), allocation)
        .await
        .expect("initialize execution genesis");
    let committed = state.committed_targets().await;
    let native = [committed.3, committed.4, committed.5, committed.6];
    let partitions = state.native_databases();
    let [a, b, h, n] =
        native::read_partitions([&partitions.0, &partitions.1, &partitions.2, &partitions.3]).await;
    let module_root = combine_module_roots(&[a.root().0, b.root().0, h.root().0, n.root().0]);
    let mut block = vera_app::genesis_block(root, targets, module_root);
    block.native_targets = Some(native.each_ref().map(|target| DbTarget {
        root: target.root,
        floor: *target.range.start(),
        tip: *target.range.end(),
    }));
    block.receipt_commitment = Some(vera_executor::receipt_commitment(0, &[]));
    block
}
