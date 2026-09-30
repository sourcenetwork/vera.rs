//! Drive the marshal floor so configured retention actually prunes finalized history.

use commonware_consensus::marshal::core::Mailbox;
use commonware_glue::stateful::PruneConfig;
use std::time::Duration;

/// Poll cadence for floor maintenance. The interval in the pruning
/// configuration counts finalized revisions, not wall time; this cadence only
/// bounds how far behind the maintenance lag can drift while idle.
const TICK: Duration = Duration::from_secs(5);

/// Advance the marshal floor to `processed_height - retained`, which lets the
/// actor prune finalized blocks and finalizations below the new floor.
pub(crate) type VeraMarshal = Mailbox<
    vera_app::ConsensusScheme,
    commonware_consensus::marshal::standard::Standard<vera_domain::Block>,
>;

pub(crate) async fn run<E: commonware_runtime::Clock>(
    context: E,
    marshal: VeraMarshal,
    pruning: PruneConfig,
) {
    let retention = pruning.retained_marshal_blocks as u64;
    let mut maintained = 0u64;
    loop {
        context.sleep(TICK).await;
        let Some(processed) = marshal
            .get_processed()
            .await
            .map(|processed| processed.height())
            .map(|h| h.get())
        else {
            continue;
        };
        let Some(target) = processed.checked_sub(retention) else {
            continue;
        };
        if target <= maintained {
            continue;
        }
        let Some(finalization) = marshal
            .get_finalization(commonware_consensus::types::Height::new(target))
            .await
        else {
            continue;
        };
        marshal.set_floor(finalization);
        maintained = target;
    }
}
