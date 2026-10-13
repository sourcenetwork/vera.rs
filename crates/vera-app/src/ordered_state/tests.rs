use super::*;

use std::{sync::Arc, time::Duration};

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZU64, NZUsize};
use vera_backend::state_set_config;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_modules::acp::abi::IAcp;

mod application;
mod checkpoint;
mod peer_sync;
mod permission;
mod record;
mod recovery;
mod sync;

const DEPLOYMENT: u64 = 9001;

fn config(
    context: &Ctx,
    prefix: &str,
    executor: VeraExecutor,
) -> <OrderedState as DatabaseSet<Ctx>>::Config {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(128));
    ordered_config(
        state_set_config(prefix, cache.clone()),
        native::state_config(prefix, cache),
        executor,
    )
}

type Sources = (
    Shared<AccountsDb>,
    Shared<StorageDb>,
    Shared<CodeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    (),
);

fn sources(state: &OrderedState) -> Sources {
    let db = &state.databases;
    (
        db.0.clone(),
        db.1.clone(),
        db.2.clone(),
        db.3.clone(),
        db.4.clone(),
        db.5.clone(),
        db.6.clone(),
        (),
    )
}

fn block(height: u64) -> BlockContext {
    BlockContext::new(
        Header {
            number: height,
            timestamp: 1000 + height,
            gas_limit: 30_000_000,
            ..Header::default()
        },
        B256::ZERO,
        B256::ZERO,
    )
}

fn anchor(height: u64) -> Anchor<Digest> {
    Anchor {
        height: Height::new(height),
        round: Round::new(Epoch::new(0), View::new(height)),
        digest: Digest::from([1; 32]),
    }
}

fn policy(signer: &BlsSigner, name: &str) -> Tx {
    Tx::new(
        signer
            .sign_native_tx(
                ACP_ADDRESS,
                IAcp::createPolicyCall {
                    policy: format!("name: {name}\nresources:\n  - name: file\n")
                        .into_bytes()
                        .into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
            )
            .unwrap()
            .into(),
    )
}
