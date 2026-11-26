mod chain;
mod fork;
mod history;
mod order;
mod registration;
mod term;

use alloy_primitives::B256;

use super::*;
use crate::types::Timestamp;

fn context(height: u64) -> BlockExecCtx {
    BlockExecCtx {
        timestamp: Timestamp {
            seconds: 1_800_000_000,
            block_height: height,
        },
        ..BlockExecCtx::default()
    }
}

fn key(seed: u8) -> Vec<u8> {
    vec![seed; CONSENSUS_KEY_BYTES]
}

const OPERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SUBMITTER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn registration(key: &[u8]) -> DeploymentRegistration {
    DeploymentRegistration {
        consensus_key: hex::encode(key),
        genesis_id: [7; 32],
        operators: crate::vera::administration::OperatorPolicy {
            threshold: 1,
            keys: vec![OPERATOR.into()],
        },
    }
}

/// A module in which the deployments with these keys are registered.
fn registered(keys: &[&[u8]]) -> VeraModule {
    let mut module = VeraModule::new();
    for key in keys {
        module.register_deployment(&registration(key), 100).unwrap();
    }
    module
}

fn revision(height: u64, term: u64, root: u8) -> VerifiedRevision {
    VerifiedRevision {
        height,
        block_hash: B256::repeat_byte(root),
        term,
        timestamp: 1_700_000_000 + height,
        module_state_root: B256::repeat_byte(root),
        ancestor: None,
    }
}

/// A revision the caller proved to descend from the block `ancestor` at `from`.
fn descendant(height: u64, term: u64, root: u8, from: u64, ancestor: u8) -> VerifiedRevision {
    VerifiedRevision {
        ancestor: Some((from, B256::repeat_byte(ancestor))),
        ..revision(height, term, root)
    }
}
