//! Two devices of one account that can each be the deployment's active device.

use std::path::Path;

use vera_client::{
    Secp256k1SigningKey,
    term::{TermCertificate, TermChange, approve_term},
};
use vera_domain::{Block, LightBlock, verify_finalized_block};
use vera_node::{Device, DeviceKey, EmbeddedConfig, EmbeddedNode, SoloDeployment, Switching};

use super::{short_epochs, support::block_on};

/// One device: its directory's settings as the active device and as a backup.
pub(crate) struct Paired {
    pub key: DeviceKey,
    pub active: EmbeddedConfig,
    pub backup: EmbeddedConfig,
}

/// Settings for two devices of `deployment` that list each other.
pub(crate) fn pair(directories: [&Path; 2], deployment: &SoloDeployment) -> [Paired; 2] {
    let keys = [(); 2].map(|()| DeviceKey::generate().unwrap());
    let addresses =
        directories.map(|directory| short_epochs::settings(directory, deployment, true).p2p_listen);
    [0, 1].map(|this| {
        let other = 1 - this;
        let switching = Switching::new(
            keys[this].clone(),
            vec![Device {
                key: keys[other].public_key(),
                address: addresses[other],
            }],
        );
        let mut active = short_epochs::settings(directories[this], deployment, true);
        active.p2p_listen = addresses[this];
        active.switching = Some(switching);
        let backup = active.following(&keys[other].public_key()).unwrap();
        Paired {
            key: keys[this].clone(),
            active,
            backup,
        }
    })
}

/// Approve `change` as the deployment's only operator, whose secret key is 1.
pub(crate) fn certify(change: TermChange) -> TermCertificate {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let key = Secp256k1SigningKey::from_bytes((&secret).into()).unwrap();
    TermCertificate {
        change,
        approvals: vec![approve_term(&change, 0, &key).unwrap()],
    }
}

/// The finalized block at `height`, verified against the deployment's consensus key.
pub(crate) fn block(node: &EmbeddedNode, height: u64) -> Block {
    let proof: LightBlock = block_on(node.rpc().request(
        "vera_getLightBlock",
        vec![serde_json::json!(format!("0x{height:x}"))],
    ))
    .unwrap();
    verify_finalized_block(&proof, node.consensus_key()).unwrap()
}
