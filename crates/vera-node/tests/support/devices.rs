//! Devices of one account that can each be the deployment's active device.

use std::{path::Path, time::Duration};

use vera_client::{
    Secp256k1SigningKey,
    term::{TermCertificate, TermChange, approve_term},
};
use vera_domain::{Block, LightBlock, verify_finalized_block};
use vera_node::{
    Device, DeviceKey, EmbedError, EmbeddedConfig, EmbeddedNode, SoloDeployment, Switching,
    TermRefusal,
};

use super::{short_epochs, support::block_on};

/// One device: its directory's settings as the active device and as a backup.
pub(crate) struct Paired {
    pub key: DeviceKey,
    pub active: EmbeddedConfig,
    pub backup: EmbeddedConfig,
}

/// Settings for two devices of `deployment` that list each other. Each
/// asks the other for the term after `freshness` without a block of its own.
pub(crate) fn pair(
    directories: [&Path; 2],
    deployment: &SoloDeployment,
    freshness: Duration,
) -> [Paired; 2] {
    devices(directories, deployment, freshness)
}

/// Settings for the devices of `deployment`, each listing every other. As a
/// backup the first follows the second, and every other device the first.
pub(crate) fn devices<const N: usize>(
    directories: [&Path; N],
    deployment: &SoloDeployment,
    freshness: Duration,
) -> [Paired; N] {
    let keys = [(); N].map(|()| DeviceKey::generate().unwrap());
    let addresses =
        directories.map(|directory| short_epochs::settings(directory, deployment, true).p2p_listen);
    std::array::from_fn(|this| {
        let others = (0..N)
            .filter(|other| *other != this)
            .map(|other| Device {
                key: keys[other].public_key(),
                address: addresses[other],
            })
            .collect();
        let mut switching = Switching::new(keys[this].clone(), others);
        switching.freshness = freshness;
        let mut active = short_epochs::settings(directories[this], deployment, true);
        active.p2p_listen = addresses[this];
        active.switching = Some(switching);
        let followed = usize::from(this == 0);
        let backup = active.following(&keys[followed].public_key()).unwrap();
        Paired {
            key: keys[this].clone(),
            active,
            backup,
        }
    })
}

/// Have `device` reach the device known by `other` at `address`, as through a relay.
#[allow(dead_code, reason = "not every test that switches devices relays them")]
pub(crate) fn reach_at(device: &mut Paired, other: &DeviceKey, address: std::net::SocketAddr) {
    let switching = device.active.switching.as_mut().unwrap();
    for listed in &mut switching.devices {
        if listed.key == other.public_key() {
            listed.address = address;
        }
    }
    let followed = switching.devices[0].key.clone();
    device.backup = device.active.following(&followed).unwrap();
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

/// Hand over to `successor`. A loaded machine can take longer than the
/// handover waits for the last proposed block, which leaves the device active.
pub(crate) fn hand_over(
    node: &EmbeddedNode,
    successor: &vera_domain::PublicKey,
) -> vera_domain::TermChange {
    for _ in 0..10 {
        match block_on(node.hand_over(successor)) {
            Ok(change) => return change,
            Err(EmbedError::Term(
                TermRefusal::Unsettled | TermRefusal::SuccessorNotCurrent { .. },
            )) => std::thread::sleep(Duration::from_secs(1)),
            Err(error) => panic!("{error}"),
        }
    }
    panic!("the handover did not settle");
}

/// The change `backup` would take over with, once it has executed every
/// block it knows to be finalized. A loaded machine can leave it behind for
/// longer than one call waits.
pub(crate) fn takeover_change(backup: &EmbeddedNode) -> vera_domain::TermChange {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match block_on(backup.takeover_change()) {
            Ok(change) => return change,
            Err(EmbedError::Term(TermRefusal::NotAtCut { head, cut })) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the backup stayed at block {cut} below finalized block {head}"
                );
            }
            Err(error) => panic!("{error}"),
        }
    }
}
