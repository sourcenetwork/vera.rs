//! What a device needs to give the deployment to another device or take it.

use std::{net::SocketAddr, time::Duration};

use vera_domain::PublicKey;

use crate::DeviceKey;

/// One of the account's other devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// The device's transport key, which term certificates name it by.
    pub key: PublicKey,
    /// Where its consensus listener is reached while it is the active device.
    pub address: SocketAddr,
}

/// The account's devices, as one of them sees them.
///
/// With this set, a device can hand the deployment over, take it over with a
/// term certificate, and follow the device that holds a later term.
#[derive(Clone, Debug)]
pub struct Switching {
    /// This device's transport key: its name in term certificates and its
    /// network key while it is a backup.
    pub device_key: DeviceKey,
    /// The account's other devices. The active device admits each as a backup.
    pub devices: Vec<Device>,
    /// Longest the active device waits for a successor to confirm it holds
    /// the final block of a handover, and a backup for the cut of a takeover.
    pub answer_timeout: Duration,
}

impl Switching {
    /// Default wait for another device's answer.
    pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);

    /// Defaults for a device that knows `devices` under `device_key`.
    #[must_use]
    pub const fn new(device_key: DeviceKey, devices: Vec<Device>) -> Self {
        Self {
            device_key,
            devices,
            answer_timeout: Self::ANSWER_TIMEOUT,
        }
    }

    pub(crate) fn device(&self, key: &PublicKey) -> Option<&Device> {
        self.devices.iter().find(|device| device.key == *key)
    }
}
