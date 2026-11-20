//! Running the part of a test that is killed in a child process.
//!
//! The child is this test binary, started again for one test alone with
//! `VERA_CRASH_SPEC` naming the scenario. A crash point named in the data
//! directory's `crash-at` aborts the child there; the parent then starts
//! the same directories in process.

use std::{
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde::{Deserialize, Serialize};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::TermCertificate;
use vera_modules::acp::abi::IAcp;
use vera_node::{DeviceKey, EmbeddedConfig, EmbeddedNode, SoloDeployment, SoloKeys};

use super::{
    devices::{self, Paired},
    short_epochs,
    support::{self, await_certified_receipt, block_on, finalize_a_write},
};

pub(crate) const SPEC: &str = "VERA_CRASH_SPEC";
const CRASH_AT: &str = "crash-at";
pub(crate) const MODULE_COMMIT: &str = "module-commit";
const FRESHNESS: Duration = Duration::from_secs(2);

/// What a child needs to rebuild the parent's settings.
#[derive(Serialize, Deserialize)]
pub(crate) struct Spec {
    pub(crate) directories: Vec<PathBuf>,
    pub(crate) chain_id: u64,
    pub(crate) timestamp: u64,
    pub(crate) listens: Vec<SocketAddr>,
    pub(crate) record: Vec<u8>,
    pub(crate) validator: Vec<u8>,
    pub(crate) share: Vec<u8>,
    pub(crate) devices: Vec<Vec<u8>>,
    pub(crate) witness: PathBuf,
}

/// What a child saw before it was killed, one entry per line.
#[derive(Serialize, Deserialize)]
pub(crate) struct Seen {
    pub(crate) label: String,
    pub(crate) submission: Option<B256>,
    pub(crate) request: Option<String>,
    pub(crate) certificate: Option<TermCertificate>,
}

impl Spec {
    /// A scenario of `count` devices of a deployment of short epochs.
    pub(crate) fn new(scratch: &Path, count: usize, chain_id: u64, seed: u64) -> Self {
        let dealt = short_epochs::deployment(chain_id, seed);
        let directories: Vec<PathBuf> = (0..count)
            .map(|index| {
                let directory = scratch.join(format!("device-{index}"));
                std::fs::create_dir_all(&directory).unwrap();
                directory
            })
            .collect();
        let listens = (0..count)
            .map(|_| {
                std::net::TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
            })
            .collect();
        Self {
            directories,
            chain_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            listens,
            record: dealt.record().to_vec(),
            validator: dealt.keys().validator_key().to_vec(),
            share: dealt.keys().share().to_vec(),
            devices: (0..count)
                .map(|_| DeviceKey::generate().unwrap().encode().to_vec())
                .collect(),
            witness: scratch.join("witness"),
        }
    }

    pub(crate) fn deployment(&self) -> SoloDeployment {
        SoloDeployment::new(
            self.record.clone(),
            SoloKeys::decode(&self.validator, &self.share).unwrap(),
        )
    }

    pub(crate) fn device_key(&self, index: usize) -> DeviceKey {
        DeviceKey::decode(&self.devices[index]).unwrap()
    }

    /// The first device as a deployment that keeps its keys in files.
    pub(crate) fn in_files(&self) -> EmbeddedConfig {
        let mut config = support::config(&self.directories[0], self.chain_id);
        config.genesis.timestamp = self.timestamp;
        config.p2p_listen = self.listens[0];
        config
    }

    /// The first device as the validator of the dealt deployment, which the host holds.
    pub(crate) fn adopted(&self) -> EmbeddedConfig {
        let mut config = short_epochs::settings(&self.directories[0], &self.deployment(), true);
        config.p2p_listen = self.listens[0];
        config
    }

    /// Two devices that switch, as `devices::pair` lays them out.
    pub(crate) fn pair(&self) -> [Paired; 2] {
        devices::devices_with(
            [&self.directories[0], &self.directories[1]].map(PathBuf::as_path),
            &self.deployment(),
            FRESHNESS,
            [self.device_key(0), self.device_key(1)],
            [self.listens[0], self.listens[1]],
        )
    }

    pub(crate) fn signer(&self, seed: u64) -> BlsSigner {
        BlsSigner::new(seed.into(), self.chain_id).unwrap()
    }

    /// Record what the child saw, durably, before it is killed.
    pub(crate) fn note(&self, seen: &Seen) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.witness)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(seen).unwrap()).unwrap();
        file.sync_all().unwrap();
    }

    pub(crate) fn seen(&self, label: &str) -> Seen {
        let lines = std::fs::read_to_string(&self.witness).unwrap();
        let mut matching = lines
            .lines()
            .map(|line| serde_json::from_str::<Seen>(line).unwrap())
            .filter(|seen| seen.label == label);
        let seen = matching
            .next()
            .unwrap_or_else(|| panic!("no {label} noted"));
        assert!(matching.next().is_none(), "{label} noted twice");
        seen
    }

    /// Run `test` in a child process that must be killed at `point`, named
    /// in `directory`.
    pub(crate) fn crash(&self, test: &str, directory: &Path, point: &str) {
        let path = self.witness.with_extension("spec");
        std::fs::write(&path, serde_json::to_vec(self).unwrap()).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(SPEC, &path)
            .env("VERA_CRASH_POINT", point)
            .env("VERA_CRASH_DIRECTORY", directory)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(600);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the child running {test} did not stop");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(!status.success(), "the child running {test} was not killed");
        assert_ne!(
            status.code(),
            Some(3),
            "{test} passed {point} without stopping"
        );
        assert_eq!(
            std::fs::read_to_string(directory.join("crash-at.hit")).unwrap(),
            point,
            "the child running {test} was killed elsewhere: {status}"
        );
        std::fs::remove_file(directory.join("crash-at.hit")).unwrap();
    }
}

/// The scenario this process runs as a child, if it is one.
pub(crate) fn child() -> Option<Spec> {
    let path = std::env::var_os(SPEC)?;
    Some(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
}

/// Arm the crash point the parent chose. The child must not get past it.
pub(crate) fn arm() {
    let directory = PathBuf::from(std::env::var_os("VERA_CRASH_DIRECTORY").unwrap());
    let point = std::env::var("VERA_CRASH_POINT").unwrap();
    if point == MODULE_COMMIT {
        // The daemon's crash point after a module journal commits, which
        // takes the module's index: ACP is committed, the others are not.
        std::fs::write(directory.join("module-commit-crash"), "0").unwrap();
    } else {
        std::fs::write(directory.join(CRASH_AT), point).unwrap();
    }
}

pub(crate) fn survived() -> ! {
    std::process::exit(3)
}

/// Submit a policy creation and note its submission and signed request.
pub(crate) fn submit(node: &EmbeddedNode, spec: &Spec, signer: &BlsSigner, label: &str) -> B256 {
    let call = IAcp::createPolicyCall {
        policy: format!("name: {label}\nresources: []\n")
            .into_bytes()
            .into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
    };
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let request = format!("0x{}", hex::encode(wire));
    let submission: B256 = block_on(
        node.rpc()
            .request("vera_sendNativeTx", vec![serde_json::json!(request)]),
    )
    .unwrap();
    spec.note(&Seen {
        label: label.into(),
        submission: Some(submission),
        request: Some(request),
        certificate: None,
    });
    submission
}

/// Note a request the child saw finalized.
pub(crate) fn note_written(spec: &Spec, label: &str, submission: B256) {
    spec.note(&Seen {
        label: label.into(),
        submission: Some(submission),
        request: None,
        certificate: None,
    });
}

pub(crate) fn nonce(node: &EmbeddedNode, signer: &BlsSigner) -> u64 {
    let next: alloy_primitives::U64 = block_on(
        node.rpc()
            .request("vera_getNativeNonce", vec![serde_json::json!(signer.did())]),
    )
    .unwrap();
    next.to::<u64>()
}

/// The request the child submitted before it was killed finalized once: its
/// receipt verifies, its signer's sequence moved past it once, and sending
/// it again executes nothing.
pub(crate) fn finalized_once(node: &EmbeddedNode, seen: &Seen, signer: &BlsSigner) {
    let submission = seen.submission.unwrap();
    await_certified_receipt(node, submission);
    assert_eq!(nonce(node, signer), 1);
    let again: Result<B256, _> = block_on(node.rpc().request(
        "vera_sendNativeTx",
        vec![serde_json::json!(seen.request.as_ref().unwrap())],
    ));
    assert!(again.is_err(), "a finalized request was admitted again");
    signer.set_next_sequence(1);
    let next = finalize_a_write(node, signer);
    assert_ne!(next, submission);
    assert_eq!(nonce(node, signer), 2);
}

impl Spec {
    /// Like [`Self::crash`], at the module crash point the daemon's tests use.
    pub(crate) fn crash_module(&self, test: &str, directory: &Path) {
        let path = self.witness.with_extension("spec");
        std::fs::write(&path, serde_json::to_vec(self).unwrap()).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(SPEC, &path)
            .env("VERA_CRASH_POINT", MODULE_COMMIT)
            .env("VERA_CRASH_DIRECTORY", directory)
            .status()
            .unwrap();
        assert!(!status.success());
        assert_ne!(status.code(), Some(3), "{test} was not killed");
        let hit = std::fs::read_to_string(directory.join("module-commit-crash.hit")).unwrap();
        assert!(hit.trim().ends_with(" 0"), "killed after module {hit}");
    }
}
