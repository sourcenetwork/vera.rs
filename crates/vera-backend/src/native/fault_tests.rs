//! Native-partition recovery under injected storage I/O failures.
//!
//! A failed or torn write during finalization is fatal to the actor by
//! design: glue panics rather than acknowledging a revision that is not
//! durable. Each failure mode runs in a child process that is expected to
//! die with that panic. The child records its last durable targets in a
//! sidecar before arming the failure; the parent then opens storage at that
//! anchor and verifies the failed revision republishes.

use super::{
    faulty_ctx::{Failure, FaultyCtx},
    state_config,
};
use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Sha256, sha256};
use commonware_glue::stateful::db::{DatabaseSet as _, Reader, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::merkle::mmr;
use commonware_utils::{NZU16, NZUsize};

type FaultyDb = commonware_storage::qmdb::current::ordered::variable::Db<
    mmr::Family,
    FaultyCtx,
    Vec<u8>,
    Bytes,
    Sha256,
    super::KeyPrefix,
    32,
    Sequential,
>;

type FaultySet = (
    Shared<FaultyDb>,
    Shared<FaultyDb>,
    Shared<FaultyDb>,
    Shared<FaultyDb>,
);

type FaultyReaders = (
    Reader<FaultyDb>,
    Reader<FaultyDb>,
    Reader<FaultyDb>,
    Reader<FaultyDb>,
);

type FaultyTarget = commonware_storage::qmdb::sync::Target<mmr::Family, sha256::Digest>;

type FaultyTargets = (FaultyTarget, FaultyTarget, FaultyTarget, FaultyTarget);

fn failed_reader(readers: &FaultyReaders, module: usize) -> &Reader<FaultyDb> {
    match module {
        0 => &readers.0,
        1 => &readers.1,
        2 => &readers.2,
        3 => &readers.3,
        _ => panic!("invalid native fault partition"),
    }
}

async fn open(context: &FaultyCtx) -> FaultySet {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(64));
    FaultySet::init(context.child("native"), state_config("fault", cache), None).await
}

fn changes(module: usize, revision: u8) -> vera_modules::module_state::ModuleChanges {
    std::array::from_fn(|index| {
        if index == module {
            vec![
                (
                    vec![revision; 8],
                    Some(vec![revision ^ u8::try_from(module).unwrap(); 32]),
                ),
                (vec![revision; 9], None),
            ]
        } else {
            Vec::new()
        }
    })
}

fn write_anchor(sidecar: &std::path::Path, targets: &FaultyTargets) {
    let mut blob = Vec::new();
    for target in [&targets.0, &targets.1, &targets.2, &targets.3] {
        let encoded = target.encode();
        blob.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        blob.extend_from_slice(&encoded);
    }
    std::fs::write(sidecar, blob).unwrap();
}

fn read_anchor(sidecar: &std::path::Path) -> FaultyTargets {
    let blob = std::fs::read(sidecar).unwrap();
    let mut targets = Vec::new();
    let mut offset = 0;
    while offset < blob.len() {
        let len = u32::from_le_bytes(blob[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        targets.push(
            FaultyTarget::decode(commonware_codec::Copying(&blob[offset..offset + len])).unwrap(),
        );
        offset += len;
    }
    let [acp, bulletin, vera, native]: [FaultyTarget; 4] =
        targets.try_into().expect("four targets");
    (acp, bulletin, vera, native)
}

#[test]
fn injected_io_failures_are_fatal_and_recovery_republishes_the_anchor() {
    if let (Ok(directory), Ok(module), Ok(code), Ok(sidecar)) = (
        std::env::var("VERA_NATIVE_FAULT_DIR"),
        std::env::var("VERA_NATIVE_FAULT_MODULE"),
        std::env::var("VERA_NATIVE_FAULT_CODE"),
        std::env::var("VERA_NATIVE_FAULT_ANCHOR"),
    ) {
        let module: usize = module.parse().unwrap();
        let failure = match code.parse::<u64>().unwrap() {
            1 => Failure::Write,
            2 => Failure::TruncatedWrite,
            3 => Failure::Sync,
            _ => panic!("invalid native fault type"),
        };
        let config = tokio::Config::new().with_storage_directory(&directory);
        tokio::Runner::new(config).start(|context| async move {
            let faulty = FaultyCtx::new(context);
            let set = open(&faulty).await;
            let baseline = std::array::from_fn(|index| changes(index, 1)[index].clone());
            let sealed = super::prepare(set.new_batches().await, baseline)
                .await
                .unwrap();
            set.apply(sealed).await;
            assert!(set.finalize().await.durable().await);
            write_anchor(
                std::path::Path::new(&sidecar),
                &set.committed_targets().await,
            );
            let module_name = ["acp", "bulletin", "vera", "nonces"][module];
            faulty.arm(failure, format!("fault-native-{module_name}-"));
            let batch = super::prepare(set.new_batches().await, changes(module, 2))
                .await
                .unwrap();
            set.apply(batch).await;
            let _ = set.finalize().await.durable().await;
        });
        panic!("injected failure must stop the actor before acknowledgement");
    }

    for (module, (code, failure_message)) in (0..4).flat_map(|module| {
        [
            (1u64, "database finalize failed"),
            (2, "database finalize failed"),
            (3, "database sync failed"),
        ]
        .map(|failure| (module, failure))
    }) {
        let directory = tempfile::tempdir().unwrap();
        let anchor_sidecar = directory.path().join("anchor");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native::fault_tests::injected_io_failures_are_fatal_and_recovery_republishes_the_anchor",
                "--nocapture",
            ])
            .env("VERA_NATIVE_FAULT_DIR", directory.path())
            .env("VERA_NATIVE_FAULT_MODULE", module.to_string())
            .env("VERA_NATIVE_FAULT_CODE", code.to_string())
            .env("VERA_NATIVE_FAULT_ANCHOR", &anchor_sidecar)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let module_name = ["acp", "bulletin", "vera", "nonces"][module];
        let internal_code = match code {
            1 => 1,
            2 => 3,
            3 => 2,
            _ => unreachable!(),
        };
        let witness =
            format!("native_io_fault code={internal_code} partition=fault-native-{module_name}-");
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.starts_with(&witness))
                .count(),
            1,
            "partition {module}, fault {code} did not inject exactly one matching I/O failure: {stderr}"
        );
        assert_eq!(
            output.status.code(),
            Some(101),
            "partition {module}, fault {code}: {stderr}"
        );
        assert!(
            stderr.contains(failure_message),
            "partition {module}, fault {code}: {stderr}"
        );

        let anchor = read_anchor(&anchor_sidecar);
        let config = tokio::Config::new().with_storage_directory(directory.path());
        tokio::Runner::new(config).start(|context| async move {
            let context = FaultyCtx::new(context);
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let set = FaultySet::init(
                context.child("recovered"),
                state_config("fault", cache),
                Some(anchor),
            )
            .await;
            let readers = set.readers();
            for index in 0..4 {
                let restored = failed_reader(&readers, index).read().await;
                assert_eq!(
                    restored
                        .get_many(&[&vec![1u8; 8], &vec![2u8; 8], &vec![2u8; 9]])
                        .await
                        .unwrap(),
                    [Some(Bytes::from(vec![1u8 ^ index as u8; 32])), None, None],
                    "partition {index} lost or advanced past the acknowledged anchor"
                );
            }

            let batch = super::prepare(set.new_batches().await, changes(module, 2))
                .await
                .unwrap();
            set.apply(batch).await;
            assert!(set.finalize().await.durable().await);
            let readers = set.readers();
            let republished = failed_reader(&readers, module).read().await;
            assert_eq!(
                republished
                    .get_many(&[&vec![2u8; 8], &vec![2u8; 9]])
                    .await
                    .unwrap(),
                [Some(Bytes::from(vec![2u8 ^ module as u8; 32])), None]
            );
        });
    }
}
