use std::{io, os::unix::fs::MetadataExt, path::Path, time::Duration};

use serde_json::json;
use tokio::{process::Command, sync::oneshot, task::JoinHandle, time::Instant};
use vera_e2e::cluster::TestCluster;

#[path = "process_io.rs"]
mod process_io;

pub(super) async fn storage(cluster: &TestCluster, phase: &str) {
    for index in 0..4 {
        let path = cluster.node(index).data_dir.clone();
        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || storage_usage(&path))
            .await
            .expect("storage sampler task");
        let (usage, error) = match result {
            Ok(usage) => (Some(usage), None),
            Err(error) => (None, Some(error.to_string())),
        };
        println!(
            "{}",
            json!({
                "kind": "storage", "phase": phase, "node": index,
                "logical_bytes": usage.as_ref().map(|s| s.logical_bytes),
                "allocated_file_bytes": usage.as_ref().map(|s| s.allocated_file_bytes),
                "regular_files": usage.as_ref().map(|s| s.regular_files),
                "error": error,
                "scan_ms": started.elapsed().as_secs_f64() * 1000.0,
            })
        );
    }
}

#[derive(Default)]
struct StorageUsage {
    logical_bytes: u64,
    allocated_file_bytes: u64,
    regular_files: u64,
}

fn storage_usage(path: &Path) -> io::Result<StorageUsage> {
    let mut total = StorageUsage::default();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.path().symlink_metadata()?;
        let usage = if metadata.is_dir() {
            storage_usage(&entry.path())?
        } else if metadata.is_file() {
            StorageUsage {
                logical_bytes: metadata.len(),
                allocated_file_bytes: metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(size_overflow)?,
                regular_files: 1,
            }
        } else {
            continue;
        };
        total.logical_bytes = total
            .logical_bytes
            .checked_add(usage.logical_bytes)
            .ok_or_else(size_overflow)?;
        total.allocated_file_bytes = total
            .allocated_file_bytes
            .checked_add(usage.allocated_file_bytes)
            .ok_or_else(size_overflow)?;
        total.regular_files = total
            .regular_files
            .checked_add(usage.regular_files)
            .ok_or_else(size_overflow)?;
    }
    Ok(total)
}

fn size_overflow() -> io::Error {
    io::Error::other("storage size overflow")
}

#[cfg(any(target_os = "linux", test))]
const STATUS_LIMIT: usize = 16 * 1024;

#[cfg(any(target_os = "linux", test))]
fn parse_rss_status(status: &str) -> Result<[Option<u64>; 4], io::Error> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid RSS status field");
    if status.len() > STATUS_LIMIT {
        return Err(invalid());
    }
    let mut values = [None; 4];
    for line in status.lines() {
        let mut fields = line.split_whitespace();
        let index = match fields.next() {
            Some("VmRSS:") => 0,
            Some("RssAnon:") => 1,
            Some("RssFile:") => 2,
            Some("RssShmem:") => 3,
            _ => continue,
        };
        let number = fields.next().ok_or_else(invalid)?;
        if values[index].is_some()
            || !number.bytes().all(|byte| byte.is_ascii_digit())
            || fields.next() != Some("kB")
            || fields.next().is_some()
        {
            return Err(invalid());
        }
        values[index] = Some(
            number
                .parse::<u64>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        );
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
async fn read_rss_status(pid: u32) -> Result<[Option<u64>; 4], io::Error> {
    use tokio::io::AsyncReadExt;

    let file = tokio::fs::File::open(format!("/proc/{pid}/status")).await?;
    let mut status = String::new();
    file.take((STATUS_LIMIT + 1) as u64)
        .read_to_string(&mut status)
        .await?;
    parse_rss_status(&status)
}

async fn rss_sample(pid: u32) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    let (values, availability) =
        match tokio::time::timeout(Duration::from_secs(2), read_rss_status(pid)).await {
            Ok(Ok(values)) => {
                let availability = if values.iter().all(Option::is_some) {
                    "complete"
                } else {
                    "partial"
                };
                (values, availability)
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
                ([None; 4], "invalid_data")
            }
            Ok(Err(_)) => ([None; 4], "read_error"),
            Err(_) => ([None; 4], "timed_out"),
        };
    #[cfg(not(target_os = "linux"))]
    let (values, availability) = ([None::<u64>; 4], "unsupported");
    json!({
        "pid": pid, "availability": availability,
        "vm_rss_kib": values[0], "rss_anon_kib": values[1],
        "rss_file_kib": values[2], "rss_shmem_kib": values[3],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_status_preserves_units_zero_and_missing_fields() {
        assert_eq!(
            parse_rss_status(
                "Name:\tverad\nRssFile:\t 256 kB\nVmRSS: 1024 kB\nRssAnon: 768 kB\nRssShmem: 0 kB\n"
            )
            .unwrap(),
            [Some(1024), Some(768), Some(256), Some(0)]
        );
        assert_eq!(
            parse_rss_status("VmRSS: 42 kB\nRssFile: 0 kB\n").unwrap(),
            [Some(42), None, Some(0), None]
        );
        assert_eq!(parse_rss_status("Name: verad\n").unwrap(), [None; 4]);
        assert_eq!(
            parse_rss_status("RssAnon: 18446744073709551615 kB").unwrap()[1],
            Some(u64::MAX)
        );
    }

    #[test]
    fn rss_status_rejects_ambiguous_or_unbounded_measurements() {
        for input in [
            "VmRSS:",
            "VmRSS: kB",
            "VmRSS: -1 kB",
            "VmRSS: +1 kB",
            "VmRSS: 1.5 kB",
            "VmRSS: 18446744073709551616 kB",
            "VmRSS: 1024 B",
            "VmRSS: 1 KiB",
            "VmRSS: 1 kB extra",
            "RssAnon: 1 kB\nRssAnon: 2 kB",
        ] {
            assert_eq!(
                parse_rss_status(input).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{input}"
            );
        }
        assert!(parse_rss_status(&" ".repeat(STATUS_LIMIT)).is_ok());
        assert_eq!(
            parse_rss_status(&" ".repeat(STATUS_LIMIT + 1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rss_status_reads_the_current_process() {
        let pid = std::process::id();
        let sample = rss_sample(pid).await;
        assert_eq!(sample["pid"], pid);
        assert_eq!(sample["availability"], "complete");
        assert!(sample["vm_rss_kib"].as_u64().unwrap() > 0);
        for field in ["rss_anon_kib", "rss_file_kib", "rss_shmem_kib"] {
            assert!(sample[field].as_u64().is_some(), "{field}: {sample}");
        }
    }

    #[test]
    fn storage_usage_counts_nested_files_without_following_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let first = root.path().join("record");
        let second = nested.join("journal");
        std::fs::write(&first, b"record").unwrap();
        std::fs::File::create(&second)
            .unwrap()
            .set_len(1 << 20)
            .unwrap();
        std::os::unix::fs::symlink(root.path(), nested.join("cycle")).unwrap();
        std::os::unix::fs::symlink(&first, root.path().join("alias")).unwrap();
        let usage = storage_usage(root.path()).unwrap();
        assert_eq!(usage.logical_bytes, 6 + (1 << 20));
        assert_eq!(usage.regular_files, 2);
        assert_eq!(
            usage.allocated_file_bytes,
            [first, second]
                .iter()
                .map(|path| std::fs::metadata(path).unwrap().blocks() * 512)
                .sum::<u64>()
        );
    }
}

pub(super) fn start(cluster: &TestCluster) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let pids: Vec<_> = (0..4)
        .map(|i| cluster.node(i).process.id().expect("running node"))
        .collect();
    println!(
        "{}",
        json!({"kind": "resource_configuration", "node_pids": pids,
        "sample_interval_ms": 1000, "rss_unit": "KiB", "cpu_time": "cumulative ps time",
        "process_io_source": if cfg!(target_os = "linux") { "linux_proc_io" } else { "unsupported" },
        "rss_breakdown_source": if cfg!(target_os = "linux") { "linux_proc_status" } else { "unsupported" }})
    );
    let selection = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let started = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                _ = interval.tick() => {}
            }
            let (output, rss_breakdown, process_io) = tokio::join!(
                async {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        Command::new("ps")
                            .args(["-p", &selection, "-o", "pid=,rss=,time="])
                            .kill_on_drop(true)
                            .output(),
                    )
                    .await
                },
                futures::future::join_all(pids.iter().copied().map(rss_sample)),
                futures::future::join_all(pids.iter().copied().map(process_io::sample)),
            );
            let mut sample = match output {
                Ok(Ok(output)) if output.status.success() => match String::from_utf8(output.stdout)
                {
                    Ok(rows) => json!({"rows": rows}),
                    Err(error) => json!({"error": error.to_string()}),
                },
                Ok(Ok(output)) => json!({"error": String::from_utf8_lossy(&output.stderr)}),
                Ok(Err(error)) => json!({"error": error.to_string()}),
                Err(_) => json!({"error": "process sampling timed out"}),
            };
            sample["rss_breakdown"] = json!(rss_breakdown);
            sample["process_io"] = json!(process_io);
            println!(
                "{}",
                json!({"kind": "resources", "elapsed_seconds": started.elapsed().as_secs_f64(), "sample": sample})
            );
        }
    });
    (stop, task)
}
