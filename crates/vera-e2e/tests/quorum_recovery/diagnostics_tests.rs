use super::*;

#[test]
fn tails_are_bounded_and_identify_available_metric_samples() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("stdout.log");
    let mut bytes = vec![b'x'; MAX_LOG_BYTES as usize + 4096];
    bytes.extend_from_slice(
        b"\nvera_diagnostics runtime_metrics=actual_metric 2\ndurable_height=17\n",
    );
    std::fs::write(&path, &bytes).unwrap();
    let tail = log_tail(&path);
    assert_eq!(tail["file_bytes"], bytes.len());
    assert_eq!(tail["truncated"], true);
    assert_eq!(tail["runtime_metrics_present"], true);
    assert_eq!(tail["durable_height_present"], true);
    assert_eq!(tail["text"].as_str().unwrap().len(), MAX_LOG_BYTES as usize);
    assert!(
        tail["text"]
            .as_str()
            .unwrap()
            .ends_with("durable_height=17\n")
    );
}

#[test]
fn only_named_logs_are_read_and_missing_samples_remain_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("stdout.log"), b"no metrics\n").unwrap();
    std::fs::write(
        root.path().join("secrets.json"),
        b"private-fixture-material",
    )
    .unwrap();
    let logs = log_tails(root.path());
    assert_eq!(logs["stdout"]["runtime_metrics_present"], false);
    assert_eq!(logs["stdout"]["durable_height_present"], false);
    assert!(logs["stderr"]["error"].is_string());
    assert!(!logs.to_string().contains("private-fixture-material"));
}

#[tokio::test(start_paused = true)]
async fn diagnostic_probes_keep_missing_receipts_distinct_from_timeouts() {
    assert_eq!(probe(async { Ok(Value::Null) }).await, json!({"ok": null}));
    assert_eq!(
        probe(std::future::pending()).await,
        json!({"error": "probe timed out"})
    );
}
