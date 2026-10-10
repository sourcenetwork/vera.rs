use super::*;

async fn run(
    url: &str,
    policy: &str,
    minimum: u64,
    trusted: &ConsensusPublicKey,
) -> std::process::Output {
    let mut command = tokio::process::Command::new(vera_e2e::resolve_binary().unwrap());
    command
        .kill_on_drop(true)
        .env("RUST_LOG", "off")
        .args([
            "client",
            "--url",
            url,
            "--compact",
            "check-read",
            "--policy-id",
            policy,
        ])
        .arg("--trusted-key")
        .arg(hex::encode(commonware_codec::Encode::encode(trusted)))
        .arg("--minimum-revision")
        .arg(minimum.to_string())
        .args(["--max-age-seconds", "30"]);
    tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .expect("certified read command exceeded its bounded request deadline")
        .unwrap()
}

pub(super) async fn exercise(
    url: &str,
    policy: &str,
    minimum: u64,
    trusted: &ConsensusPublicKey,
    unrelated: &ConsensusPublicKey,
) {
    let accepted = run(url, policy, minimum, trusted).await;
    assert!(accepted.status.success(), "certified read command failed");
    assert!(accepted.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(report.as_object().unwrap().len(), 4);
    assert_eq!(report["policyId"], policy);
    assert!(report["revision"].as_u64().unwrap() >= minimum);
    let timestamp = report["timestamp"].as_u64().unwrap();
    let checked = report["checkedAt"].as_u64().unwrap();
    assert!(checked.saturating_sub(timestamp) <= 30);
    assert!(timestamp.saturating_sub(checked) <= 5);

    let untrusted = run(url, policy, minimum, unrelated).await;
    assert!(!untrusted.status.success());
    assert!(untrusted.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&untrusted.stderr)
            .contains("light block consensus key does not match the trusted key")
    );

    let absent = run(url, &"ff".repeat(32), minimum, trusted).await;
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&absent.stderr)
            .contains("selected policy is absent at the certified revision")
    );
}
