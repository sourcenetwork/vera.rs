//! Resume snapshot startup after a process crash during durable history import.

#[path = "support/catchup.rs"]
mod catchup;

#[tokio::test]
async fn interrupted_snapshot_resumes_without_an_explicit_request() {
    catchup::recover_replica(true, true, false, catchup::ReplicaSource::Empty).await;
}

#[tokio::test]
async fn interrupted_snapshot_resumes_from_pruned_peers() {
    catchup::recover_replica(true, true, true, catchup::ReplicaSource::Empty).await;
}

#[tokio::test]
async fn stale_snapshot_target_recovers_after_sync_fixes() {
    catchup::recover_replica_with_delay(true, true, true, true).await;
}
