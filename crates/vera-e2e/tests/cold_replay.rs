//! Recover an empty replica by replaying retained history.

#[path = "support/catchup.rs"]
mod catchup;

#[tokio::test]
async fn cold_replica_replays_across_epochs() {
    catchup::recover_replica(false, false, false, catchup::ReplicaSource::Empty).await;
}

#[tokio::test]
async fn stopped_backup_restores_revocations_and_rejoins_pipelined_consensus() {
    catchup::recover_replica(false, false, false, catchup::ReplicaSource::StoppedBackup).await;
}
