use std::{fs::OpenOptions, io::Write as _, time::Duration};

use super::{LogEvent, LogTracker};

#[tokio::test]
async fn indexed_progress_is_independent_of_proposals_and_survives_tail_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stdout.log");
    std::fs::write(
        &path,
        "INFO vera_app::app: verified block height=2 txs=0 total_ms=1\n",
    )
    .unwrap();
    let mut tracker = LogTracker::new(path.clone());
    let timeout = Duration::from_secs(5);

    tokio::time::timeout(timeout, async {
        // Confirm the parser reached EOF before extending the same file.
        tracker.eof.notified().await;
        assert_eq!(tracker.latest_height(), 2);
        assert_eq!(tracker.latest_indexed_height(), 0);

        let (event, ()) = tokio::join!(
            tracker.wait_for("^indexed finalized block height=8$", timeout),
            async {
                writeln!(
                    OpenOptions::new().append(true).open(&path).unwrap(),
                    "TRACE vera_node::finalize: indexed finalized block \x1b[3mheight\x1b[0m\x1b[2m=\x1b[0m8"
                )
                .unwrap();
            }
        );
        assert!(matches!(event.unwrap(), LogEvent::BlockIndexed { height: 8 }));
        assert_eq!(tracker.latest_height(), 2);
        assert_eq!(tracker.latest_indexed_height(), 8);

        let (event, ()) = tokio::join!(
            tracker.wait_for("^block built height=100$", timeout),
            async {
                writeln!(
                    OpenOptions::new().append(true).open(&path).unwrap(),
                    "INFO vera_app::app: built block height=100 txs=0 total_ms=1"
                )
                .unwrap();
            }
        );
        assert!(matches!(event.unwrap(), LogEvent::BlockBuilt { height: 100, .. }));
        assert_eq!(tracker.latest_height(), 100);
        assert_eq!(tracker.latest_indexed_height(), 8);

        let (event, ()) = tokio::join!(
            tracker.wait_for("^indexed finalized block height=7$", timeout),
            async {
                writeln!(
                    OpenOptions::new().append(true).open(&path).unwrap(),
                    "TRACE vera_node::finalize: indexed finalized block height=9\n\
                     TRACE vera_node::finalize: indexed finalized block height=7"
                )
                .unwrap();
            }
        );
        assert!(matches!(event.unwrap(), LogEvent::BlockIndexed { height: 7 }));
        assert_eq!(tracker.latest_height(), 100);
        assert_eq!(tracker.latest_indexed_height(), 9);

        tracker.restart();
        assert_eq!(tracker.latest_height(), 100);
        assert_eq!(tracker.latest_indexed_height(), 9);
        tracker
            .wait_for("^indexed finalized block height=7$", timeout)
            .await
            .unwrap();
        assert_eq!(tracker.latest_height(), 100);
        assert_eq!(tracker.latest_indexed_height(), 9);
    })
    .await
    .expect("log parser should observe appended indexed progress and replay without regressing");
}
