//! Process crash points for tests, in fault-injection builds.
//!
//! A test names a point in the data directory's `crash-at` file. The process
//! aborts when it reaches that point, after recording the point it stopped
//! at in `crash-at.hit`.

use std::{io::Write as _, path::Path};

const MARKER: &str = "crash-at";

/// Abort if the test named `point` for the node in `directory`.
pub(crate) fn point(directory: &Path, point: &str) {
    let marker = directory.join(MARKER);
    let Ok(named) = std::fs::read_to_string(&marker) else {
        return;
    };
    if named.trim() != point {
        return;
    }
    std::fs::remove_file(&marker).expect("consume crash marker");
    let hit = directory.join("crash-at.hit");
    let mut witness = std::fs::File::create(&hit).expect("create crash witness");
    witness
        .write_all(point.as_bytes())
        .expect("write crash witness");
    witness.sync_all().expect("sync crash witness");
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .expect("sync crash directory");
    std::process::abort();
}
