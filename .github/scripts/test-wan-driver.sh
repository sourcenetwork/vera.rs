#!/usr/bin/env bash
set -euo pipefail

log=$(mktemp "${RUNNER_TEMP:?}/wan-driver.XXXXXX")
cargo +1.98.0 test --frozen --release -p vera-e2e --example wan_baseline \
    -- --exact tests::certified_remote_workload_checks_all_replicas --nocapture \
    2>&1 | tee "$log"
grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log"
