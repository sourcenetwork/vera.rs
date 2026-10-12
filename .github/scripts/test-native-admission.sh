#!/usr/bin/env bash
set -euo pipefail

cargo +1.98.0 test --frozen -p vera-jsonrpc --lib retryable
cargo +1.98.0 test --frozen -p vera-consensus --lib \
    components::mempool::tests::full_pending_queue_rejects_without_eviction_and_recovers_after_pruning -- --exact \
    --nocapture
