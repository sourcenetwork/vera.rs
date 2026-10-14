#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?required}"
: "${GITHUB_WORKSPACE:?required}"
test -x target/release/verad
test -x target/release/examples/mixed_policy_workload
test ! -e mixed-load-results
mkdir mixed-load-results
private="$(mktemp -d "$RUNNER_TEMP/vera-mixed-load.XXXXXXXX")"
cleanup() {
  python3 .github/scripts/stop-test-nodes.py "$GITHUB_WORKSPACE/target/release/verad"
  rm -rf -- "$private"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

result=0
for rate in 1 2 4 8; do
  directory="$private/rate-$rate"
  export VERA_E2E_DIR="$directory/clusters"
  mkdir -p -m 700 "$VERA_E2E_DIR"
  case_result=0
  python3 tools/performance/record.py \
    --node target/release/verad --runner target/release/examples/mixed_policy_workload \
    --history regolith --rust-log warn --timeout-seconds 1860 \
    --output "$directory/measurement" 256 "$rate" 8 1800 || case_result=1
  python3 .github/scripts/qualify-mixed-policy.py \
    --directory "$directory/measurement" --node target/release/verad \
    --runner target/release/examples/mixed_policy_workload --profile "curve-$rate" \
    --output "mixed-load-results/curve-$rate.json" || case_result=1
  python3 .github/scripts/stop-test-nodes.py "$GITHUB_WORKSPACE/target/release/verad"
  rm -rf -- "$directory"
  if ((case_result != 0)); then result=1; fi
done
exit "$result"
