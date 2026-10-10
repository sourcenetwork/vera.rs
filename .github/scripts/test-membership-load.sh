#!/usr/bin/env bash
set -euo pipefail

log=$(mktemp "${RUNNER_TEMP:?}/membership-load.XXXXXX")
result=0
cargo +1.98.0 test --frozen --release -p vera-e2e --test native_membership \
    -- pipelined_member_joins_without_bootstrap_share_and_sustains_quorum --exact --nocapture \
    > "$log" 2>&1 || result=$?
python3 - "$log" "$result" <<'PY'
import json
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
result = int(sys.argv[2])
record = {'exit_code': result}
site = re.search(r'panicked at (?:[^\n]*/)?([\w-]+\.rs):(\d+):(\d+):', text)
if site:
    record['panic_site'] = {'file': site[1], 'line': int(site[2]), 'column': int(site[3])}
measurements = re.findall(r'^native membership load cycles=(\d+) first=(\d+) last=(\d+) verified_replicas=(\d+)$', text, re.M)
summaries = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text, re.M)
valid = result == 0 and summaries == [('1', '0', '0')] and len(measurements) == 1
if valid:
    cycles, first, last, replicas = map(int, measurements[0])
    record.update(cycles=cycles, first_height=first, last_height=last, verified_replicas=replicas)
    valid = cycles >= 2 and 0 < first < last and replicas == 3
record['qualified'] = valid
print(json.dumps(record))
sys.exit(0 if valid else 1)
PY
