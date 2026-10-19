# Local network status view

The read-only collector in `tools/performance/live_status.py` serves a small view
on **127.0.0.1 only**. It neither deploys a service nor starts validators, submits
workloads, discovers trust, or changes network configuration. Deployment, access
control, TLS and approved public member labels are separate operator actions.
Do not expose the local listener directly to a public network.

## Run against an operator-selected network

Build the finality verifier from the same checkout:

```sh
cargo build --locked -p vera-domain --example verify_status
```

Create a private configuration outside published artifacts. Example shape (replace
both the endpoint and the key; the key is the independently provisioned 96-byte
hex consensus public key, **not** an RPC response or a private signing key):

```json
{
  "environment": "same-host",
  "trusted_key": "<192 hex characters from operator trust>",
  "members": [
    {"id": "validator-0", "rpc": "http://127.0.0.1:8545", "chain_id": 1}
  ]
}
```

```sh
python3 tools/performance/live_status.py --config /private/network.json \
  --verifier target/debug/examples/verify_status --interval 2 --stale 15 --window 60
```

Open the printed localhost URL. `environment` must be `same-host`, `wan` or
`unknown`; this is an operator declaration, not measured placement or WAN
qualification. Member IDs are public-safe labels, not authenticated identities.
Omitting `trusted_key` permits explicitly **unverified** observations; providing a
key without a verifier is an error rather than an unverified fallback.

Each poll checks `eth_chainId`, reads `vera_nodeStatus`, then requests the exact
`vera_getLightBlock` height and verifies its evidence with `verify_light_block`
against operator trust. A bad certificate, wrong height, chain mismatch, malformed
response or timeout fails the observation. Last good data remain visible with a
disconnected/stale label. Verification authenticates the revision and its timestamp,
not the status fields, endpoint identity or freshness: even an authentic old
certificate can be replayed. A stationary revision shows growing progress age.
Restart detection uses a decrease in reported uptime (not authenticated); it resets
the interval history. A height regression without that signal fails observation.

Polling can skip revisions. Only consecutive observed heights receive a measured
revision interval; the chart does not invent intermediate observations. These are
collector-monotonic observation intervals, not proposer intervals. Wall-clock
observation timestamps and block clock offsets are separate: clock offset is not
latency. Histories are bounded to 4,096 changes per member and filtered to the
selected sample window. Restarting the collector starts a new session.

## Recorded client measurements

Load an existing `manifest.json` / `workload.jsonl` directory alongside live data,
or alone for offline review:

```sh
python3 tools/performance/live_status.py --replay /path/to/recorded-run
```

The collector reuses `replay.py`'s validation and pass/fail gates. It displays
recorded scheduled-to-certified receipt, permission-read and complete-workflow
latency distributions separately, with their counts/percentiles and full recorded
window. Completed workflow rate is completed workflows divided by that recorded
elapsed time. Missing measurements remain unavailable; failed runs stay failed.
No live client latency or throughput is inferred from revision progress. Replay
placement stays unknown because artifacts alone do not establish WAN placement.
These observations are not the sustainable capacity qualification tracked in #232.

## Privacy, boundaries and validation

The browser receives no endpoint URLs, raw RPC payloads, exception details, keys,
manifest source strings or operator configuration. Provenance is restricted to
hashes of the configuration, trust text, verifier binary, collector/assets and
recorded input files. Hashes identify inputs; they do not authenticate their owner.
Keep low-entropy secrets out of configuration: a hash is not secret storage.
The private configuration has a 64 KiB limit and at most 64 members. Requests have
bounded response sizes, timeouts and concurrency; redirects and ambient proxies
are disabled. There are no write routes, cross-origin grants or dynamic HTML
interpolation. The browser marks collector loss explicitly rather than retaining
a green connected label.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/performance -p test_live_status.py
cargo test --locked -p vera-domain --example verify_status
cargo test --locked -p vera-domain light_block
node --check tools/performance/live/app.js
```

Tests cover local HTTP RPC/browser serving, missing/stale/disconnected/reconnecting
members, delayed/malformed/wrong-revision evidence, verification failure without
fallback, clock skew, skipped revisions, regression and restart. Existing domain
tests cover real threshold certificates and forged/substituted evidence. No live
WAN network or deployment is claimed by these local tests.
