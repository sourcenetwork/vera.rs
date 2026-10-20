# Cross-endpoint inclusion and receipt qualification

Issue #82's historical downstream timeout is not assumed reproducible. This test
qualifies the current native Rust client path independently of manual transaction
broadcast, using four real validator processes and operator-provisioned test
consensus trust. It does not claim a downstream gateway or WAN release gate.

## Workload and boundaries

`crates/vera-e2e/tests/cross_endpoint_receipts.rs` submits 24 distinct, signed native
ACP policy creations, one outstanding operation at a time. It exercises all twelve
ordered pairs of different ingress/observer members twice. Each signed submission
is sent exactly once to its selected ingress endpoint; only the node's own
forwarding can disseminate it. There is no test-side rebroadcast or admission
retry. The exact locally computed submission ID must match the admission response.

Finality observation and submission/receipt observation run concurrently. Status
heights schedule light-block requests but do not establish finality. Every newly
observed revision is independently verified against the seeded test consensus key;
a subsequently verified receipt identifies which observed revision included the
submission. The test requires successful execution, matching finality/receipt block
identity, and identical verified execution receipts on all four replicas.

The JSONL output separates:

- Admission call latency.
- Submission to observation of independently verified finality for the inclusion
  revision.
- Submission to certified receipt availability on a different member.
- **Signed** finality-to-receipt observation delta. A negative value means the
  receipt call completed verification before the independent finality observer did.
  It is retained, not clamped to zero or presented as negative server delay.
- Receipt poll count, inclusion height/block hash, ingress/observer indices and
  exact submission IDs. All-replica reconciliation runs outside these timings.

All timings use one client's monotonic clock, including RPC/decoding/proof
verification costs. They are not server consensus timestamps or internal
publication latency. Polling is 50 ms and each whole submission/observation has a
fixed 30-second deadline. Replica reconciliation has its own fixed 30-second
budget. Permanent errors and proof failures are not hidden by polling. An incomplete
operation stops the sequence rather than producing dependent-sequence timeouts.

The profile uses four same-host validators, normal consensus timing
(500 ms leader / 1 s notarization / 2 s retry), 20 revisions per epoch, seed and
deployment 9088, and one signer. Generated node configs, genesis, transaction IDs
and logs are retained for reproduction. This is a bounded correctness and latency
sample, **not** a maximum-throughput benchmark, historical-flake proof, fault
injection, or four-host WAN qualification. No >95%/five-second target is silently
reintroduced as a release gate.

## Reproduce and retain evidence

```sh
cargo build --locked -p verad
VERAD_BINARY="$PWD/target/debug/verad" \
  VERA_E2E_KEEP=1 VERA_E2E_DIR="$PWD/target/receipt-qualification" \
  cargo test --locked -p vera-e2e --test cross_endpoint_receipts -- --nocapture
```

The configuration row locates each node's configuration and log directory. Each
run writes `cross-endpoint-receipts.jsonl` alongside the four node directories,
flushing every observation. Set `VERA_E2E_KEEP=1` to prevent harness cleanup. Keep
stdout, the run directory, repository revision, test-source and lockfile hashes,
binary hash, build profile, host/CPU and exact commands together. Failure rows
include per-node status diagnostics; inspect the retained logs to distinguish
admission, forwarding, consensus/execution and proof-lookup failures. Test keys
are deterministic fixtures, not production keys; never publish production keys or
unreviewed raw operator artifacts.

The Linux recovery lifecycle job runs this test with its existing evidence capture.
A local result does not substitute for hosted execution or an actual downstream
consumer qualification.

## Recorded local qualification

The [source-bound results](cross-endpoint-receipts-results.json) record one
exploratory run and two runs of the final test source on an Apple M2 Pro/macOS
host, using a dev build with debug information disabled. Each run exercised all
12 ordered endpoint pairs twice and verified receipts on every replica.

| Final-source run | Verified operations | Receipt latency p50 | Receipt latency p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| 2 | 24/24 | 762.7 ms | 1,355.8 ms | 1,358.5 ms |
| 3 | 24/24 | 721.2 ms | 1,574.8 ms | 1,583.5 ms |

Percentiles use nearest rank separately per run. The results include admission,
observed finality and signed finality-to-receipt distributions, as well as source,
lockfile, binary and stdout hashes. Raw node logs/configuration and per-submission
JSONL remain in the retained local evidence directory; hashes do not make those
private artifacts available to other readers. Hosted execution remains unverified
until the proposed change runs in CI.

No historical timeout reproduced, so this change adds qualification and diagnostics,
not a claimed forwarding or receipt-publication fix. The finality-to-receipt delta
includes observer scheduling and RPC/proof work; its negative samples are expected
when the receipt observer completes first. The result does not establish the old
downstream flow's latency, sustained throughput or WAN behavior.
