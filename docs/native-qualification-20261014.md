# Native workload measurements on October 14, 2026

Four local Vera validators completed the growing-state and admission-recovery
workloads below using pipelined Simplex, operator-managed membership, Commonware
QMDB state and Regolith finalized history. These are measured offered-load and
recovery results. They do not establish maximum capacity, a memory plateau or
multi-host latency.

## Growing state

[Run 38503258544](https://github.com/sourcenetwork/vera.rs/actions/runs/38503258544)
offered 90,000 distinct ACP object registrations at 50/s over thirty minutes.
Each operation used a distinct signer and included one verified permission read.
All operations completed, all four replicas agreed, and hard-restart inspection
found no state or receipt mismatch. There were no rejected, reverted, unsent,
unknown or verification-failed operations, and no client or server throttles.

The validators and client shared one hosted Linux machine with four logical CPUs,
an Intel Xeon Platinum 8573C and 16,765,378,560 bytes of physical memory. The clean
source and runner revision was `2c2bf3600f8c81e51c258bb16b63587bed8b5f59`.
The build used Rust 1.98.0, the normal release profile, Commonware revision
`4f5db3d0dc30900015fb13347e9ec20ae085b79a` and Regolith revision
`f6958cf0cea97f658dbdbc3572063a8122645101`.

| Measurement | Result |
| --- | ---: |
| Confirmed registrations / completed workflows | 90,000 / 90,000 |
| Confirmed registrations/s | 49.996 |
| Scheduled arrival to certified receipt p50 / p95 / p99 | 162.980 / 275.807 / 292.985 ms |
| Verified permission read p50 / p95 / p99 | 2.230 / 7.702 / 12.683 ms |
| Scheduled arrival to completed workflow p95 | 280.265 ms |
| Restart to RPC readiness / observed certified probe | 9.783 / 9.842 s |
| First sampled RSS per validator | 129.71–131.89 MiB |
| Last and peak sampled RSS per validator | 802.67–816.31 MiB |
| RSS growth during the last ten minutes | 154.31–182.30 MiB |
| Average CPU cores used per validator | 0.346–0.369 |
| Retained allocated files after the workload | 323.89–324.74 MiB per validator |

![Measured registration receipt latency and validator memory](performance/20261014-growing-state.svg)

The chart is copied from the run's artifact. Its latency distribution contains
all 90,000 certified outcomes; each memory curve contains 1,801 one-second samples
with no missing members. The source and runner were clean. Per-revision tracing
was disabled; numeric resource diagnostics ran every thirty seconds. The allocator
was glibc 2.39 with no arena override. These results do not measure zero-overhead
execution or a controlled improvement over a different host or allocator setting.

The workload used a 100 ms proposal batch wait, at most 256 operations and 16 MiB
of encoded operation bytes per revision, 192 revisions per epoch and Simplex
terms of sixteen views with four optimistic views. This growing-state run differs
from the earlier fixed-object updates: both live objects and worker records grow.

### Observed memory components

The workload clock anchor identifies sixty in-workload numeric snapshots for each
original validator process. Near the end of the timed workload, sampled history
block-cache use was 0.03–2.34 MiB and memtables were approximately 38.08 MiB.
The cached revision index and finalization-proof counts were both 1,024;
the epoch-proof count was 78. Regolith's admitted-write stall counter did not
increase between the first and last of these snapshots.

glibc reported 451.31–459.45 MiB in arena allocations, 119.57–122.68 MiB in direct
mapped allocations and 200.15–237.70 MiB free inside its retained arenas. Those
scopes overlap the storage and application measurements; they cannot be added
together as independent parts of RSS. They also do not identify every allocation
owner or prove a leak. Continued late RSS growth means a stable resource envelope
remains unqualified. Reducing the history block-cache budget alone does not
explain the observed memory use in this run.

### Artifact provenance

The official artifact is
`performance-regolith-2c2bf3600f8c81e51c258bb16b63587bed8b5f59`, ID
`11868024251`, with ZIP SHA-256
`fba5c3137978d3aecc777e604628e582240e55afd1907912b60148d46f6c5f0b`.
The manifest, raw operation outcomes, replica and restart records, resource
samples and numeric diagnostic timestamps were checked. Receipt percentiles were
regenerated from the raw observations.

The tested daemon SHA-256 is
`8a2de2dae0954b1dd87f270cf0303092805ee24a642f5eb3113a949a1e1ec5b5`;
the workload runner SHA-256 is
`0b82010a60b536f16e8970e0085e5a238fd47cacf93b54d71e3db3b946605ab3`.
The retained chart SHA-256 is
`517dd9da46dd6a4a8676400d6938cfc8ee4734ad23e0364b579143a2fbb64e1b`.
The artifact also contains an interactive replay of the collected measurements.

## Admission overload and recovery

[Run 38505857951](https://github.com/sourcenetwork/vera.rs/actions/runs/38505857951)
passed both the single-worker and four-worker
[admission saturation](native-pressure.md) cases on a four-logical-CPU AMD EPYC
7763 host. Each case admitted 4,096 namespace operations without quorum, rejected
1,200 requests at the capacity limit, restored quorum, retried the rejected wire
and reconciled all 4,097 certified operations on four replicas. The four-worker
case preloaded 1,024 independent sequences per worker in round-robin order.

| Measurement | One worker | Four workers |
| --- | ---: | ---: |
| Capacity rejection p50 / p95 / p99 | 3.271 / 5.846 / 6.523 ms | 3.251 / 5.726 / 5.831 ms |
| Pending encoded operation bytes | 1,146,496 | 1,145,344 |
| Observed backlog-tail recovery | 77.290 s | 86.291–86.317 s |
| Spread between workers' observed tails | 0 ms | 25.340 ms |
| Recovery plus four-replica reconciliation | 82.930 s | 91.837 s |

Tail timings include receipt polling and drain of previously admitted work; they
are not ordinary write-confirmation latency. Equal preloaded sequences do not
establish fairness under unequal continuous offered load. The two surviving
processes have complete one-second RSS, CPU and kernel I/O series; restarted
processes are outside those series. Retained file sizes were measured before
admission, at saturation and after reconciliation.

The run also passed the stopped-validator and delayed-validator cases. The tested
merge `ae2e4acfd42ef36e48be70c57fd9a7793c5dffa8`, candidate
`fc93be656b270bd00e24926a0b4b98a387df523f` and merged main
`bc4c876b275f552c7501a40ce2ce02a66a927a93` have identical complete trees:
`64ec14404ff947f20b74396e5134e70c981096a4`. Both pressure profiles used the same
daemon hash as the growing-state run above. Their release fixture SHA-256 is
`3cff3b36641814c70338b8ca790236547137c3e2419058a8e08587e14f80cddf`.

The official result artifact, ID `11868563087`, has ZIP SHA-256
`0d1726b416a585f4696df4e9d5be591ac56554bb4bc4d1fb16237a5bb85d5979`.
The resource artifact, ID `11868298438`, has ZIP SHA-256
`3ba88de776accd4a493805343d091d02d5d3c9186418ddffc4de2cccd2ac7376`.
Both digests, case outcomes and tested-tree equality were checked.

Earlier [run 38503134884](https://github.com/sourcenetwork/vera.rs/actions/runs/38503134884)
failed its backlog recovery deadline. Its worker-suffixed diagnostic records were
not retained by the summary exporter. The exporter now preserves bounded nonce
and node-progress diagnostics, while the original deadline and outcome assertions
remain unchanged. The passing successor does not explain that earlier failure;
its cause remains open.
