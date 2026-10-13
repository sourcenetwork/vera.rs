# Native qualification on October 13, 2026

The selected native stack passed the gateway, threshold and process-recovery
checks below. Vera uses pipelined Simplex, operator-managed membership, Commonware
QMDB authenticated state and Regolith finalized history. Trust remains a separate
Go gateway; Orbis remains a separate Rust threshold service. These results cover
the recorded sources and scenarios. Resource bounds and multi-host qualification
remain open.

## Tested sources

| Component | Revision | Role |
| --- | --- | --- |
| Vera | `0c26e9e568c179790cc2f3eb9e48849b08e6173f` | Daemon and shared verifier |
| Vera runtime merge | `112a1df99dbf23915c5764e540d495d63c7eacab` | Same complete tree as the tested candidate |
| Trust API | `52f66e6d4b7ccdd3c3446aa91b9a147f531527bc` | Executable and container gateway |
| Orbis normal runtime | `20dfa47de9ad5ae5fe4c7748089dea5be286b556` | BLS12-381 and Jubjub threshold services |
| Orbis qualification fixture | `c638455a5d43e5e31aeac41427a69ed18733f705` | Native integration driver |
| Vera SDK used by consumers | `9d5c2b9ea7cb971a7871028b7b0b22d488a7ecbf` | Native client and verifier source |
| Defra | `8cfd791fe7f3b69777c60b436f6b32c1a4447526` | Native provider and document store |
| Backbone SDK selected by Defra | `7d67ddbbb0d3d671b95dfe322b920e2e943c1daa` | Approved native proof client |

Vera's candidate and merge have tree
`45049623e125e77e509460753d9595789bdf055f`. The actual Trust PR merge used by the
jobs, `bd1f4933fbaecfcb542550293c91410da5805f87`, has the same complete tree as
the listed Trust candidate. The Orbis driver checks the normal runtime's source
boundary before reusing its images. Fixture revisions do not imply a runtime
upgrade. The Backbone client source matches its approved candidate; Defra's
lockfile selects the SDK revision in the table.

The measured cohort pins Rust 1.98.0, Regolith 0.1.9 at
`061846fc870389391f77b8c2a3cf370b6e69d95f` and Commonware 2026.9.0 at
`0ebcf164594621f2c82769eef7e9f3a21153055f`. Consumer stores retain their tested
pins; they are not assumed to be identical to Vera's history store.

## Verified consumer results

- [Gateway recovery, run 38384932545](https://github.com/sourcenetwork/trust-api/actions/runs/38384932545):
  executable and container modes each passed initial operation, restart/outcome
  recovery, and relay-revocation/restart phases. Four Go root cases per phase
  produced 24 passing case instances. Both modes use four Vera validators and
  Rust Defra, with independently provisioned consensus trust.
- [Real ring consumers, run 38384932362](https://github.com/sourcenetwork/trust-api/actions/runs/38384932362):
  BLS12-381 and Jubjub each passed executable and container contracts. Each curve
  checked six production-KDF stores, two Go contracts and sixteen ring records.
  Both curves used identical Vera, gateway and verifier executables and identical
  private Vera/gateway images. The normal Orbis image differs by curve.
- [Threshold lifecycle, run 38377014040](https://github.com/sourcenetwork/orbis-rs/actions/runs/38377014040):
  nine selected cases passed. Both curves covered distributed signing, PET,
  member replacement and scheduled refresh after restart; BLS also covered
  Defra signing.

Downloaded completion records, archive checksums and source bindings were checked
for these runs. The gateway runtime archive's six transferred binaries were also
hashed independently. Host and container gateway builds use separate recipes;
their binary equality is not assumed.

Earlier Defra document/replication, Backbone consumer, threshold churn and soak
checks retain their own source and scenario boundaries in the
[October 11](native-qualification-20261011.md) and
[October 12](native-qualification-20261012.md) records. The final focused checks
above do not turn every earlier workflow into a newly executed test.

## Release and recovery evidence

[Merged-main CI 38382288298](https://github.com/sourcenetwork/vera.rs/actions/runs/38382288298)
passed all twelve executed checks, including Linux lifecycle, snapshot recovery,
disk-full, sync-failure, commit-crash and release packaging. These qualify their
named process and injected-storage-failure cases, rather than physical device
power loss or hostile restoration of signing state.

[Two clean builds, run 38376496879](https://github.com/sourcenetwork/vera.rs/actions/runs/38376496879)
produced identical normal Linux release executables with SHA-256
`35cfca781a1dce16a2733bd4aeecdcbc120a124753d20f34692ccd72b37db0a7`.
Downloaded archives and the regenerated comparison matched. This establishes
reproducibility for the recorded Ubuntu 24.04/Rust 1.98.0 environments.

The native runtime dependency review at RustSec database revision
`d5f46becf4d442d460e1fce5e12f2c0f00924868` found no vulnerability, unsoundness or
yanked-package findings in the selected Linux runtime graph, excluding development
dependencies. Maintenance notices for `derivative`, `paste` and `unsafe-libyaml`
remain unsuppressed. Parser input limits do not establish `unsafe-libyaml` memory
safety. This review is a dependency check, not a complete security proof.

## Measured operating behavior

[Run 38376511669](https://github.com/sourcenetwork/vera.rs/actions/runs/38376511669)
completed 90,000 fixed-object updates at 49.998/s over 30 minutes, with one verified
permission read per write. Certified receipt p95 was 276.88 ms; permission-read
p95 was 8.73 ms. All four replicas reconciled, the restarted member retained the
inspected receipts and state, and all four read throttles recovered.

[Allocator comparison 38386604388](https://github.com/sourcenetwork/vera.rs/actions/runs/38386604388)
completed two further 90,000-update runs with the same normal binaries, one hosted
machine and 128 fixed objects. Both passed replica and restart checks with zero
mismatches. Per-revision span-close tracing was disabled; periodic numeric
diagnostics and one-second resource sampling remained enabled.

| Measurement | Default glibc arenas | Two glibc arenas |
| --- | ---: | ---: |
| Completed updates/s | 49.997 | 49.997 |
| Certified receipt p95 | 611.77 ms | 592.91 ms |
| Verified permission-read p95 | 16.12 ms | 15.80 ms |
| Last/peak sampled RSS per validator | 441.21–473.38 MiB | 336.65–352.65 MiB |
| RSS growth during the last ten minutes | 51.32–78.19 MiB | 33.43–41.84 MiB |

Average final RSS was 24.0% lower with two arenas in this single sequential pair.
Both cases were still growing. The production allocator remains unchanged. The
AMD EPYC host and recorded load differ from the earlier Xeon run despite identical
daemon bytes; the latency difference does not establish a source regression or
its cause. Both downloaded reports regenerated exactly from the raw observations.

These runs establish completed work at the offered 50/s load on one four-CPU
Ubuntu host. They do not establish maximum capacity, a 300 ms latency guarantee,
a memory ceiling or WAN performance. Receipt latency includes scheduling,
submission, polling and verification. The
[Go/Rust comparison](performance-20261011.md#matched-gorust-registrations) remains
a separate deployment comparison with its own sources and settings.

### Two-hour fixed-state run

[Extended run 38402671704](https://github.com/sourcenetwork/vera.rs/actions/runs/38402671704)
completed all 360,000 updates and verified permission reads over two hours at
49.999 updates/s. All four replicas reconciled; the restart inspection checked
360,000 operations with zero receipt or state mismatches. Two receipt-read
throttles recovered. There were no rejected, reverted, unresolved or incomplete
workflows. Restart RPC readiness took 3.51 seconds.

| Measurement | Observed result |
| --- | ---: |
| Certified receipt p50 / p95 / p99 | 168.19 / 286.00 / 310.95 ms |
| Verified permission-read p50 / p95 / p99 | 3.10 / 11.01 / 16.64 ms |
| Peak sampled RSS per validator | 669.62–679.10 MiB |
| Average CPU per validator | 0.40–0.44 cores |
| RSS change during the last ten minutes | -0.05 to +6.31 MiB |
| RSS change during the last thirty minutes | +263.07 to +274.70 MiB |

![Two-hour certified receipt latency and validator resident memory](performance/20261013-fixed-state.svg)

The run used 128 fixed objects, four local validators, a 100 ms batch interval,
192-revision epochs and two controlled glibc 2.39 arenas on one four-CPU AMD EPYC
7763 Ubuntu host. Source `dd0bc0e89630e128053b192a532f886bf74a9592` produced the same
normal daemon hash as the two clean builds above. Per-revision span-close tracing
was disabled; numeric diagnostics and one-second sampling remained enabled.
All 7,201 resource samples per validator were present. The artifact checksum
matched GitHub's digest and the numeric report regenerated exactly from raw
observations. These are offered-load results, rather than a maximum-capacity
measurement or a 300 ms guarantee.

The synchronized RSS jump coincides with the first Regolith compaction after the
fourth memtable flush. Between recording seconds 6,330 and 6,360, each validator's
compaction-output counter increased from zero to 116,683,074 bytes, while free
glibc arena memory increased by 252–258 MiB. Live allocator usage and directly
mapped memory did not show the same jump. The selected Regolith source scans
compaction inputs through the shared read cache and evicts those inputs after
publication. This establishes cache pollution in that implementation; the
30-second diagnostic interval does not capture its transient peak or attribute
the entire RSS jump to one owner.

The slower final ten minutes do not prove a memory plateau. The thirty-minute
window includes the compaction jump, and the complete run covers only one
observed compaction episode. A successful restart also does not explain older timeouts.

### Compaction cache boundary

Vera now selects Regolith revision `f6958cf0cea97f658dbdbc3572063a8122645101`.
Compaction scans use a zero-capacity cache instead of populating the foreground
read cache with input blocks that become obsolete when the merge completes.
Foreground reads retain their configured cache; obsolete-file eviction still
targets that shared cache. The default history cache budget and allocator are
unchanged. Partitioned-index scans also bypass metadata caching during the merge,
which can increase metadata reads. Checksums, version reduction and durable
publication retain their existing paths.

The Regolith candidate's Linux workspace run passed all 1,810 selected tests,
including the cache-inspection fixture. That fixture checks the cache during
compaction, before eviction can hide pollution, and verifies all 256 output
key/value pairs for flat and partitioned indexes with uncompressed and LZ4 data.
The Linux CI profile has no default test filter; successful individual case lines
are suppressed in its log. The selected revision also passed strict lint, MSRV,
allocation budgets and modeled durability checks. These results establish the
tested code boundary, rather than a measured whole-Vera RSS reduction. The
two-hour numbers above remain results from the preceding Regolith revision.

## Remaining qualification

Establish a steady-state resource envelope and document growing-data sizing.
Historical readiness and DKG deadlines remain causally unexplained; later passes
do not explain them. Multi-host/WAN qualification awaits test hosts. Preserve
these limits when selecting deployment budgets or describing release readiness.
See [operations](operating.md), [certified readiness](readiness.md),
[history recovery](history-storage.md) and [key boundaries](native-pet.md#deployment-boundary)
for the implemented operating requirements.
