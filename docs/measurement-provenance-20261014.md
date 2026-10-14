# Measurement provenance and storage accounting

This index binds the current local measurements to their tested sources, build
recipes, machines and raw artifacts. Measurements retain their original source;
merging newer changes does not turn an older result into a measurement of main.
All six runs used four local validators on one Ubuntu 24.04 x86-64 hosted runner
with four logical CPUs. None measures independent hosts or a WAN deployment.

## Measurement set

| Measurement and raw artifact | Tested source | Host CPU | Workload |
| --- | --- | --- | --- |
| [Growing state, run 38503258544](https://github.com/sourcenetwork/vera.rs/actions/runs/38503258544), artifact `11868024251` | `2c2bf3600f8c81e51c258bb16b63587bed8b5f59` | Intel Xeon Platinum 8573C | 90,000 distinct registrations, 50/s, 30 minutes, one verified permission read per write |
| [Fixed state, run 38431246384](https://github.com/sourcenetwork/vera.rs/actions/runs/38431246384), artifact `11841287647` | `f3bbd7d2ed4559c43dab9e171d1bf70b0e639c64` | AMD EPYC 9V74 | 360,000 archive/unarchive updates over 128 objects, 50/s, two hours, one verified permission read per write |
| [Paired components and native workloads, run 38511059472](https://github.com/sourcenetwork/vera.rs/actions/runs/38511059472), artifact `11871092725` | Head `088be4d488a679fa3df2d2904c9d15b100d2fd91`; base `bc4c876b275f552c7501a40ce2ce02a66a927a93` | AMD EPYC 7763 | Head/base/base/head; 600 registrations and 600 fixed-object updates per pass at 20/s; component v6 has 29 cases |
| [Admission pressure, run 38511059334](https://github.com/sourcenetwork/vera.rs/actions/runs/38511059334), numeric artifact `11870428392` | Actual merge `4dd9591ae23ac558aec69f1cad3df90189e93189`, identical tree to `088be4d488a679fa3df2d2904c9d15b100d2fd91` | AMD EPYC 9V45 | One and four signer lanes; each case fills 4,096 pending slots, rejects 1,200 additional requests, restores quorum and checks 4,097 confirmed operations |
| [Mixed load, run 38461033855](https://github.com/sourcenetwork/vera.rs/actions/runs/38461033855), artifact `11848372514` | Actual merge `f27117bc7247477cdffa2a05bb9f28d787263397`; candidate `3f3f4673fc8ed44518e542c1ac37e2ae694390a4` | AMD EPYC 9V45 | 256 workflows at each offered rate 1/2/4/8 workflows/s; five sequential certified submissions and sixty permission checks per workflow |
| [Paired Go/Rust, run 38146229649](https://github.com/sourcenetwork/vera.rs/actions/runs/38146229649), artifact `11705084908` | Go `ce83826bfeb4ce0fdc1751fc6a28cd4b9c7e7933`; Rust `44907d84a540da626e52e399ecc7e638800f6899` | AMD EPYC 9V74, recorded by the Rust manifest on the shared runner | Go/Rust/Rust/Go; 600 distinct registrations per deployment at 20/s |

The pressure cases use a normal release daemon and release test fixture;
the other capacity measurements also use normal release binaries. Component timings run in-process and
exclude network consensus, durable publication and RPC. The eight paired native
workloads total 4,800 verified completions. All named successful native workload
cases retain replica reconciliation and hard-restart checks.

The mixed source's toolchain and workflow blobs were checked against the actual
merge: `d1ad785747eb8330d0e6226ee0d781d82336aca0` and
`13d8ace441dfb689b1ab5fb803861275962f1f8a`, respectively. They match the candidate's
corresponding files; the actual merge remains the recorded source.

## Build and observation settings

Rust workflows pin **1.98.0** and use frozen dependencies. Their source-specific
`rust-toolchain.toml`, `Cargo.toml`, `Cargo.lock` and workflow files are the build
recipes. The release profile sets `opt-level = 3`, thin LTO, no debug information
and symbol stripping. These are recorded recipe settings; the older measurement
artifacts do not independently record `rustc -Vv` output.

- Growing and fixed state use their source's
  [Performance workflow](../.github/workflows/performance.yml): release `verad`
  and `operation_baseline`. The fixed case sets two glibc arenas; the growing
  case uses default glibc 2.39 arenas. Both enable thirty-second numeric resource
  snapshots, one-second RSS/CPU sampling and no per-revision span-close tracing.
- Paired components/native workloads use
  [PR performance](../.github/workflows/performance-pr.yml), the head-built
  workload runner for both sources, and the same host for all four passes.
  Component samples use a 200 ms warm-up and nine 100 ms samples per case.
- Pressure uses the source's
  [native pressure workflow](../.github/workflows/native-pressure.yml), retaining
  its assertion and resource records. It is recovery evidence, not a release
  throughput measurement.
- Mixed load uses
  [native mixed load](../.github/workflows/native-mixed-load.yml), normal release
  `verad` and `mixed_policy_workload`, with syscall tracing disabled.
- Go/Rust uses [Go comparison](../.github/workflows/go-comparison.yml). The Go
  manifest records `go version go1.26.2 linux/amd64`; the daemon build uses
  `go build -mod=readonly -p 2 -trimpath`. Go uses LevelDB and a 200 ms batch wait;
  Rust uses Regolith and 100 ms. This comparison includes those implementation
  and configuration differences.

The manifests retain executable hashes, exact arguments, operating system and
machine metadata. Growing and fixed workloads use 128 outstanding requests,
100 ms proposal batching, 192-revision epochs, 256 retained consensus revisions
and pipelined Simplex with sixteen-view terms and four optimistic views. Signing
and setup occur before throughput timing. Measured receipt latency includes
scheduling, submission, finalization, polling and verification; it is not an
isolated Simplex finality measurement.

## Raw output and integrity

| Artifact | Verified ZIP SHA-256 |
| --- | --- |
| `11868024251` | `fba5c3137978d3aecc777e604628e582240e55afd1907912b60148d46f6c5f0b` |
| `11841287647` | `3ae1dbf07853a800226cd199011470e56373ca6dc351fe6f16c70ec731af1705` |
| `11871092725` | `fee78ed5c69f13a7f69431dea8ed826948ee16f51008f7acba59778c9a48f92b` |
| `11870428392` | `374c096d3b90cf438a088eedfebeda21f83c5a8ed1cf525178266d722ade5caf` |
| `11848372514` | `178400ffe8938f5ea95a46c41db327b591519bd33157b5f4df043f5d0ee639c4` |
| `11705084908` | `79f74bbced78bb6b643d04a6fef5594a49f0a6b5ae20390644509f3fdf8a2b13` |

Growing/fixed artifacts contain `manifest.json`, `workload.jsonl`,
`diagnostics.jsonl` and `report.json` within each case directory. Paired native
artifacts contain those manifests and raw workload outputs beneath
`head1`, `base1`, `base2` and `head2`, together with component samples and the
comparison. Pressure's two evidence JSON files contain numeric observations,
raw rejection-latency samples, per-worker progress and storage observations.
Mixed `curve-*.json` files retain workflow and submission observations plus the
aggregate report. Go/Rust passes retain their manifests, raw observations,
resource series and verification results. Download these artifacts while their
GitHub retention period remains active and verify the ZIP checksum before use.

## Clock-aligned storage accounting

[`storage_summary.py`](../tools/performance/storage_summary.py) reads an already
qualified workload report and its numeric diagnostics:

```sh
python3 tools/performance/storage_summary.py /path/to/qualified-case
```

It selects the original four process IDs and the timed workload's UTC anchor,
excluding setup, post-workload checks and restarted processes. It rejects missing
member coverage, malformed counters, counter regression and ambiguous clocks.
Future sustained Performance runs emit `storage-summary.json` alongside their
raw measurements.

Reprocessing the growing artifact gives sixty in-workload snapshots per member,
from approximately 25 to 1,795 seconds:

| Storage observation over that sampled interval | Per-member result |
| --- | ---: |
| Regolith submitted batch key/value bytes | 98.23–98.24 MB |
| Regolith WAL bytes | 99.62–99.63 MB |
| Regolith flush output | 27.45 MB |
| Regolith compaction output | 0 bytes |
| Encoded WAL + flush + compaction output / batch input | 1.29358–1.29359 |
| Regolith admitted-write stall counter increase | 0 µs |
| Commonware requested storage-write bytes | 2.23627–2.23697 GB |
| Commonware synchronization requests | 698,466–699,351 |

MB and GB in this table are decimal bytes. Regolith's ratio measures its encoded
output against submitted batch key/value bytes. Commonware counts requested
bytes before the operation returns, includes QMDB and consensus archives, and
can include failed attempts. Neither figure measures physical-device write
amplification, synchronization latency or attributes every write to one store.
The sampled interval contains no Regolith compaction; the separate two-hour
fixed-state run exercised compaction, but predates the new batch/WAL/flush counters
and cannot supply the same ratio.

The report also retains sampled first/last/peak history-cache, memtable,
arena-pool, execution-index and proof-cache counters. Those scopes overlap and
cannot be added into a whole-process RSS total. Current enumeration, decoding and
verification limits are documented in [permission proofs](permission-proofs.md)
and [operating a validator](operating.md#resident-memory-and-measured-workloads).
Verified permission-read latency includes proof generation and consumer
verification: growing p95 is 7.70 ms; fixed two-hour p95 is 12.95 ms.

Growing-state RSS increases as objects, relationships and signing identities are
added; this alone is not evidence of a leak. The fixed two-hour workload ended at
415.91–461.62 MiB per member, with only 0.26–3.66 MiB additional RSS in its final
ten minutes. That finite window does not establish an indefinite plateau.
These results define measured workload envelopes, rather than a hard memory
ceiling for arbitrary datasets or a maximum sustainable throughput.

The [storage resource envelope](storage-resource-envelope.md) records the selected
finite-profile regression budgets and their measured unused capacity. Its gate
validates both retained artifacts and runs in future sustained selections.
