# Native allocation attribution

The **Native heap profile** workflow runs the existing four-validator workload.
Select `startup` for 6,000 updates at 20 offered operations/s, or `sustained` for
90,000 updates at 50 offered operations/s against 128 fixed objects. Select
`growing` for 90,000 distinct registrations at 50 offered operations/s. Both
thirty-minute profiles use two glibc arenas. Every profile preserves certified
permission reads, all-replica verification and full restart checks. The manifest
records the selection and fixed-update object count; zero selects registrations.
Qualification checks that the workload's reported mode, object count and operation
count match that selection before analyzing the trace. Successful fixed-state
updates cannot qualify a growing-data profile.
Current profiles use Regolith history. Earlier RocksDB profiles below remain
historical measurements.

Startup profiles allow two minutes for trace inventory; sustained and growing
profiles allow ten minutes for their larger folded trace. Symbol decoding retains its
separate two-minute deadline and bounded inventory. These reporting budgets do
not change workload or production request deadlines. The selected scan budget is
recorded in the profile manifest. A successful workload alone does not qualify
allocation attribution if later reporting fails.

The sustained Regolith diagnostic in
[run 38053754819](https://github.com/sourcenetwork/vera.rs/actions/runs/38053754819)
certified all 90,000 operations, checked four replicas and passed restart with
zero receipt or state mismatches. Reporting then exceeded the previous
two-minute deadline while rewriting decoded stacks. Its retained workload
evidence does not include qualified allocation attribution. The growing profile below qualifies its allocation attribution. Fixed-state
sustained attribution remains a separate gate.

## Growing-state allocation attribution

A source-bound heaptrack run on October 11, 2026 completed 90,000 distinct native ACP registrations at an offered 50 operations/s. All operations verified across four replicas; restart inspection found no receipt or state mismatches. The profile instruments member 3 on its first boot, uses two glibc arenas and a release build with debug symbols. It is an allocation study, not a capacity benchmark or the native-only cleanup candidate qualification.

Peak tracked allocations were 654.34 MiB. The first process ended with 651.55 MiB still allocated. Interval peaks rose from 364.51 MiB around ten minutes to 494.26 MiB around twenty minutes and 590.11 MiB around thirty minutes. Growing live data prevents treating this as a fixed-state plateau test. These quantities exclude allocator overhead and do not equal RSS.

| Innermost recorded caller | Retained MiB |
| --- | ---: |
| `commonware_actor::mailbox::new_unreliable (mailbox.rs)` | 135.12 |
| `commonware_storage::index::ordered::Index (ordered.rs)` | 111.44 |
| `vera_modules::kv_store::InMemoryKvStore (kv_store.rs)` | 78.80 |
| `commonware_runtime::iobuf::pool::BufferPoolInner (mod.rs)` | 72.91 |
| `vera_node::history::write (function.rs)` | 64.54 |
| `vera_modules::acp::policy_edit_budget::BudgetedEncoding (policy_edit_budget.rs)` | 63.67 |
| `vera_node::history::regolith_store::Snapshot (regolith_store.rs)` | 61.19 |
| `vera_modules::acp::policy_edit_budget::BudgetedEncoding (mod.rs)` | 24.23 |
| `commonware_runtime::iobuf::pool::BufferPool (mod.rs)` | 15.84 |

Each allocation is charged once to its innermost recognized project caller. This attributes an allocation path, not necessarily a unique owning component. Buffers returned by an encoder may remain in records or journals; a storage wrapper may appear above allocator internals. Retention at process exit alone does not establish a leak. Only 91,424 bytes remain unresolved after Rust symbol decoding.

The evidence identifies actor queues, ordered QMDB indexes, live ACP maps and encoded records, buffer pools and history as the next memory-review targets. It does not justify allocator replacement, weakened synchronous durability or a throughput claim. A fixed-state steady-load result and matched uninstrumented measurements are still needed to distinguish growing data, bounded caches and unwanted retention.

[Allocation workflow and numeric artifact](https://github.com/sourcenetwork/vera.rs/actions/runs/38116457453) at source `68287c9016672908f17e3a664cfc40716e56f252`.

The sustained profile investigates growth while live object count remains fixed.
The growing profile adds live state and helps distinguish dataset costs from
fixed-workload retention. Their instrumented results do not replace normal-release
resource measurements or by themselves prove a leak or bounded memory.

The diagnostic release build keeps its optimization settings, adds full debug
information without stripping symbols, and forces Rust frame pointers. These
settings are limited to the profiling workflow; normal release builds keep their
existing settings. Full debug information follows [Heaptrack's Rust guidance](https://github.com/KDE/heaptrack#enable-debug-symbols);
[frame pointers](https://doc.rust-lang.org/rustc/codegen-options/index.html#force-frame-pointers)
provide an additional stack-unwinding aid, without guaranteeing complete caller
coverage. A launcher execs the validator directly, preserving
its PID and inherited RPC listener. Only member3's first process receives the
Heaptrack preload library; the other validators, workload driver and restarted
member run without it. The production allocator and runtime source are unchanged.

The collector scans the folded trace once, interns distinct frames and aggregates
weights for identical stacks. It decodes the frame dictionary rather than rewriting
every allocation stack. Caller classification runs once per distinct frame;
weighted stack attribution preserves the original total and innermost-caller rule.
Inventory limits cover frame bytes, frame count, stack depth, unique stacks and
stored frame references. A byte-bounded memo speeds repeated-stack parsing.

Before symbol decoding, `allocation-summary.json` retains numeric heap samples,
total retained bytes, inventory counts and original unresolved bytes. It explicitly
marks caller attribution unqualified. A later decoder failure retains this
checkpoint and the completed workload evidence; only `allocations.json` qualifies
the completed caller analysis. Raw frames and stack identities remain private.

The artifact records source/binary/tool provenance, operation outcomes, interval peak
heap samples and the largest retained allocation callers. Each allocation is
charged once to its innermost resolved Vera, Commonware or Regolith frame, or the
innermost recognized allocator/library frame when no component frame is available. An
unresolved leaf cannot discard a recognized caller. Generic allocator names
identify an allocation mechanism; they do not establish the owning component. Heaptrack1.5's
folded stacks expose function names and file basenames; source paths and line
numbers are retained only when the installed tool includes them. Unresolved
frames remain explicit. Raw traces, node files and full profiler output stay in
a private runner directory and are removed when the profiling step ends.

`attribution_bytes` separates Vera/Commonware callers, Regolith callers, other
recognized library callers, generic allocator frames and unresolved stacks. These totals cover every
allocation, including callers omitted from the largest-50 table, and must sum to
`total_retained_bytes`. Low unresolved-symbol bytes alone do not establish
component ownership. The collector checks and records the diagnostic build
settings before starting a workload; encoded Rust flags that would override the
declared frame-pointer setting are rejected.

Regolith source locations omit private checkout paths and normalize registry and
Git checkouts to `regolith/src/`. Older artifacts lack the `regolith_caller`
category; their Vera/Commonware caller totals may include deeper Regolith
allocations and cannot establish the storage component's ownership.

Compare sampled heap peaks with previously measured RSS and bounded cache/pool
counters. Bytes retained when a process is stopped include ordinary live caches
and state; retention alone does not establish a leak. Instrumented throughput
and latency are diagnostic observations and must not be used as capacity numbers.
Heaptrack's own bookkeeping also adds memory outside the reported application
allocations. A suspected fix still needs confirmation without the profiler.

The collection mechanism follows [Heaptrack's preload implementation](https://github.com/KDE/heaptrack/blob/v1.5.0/src/track/heaptrack_preload.cpp).

Heaptrack1.5 writes Massif timestamps in seconds, including fractional values.
The collector normalizes these to integer milliseconds and rejects unknown units
or regressing samples. Massif `mem_heap_B` is the peak between timestamp samples,
not an instantaneous live-heap measurement; the artifact names it
`interval_peak_heap_bytes`. These details follow [the upstream Massif writer](https://github.com/KDE/heaptrack/blob/v1.5.0/src/analyze/print/heaptrack_print.cpp).
Workload provenance and outcomes are saved separately before allocation analysis,
so an extraction failure does not discard the completed workload evidence.

Rust v0 names need a separate decoder: [Heaptrack1.5 only demangles names with
an `_Z` prefix](https://github.com/KDE/heaptrack/blob/v1.5.0/src/interpret/dwarfdiecache.cpp#L215).
Before collecting a workload, the script checks GNU `c++filt` against a known
Rust v0 symbol. It then decodes folded stacks privately, preserving recursion
limits and checking that total allocation weights remain unchanged. The manifest
records the decoder version; numeric unresolved bytes are reported before and
after decoding. The existing source-name filter still governs public callers. Unresolved stacks
also retain weighted counts by fixed format categories: missing stack, missing
symbols, residual mangled symbols, and unrecognized symbols. No raw symbol names or
private paths are included in those categories.
Trace inventory and dictionary decoding have separate deadlines; work in one
phase cannot consume the next phase's budget. The dictionary still uses bounded
symbol batches and checks decoded frame coverage.
Decoding and classification preserve allocation accounting. The diagnostic build
settings affect the profiled binary, so comparisons must retain its manifest;
the production allocator remains unchanged.

The first successful RocksDB profile at `96b28a49` qualified all 6,000 operations,
all four replicas and full restart verification. It recorded 255,984,599 bytes
still allocated at process end; 235,325,360 bytes (91.93%) were unresolved by the
original extractor. Identified Marshal storage accounted for 12,629,024 bytes.
Interval peaks rose from about 241.3 MB at ten seconds to 256.0 MB at process end
(321.2 seconds).

The decoder-qualified profile at `6f236d9a` also completed and independently
verified all 6,000 operations on four replicas and checked all operations after
restart with zero receipt or state mismatches. It recorded 255,990,028 retained
bytes. Decoding reduced unresolved bytes from 235,330,809 to 234,426,189: only
904,620 bytes gained attribution, leaving 91.58% unidentified. This result does
not support assigning the bulk of memory to undecoded Rust names. The retained
caller table identifies 12,629,872 bytes in Marshal storage and 7,340,032 bytes
in RocksDB arena allocation. The extractor now preserves recognized callers
beneath unknown leaves and records unresolved format categories to distinguish
missing symbol coverage from unrecognized stack formats.

These are instrumented five-minute observations, not sustained memory bounds,
capacity measurements or identified leaks. Most allocation owners remain
unproven, so these results do not justify an allocator or cache-limit change.

The caller-preserving profile at `0b55d7e4` completed all 6,000 operations,
verified four replicas and checked every operation after restart with zero
mismatches. It recorded 256,278,302 retained bytes, with only 91,528 bytes of
unresolved symbols. However, 234,045,093 bytes (91.32%) were attributed to
`std::alloc::System`, which still does not identify their component owner.
That run used source line tables and the default frame-pointer setting, unlike
the full-debug/frame-pointer profile below.

The [full-debug profile](https://github.com/sourcenetwork/vera.rs/actions/runs/38004786626)
at `e2b83331` completed and independently verified all 6,000 operations on four
replicas, including restart verification with zero receipt or state mismatches.
It recorded 256,181,630 retained bytes: unreliable-mailbox allocation callers
accounted for 141,124,320 bytes, three buffer-pool callers for 90,814,948 bytes,
and unresolved stacks for 91,424 bytes. These allocation callers explain much
of this short profile's retained heap; they do not identify the cause of late
RSS growth in the thirty-minute normal-release measurements. Preallocated
queues and reusable pools are ordinary live allocations, and the process-end
weights do not prove a leak. Sustained heap qualification remains separate.
