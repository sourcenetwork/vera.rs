# Native allocation attribution

The **Native heap profile** workflow runs the existing four-validator fixed-state
workload against 128 objects, offering 6,000 updates at 20 per second. It preserves
certified permission reads, all-replica verification and full restart checks.
Select RocksDB or Regolith for the history backend when dispatching it.

The release build keeps its optimization settings and adds source line tables
without stripping symbols. A launcher execs the validator directly, preserving
its PID and inherited RPC listener. Only member3's first process receives the
Heaptrack preload library; the other validators, workload driver and restarted
member run without it. The production allocator and runtime source are unchanged.

The artifact records source/binary/tool provenance, operation outcomes, interval peak
heap samples and the largest retained allocation callers. Each allocation is
charged once to its innermost resolved Vera/Commonware frame, or the innermost
recognized allocator/library frame when no component frame is available. An
unresolved leaf cannot discard a recognized caller. Generic allocator names
identify an allocation mechanism; they do not establish the owning component. Heaptrack1.5's
folded stacks expose function names and file basenames; source paths and line
numbers are retained only when the installed tool includes them. Unresolved
frames remain explicit. Raw traces, node files and full profiler output stay in
a private runner directory and are removed when the profiling step ends.

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
This improves attribution without changing the measured binary or allocator.

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
