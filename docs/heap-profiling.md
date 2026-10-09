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
heap samples and the largest retained allocation owners. Each allocation is
charged once to its innermost resolved Vera/Commonware frame. Heaptrack1.5's
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
after decoding. The existing source-name filter still governs public owners.
This improves attribution without changing the measured binary or allocator.

The first successful RocksDB profile at `96b28a49` qualified all6,000 operations,
all4 replicas and full restart verification. It recorded255,984,599 bytes still
allocated at process end;235,325,360 bytes (91.93%) were unresolved by the original
extractor. Identified Marshal storage accounted for12,629,024 bytes. Interval
peaks rose from about241.3MB at10seconds to256.0MB at process end (321.2seconds).
Those figures describe one instrumented five-minute workload, not a sustained
memory plateau or an identified leak. The missing symbol coverage prevents
assigning most bytes to a component; corrected decoding requires fresh evidence.
