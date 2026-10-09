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

The artifact records source/binary/tool provenance, operation outcomes, live
heap samples and the largest retained allocation owners. Each allocation is
charged once to its innermost resolved Vera/Commonware frame. Heaptrack1.5's
folded stacks expose function names and file basenames; source paths and line
numbers are retained only when the installed tool includes them. Unresolved
frames remain explicit. Raw traces, node files and full profiler output stay in
a private runner directory and are removed when the profiling step ends.

Compare live heap growth with previously measured RSS and bounded cache/pool
counters. Bytes retained when a process is stopped include ordinary live caches
and state; retention alone does not establish a leak. Instrumented throughput
and latency are diagnostic observations and must not be used as capacity numbers.
Heaptrack's own bookkeeping also adds memory outside the reported application
allocations. A suspected fix still needs confirmation without the profiler.

The collection mechanism follows [Heaptrack's preload implementation](https://github.com/KDE/heaptrack/blob/v1.5.0/src/track/heaptrack_preload.cpp).
