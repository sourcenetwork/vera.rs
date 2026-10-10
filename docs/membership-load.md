# Membership changes during access updates

The pipelined case in `crates/vera-e2e/tests/native_membership.rs` runs a separate
ACP writer while a fifth validator joins without a bootstrap share, restarts,
and replaces an original member. It then checks that the surviving quorum can
still finalize writes. The original admission, epoch-material, share persistence
and participant checks remain active.

`support/membership_load.rs::Load::start` creates one independent policy/object
and begins alternating grants and revocations for one reader. Each operation
requires a verified successful receipt and matching current permission evidence.
The first complete grant/revocation cycle finishes before admission starts.
The loop waits 200 ms between cycles; this is a correctness workload rather than
a throughput benchmark.

`Load::finish` requests one final cycle after the last membership write. Its
revocation must finalize at a later height. All three surviving replicas,
including the admitted validator, must publish that height and provide verified
current evidence denying access. Existing receipt and membership deadlines stay
unchanged. Dropping the fixture aborts its writer task.

The focused `Native membership under load` workflow builds the normal release
validator and executes exactly the pipelined case. Its driver requires one passed,
zero failed and zero ignored tests, at least two grant/revocation cycles, and
three verified replicas. Raw output stays in the runner's temporary directory;
only bounded counts, heights and a failure location appear in the job output.
This single-host scenario does not qualify WAN behavior, overload or capacity.
