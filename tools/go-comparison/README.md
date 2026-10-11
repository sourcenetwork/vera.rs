# Go registration comparison fixture

This harness starts four private, disk-backed Go validators and measures signed
registrations. It verifies transaction inclusion and successful execution against
adjacent signed headers using the independently generated genesis committee.
It then reconciles receipts and owners on every replica before and after an
all-node process kill and restart. Owner queries check RPC consistency; they do
not supply an authenticated state proof.

The reference source is Go Vera `ce83826bfeb4ce0fdc1751fc6a28cd4b9c7e7933`,
the source used for the earlier Go baseline. This is a pinned reference, not a
claim about the latest Go release. The fixture uses GoLevelDB and a 200 ms commit
timeout. It does not alter Vera's Rust deployment or add a Go runtime to it.

`main.go` and `verify.go` build inside that reference checkout's existing module;
they use its locked SDK and CometBFT dependencies. Copy them and `verify_test.go`
to a new `comparison-driver` directory, then build:

```sh
go build -mod=readonly -p 2 -trimpath -o /private/output/go-verad ./cmd/verad
go build -mod=readonly -p 2 -trimpath -o /private/output/go-driver ./comparison-driver
```

From the Rust repository, run with an output directory that does not exist:

```sh
python3 tools/go-comparison/run.py \
  --node /private/output/go-verad --driver /private/output/go-driver \
  --source-root /reference/go-vera \
  --source ce83826bfeb4ce0fdc1751fc6a28cd4b9c7e7933 \
  --output /private/output/go-run --count 600 --workers 600 --rate 20
```

One account per registration, numeric object IDs, one shared `baseline` policy,
zero permission reads, 128 outstanding workflows and a 50 ms receipt poll match
the Rust registration baseline's logical workload. Signing occurs before the
driver's measured interval. The Go fixture accepts smaller worker counts for
separate sequence-contention experiments; those do not match Rust's one-signer-
per-registration workload and must not be compared as equivalent runs.

Run `TestCertifiedExecution` in the Go checkout with `VERA_GO_EVIDENCE` set to the
output directory and `VERA_GO_GENESIS` to its `genesis.public.json`. Its negative
cases alter results, transactions, proof roots, signatures, committee and network
identity using the captured real proof. They require rejection of forged evidence.

The manual `Go comparison fixture` workflow defaults to a small Go harness check.
Set `paired=true`, `count=600` and `rate=20` for two fresh passes per implementation
on the same hosted runner, in Go/Rust/Rust/Go order. Both binaries build before any
measurement. The Rust node uses normal release settings, pipelined consensus,
192-revision epochs and 256-revision consensus retention. Each pass reconciles all
four replicas; Go restarts all validators and Rust recovers one replica after a
three-voter write. Recovery happens outside the measured interval.

`compare.py` rejects source, binary, host, signer-count and logical-workload drift,
failed or missing observations, summary contradictions and missing recovery or
proof-rejection checks. It produces raw percentile tables, observed completed
registrations per second and a CDF plot. The observed median p95 ratio describes
these passes, not statistical confidence, maximum capacity or a WAN result.
Go authenticates successful execution using the next signed header; Rust binds
the result to its finalized revision. Signing schemes, history storage and
consensus timing differ. Go resource sampling includes driver preparation, so the
report does not compare RSS between implementations. Existing measurements from
different machines cannot substitute for this paired run.

Fixture data, keys, logs and failed-command messages stay in the private output
directory. Only explicitly selected successful observations, resource samples,
manifest, public genesis and execution proof are suitable for CI artifacts.
