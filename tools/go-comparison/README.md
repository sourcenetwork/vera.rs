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

The manual `Go comparison fixture` workflow compiles and qualifies this side of
the comparison. Its small default run is a harness check. A Go/Rust speedup needs
both implementations measured sequentially on the same host with these matched
parameters, independently checked raw observations and documented differences in
consensus timing, signature scheme, storage and result-proof availability. Neither
this harness nor the historical results establish that comparison by themselves.

Fixture data, keys, logs and failed-command messages stay in the private output
directory. Only explicitly selected successful observations, resource samples,
manifest, public genesis and execution proof are suitable for CI artifacts.
