# ACP v1 behavioral fixtures

This tool runs `github.com/sourcenetwork/acp_core` **v0.8.2**, the version used by
Go Vera at `205df1adcd27a350168b14fe49b9160387acba93`. It uses the real engine with
its in-memory runtime. No Go service or library is required by the Rust node.

From this directory, regenerate the checked-in fixture atomically:

```sh
go run -mod=readonly . < cases.json > cases.generated.json &&
  mv cases.generated.json ../../crates/vera-modules/tests/fixtures/acp_v1.json
```

From the repository root, replay it in Rust:

```sh
cargo test --locked -p vera-modules --test acp_go_parity
```

Cases compare success/error, access and management decisions, ownership,
metadata and edit pruning counts. Rust also checks error atomicity and restores
and validates its store after every operation. Timestamps, error wording and
transport encodings are deliberately not compared. The driver names the existing
Rust syntax extensions explicitly; see [ACP v1](../../docs/acp-v1.md).

The fixture is an independent regression reference, not an exhaustive proof of
equivalence. Add a source case, regenerate with Go, and commit both input and output
when changing behavior. Rust CI consumes the fixture without fetching or running Go.
