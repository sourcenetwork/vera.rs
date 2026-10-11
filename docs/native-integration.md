# Native integration baseline

The current Linux version set and source-bound results are in
[native qualification, October 11](native-qualification-20261011.md). The baseline
below records the earlier September checks.

This version set passed the focused local integration checks below on macOS
arm64 on September 19, 2026. Validators, the Go gateway and Rust threshold
services remain separate processes. Native fixtures disable legacy EVM execution.

| Component | Revision | Build selection |
|---|---|---|
| Vera and shared verifier | `cf5ae4751867b4b8f07f7b31bfc2ca68ff052ca4` | Rust 1.98.0; native-only pipelined genesis |
| Backbone proof client | `5ad4d5566acec208486041d0c647c859e481dc10` | `acp-light-client` |
| Defra | `7f4900735af348485575920f163a5954f9fe4a3d` | CLI built with `sourcehub` |
| Orbis | `e650290ed98d40b3feb868a8b76503af0a7bf3a8` | Default features disabled; `native,bls12-381,iroh` |
| Trust API | `fd13157503c95c0cb9b62ebfa63ff81040f2bdfe` | Go 1.26.6; `vera_native` and CGo |

Backbone, Defra and Orbis lockfiles resolve one Vera source revision. Orbis also
pins the listed Backbone and Defra revisions. Trust links the matching Vera
shared verifier; see [building and loading the verifier](native-verifier.md).
The tested validator executable was built at `ae7b84bf7b`; the listed Vera
revision adds only the Go gateway test and documentation to that runtime.

## Verified workflows

- Backbone: 16 proof-client, finality and transport tests, including forged
  evidence, stale state and response bounds.
- Defra: 14 native-provider tests and five process cases covering pending worker
  recovery, protected document and commit-history permissions/revocation,
  archived-owner rejection, exclusions and cross-object rules.
- Orbis: the distributed native workflow covers application signing, encryption,
  authorization revocation, interrupted resharing and recovery, with the aligned
  Defra libraries and four Vera validators.
- Trust: the separate Go gateway workflow runs before validator restart, after
  restart and after relay revocation. The tested gateway uses its embedded store;
  external Rust Defra identity-store integration is a separate check.

Focused lint checks passed for the changed consumer targets. These checks do
not establish multi-host deployment, WAN behavior, production capacity, Linux
image packaging or resolution of the separately tracked recovery timeout.

## Reproduce the process checks

Check out the listed revisions. Build `verad`, the shared verifier and Defra's
CLI before running the tests; provide absolute executable paths. Run commands
from the corresponding repository and use Rust 1.98.0.

Defra:

```sh
cargo build --frozen -p cli --features sourcehub
DEFRA_RUST_BINARY=/path/to/defra VERAD_BINARY=/path/to/verad RUST_LOG=info \
cargo test --frozen -p integration-test --test hubrs -- \
  --test-threads=1 --skip p2p --skip smoke --skip compartments
```

Orbis:

```sh
VERAD_BINARY=/path/to/verad cargo test --frozen -p orbis-node \
  --no-default-features --features native,bls12-381,iroh \
  --test native_startup native_distributed_threshold_workflows -- \
  --ignored --exact --nocapture
```

Trust's Go binaries and the Vera harness invocation are described in
[the verifier integration instructions](native-verifier.md).
