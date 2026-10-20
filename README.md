# Vera

Vera is a Rust service for access control, identity, coordination, and verifiable
history. An operator-managed group uses Commonware Simplex to agree on ordered
revisions. Clients verify certified results against independently provisioned
trust.

**Start with [the architecture guide](docs/architecture.md)** for diagrams of the
services, write and read flows, membership changes, storage, and recovery.

| Service | Responsibility |
|---|---|
| Vera | Rust ACP execution, certified state and history, bulletin, consensus membership |
| DefraDB | Application documents and queries; consumes Vera authorization |
| Trust API | Optional separate Go gateway for authentication and managed native requests |
| Orbis | Separate Rust application threshold signing and encryption services |

The native stack uses Commonware DKG for consensus shares, local Rust ACP crates
for permission evaluation, and Commonware QMDB for authenticated state. History
uses Regolith with synchronous durable writes. Application threshold
protocols and secrets remain separate from consensus.

## Guides

- [Architecture and flows](docs/architecture.md)
- [Operator-managed membership](docs/consensus-membership.md)
- [Policies](docs/native-policies.md) and [verified permission reads](docs/permission-proofs.md)
- [Submission retries and operation identities](docs/operation-identities.md)
- [Consensus and application threshold capabilities](docs/threshold-capabilities.md)
- [Operating a member](docs/operating.md), [storage](docs/history-storage.md), and [snapshot recovery](docs/snapshot-recovery.md)
- [Performance reports and benchmark jobs](docs/performance.md)
- [Native workload measurement](docs/native-workload.md)
- [Release qualification and operating limits](docs/release-qualification.md)
- [Native consumer qualification and tested versions](docs/native-qualification-20261014.md)

## Development

The repository pins Rust 1.98.0. Build the service with:

```sh
cargo +1.98.0 build --frozen -p verad
```

See [CLAUDE.md](CLAUDE.md) for implementation structure and development conventions.

## Qualification status

The [release qualification record](docs/release-qualification.md) collects local
workload limits, recovery/security coverage and the tested consumer versions.
The fixed and growing resource profiles passed; their measurements do not imply
a hard RAM ceiling for arbitrary datasets. The
[first-release checklist](docs/release-qualification.md#first-release-crates-and-daemon-artifacts)
covers package publication and automated releases. The pending Commonware DKG
boundary retry, unmerged Orbis service qualification and
[four-host WAN test](docs/wan-gates.md) are follow-up work.
Earlier unexplained readiness/read failures
retain their documented limits; later passing checks do not establish their cause.
