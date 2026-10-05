# Vera architecture

Vera is a replicated authorization and coordination service. Independent Rust
processes agree on ordered revisions, execute the same access-control rules, and
return results that clients can verify. Operators control consensus membership.
DefraDB stores application documents; Vera stores policies, relationships,
identities, coordination records, and their certified history.

This describes the native implementation. Recovery qualification, deployment
packaging, and sustained capacity measurements remain open. Implementation is
not a claim of production qualification.

The [causal authorization design](causal-authorization.md) records the agreed
direction for offline policy and document histories, existing function boundaries,
and the unresolved revocation rules. That design is not yet an enabled ACP feature.

## Service boundaries

```mermaid
flowchart TB
    App[Application]
    Trust[Trust API · Go<br/>Authentication, API keys, relay, retries]
    Defra[DefraDB · Rust<br/>Documents and queries]
    Orbis[Orbis · Rust<br/>Application signing and encryption]
    subgraph Vera[Vera consensus group · Rust]
        V1[Member A]
        V2[Member B]
        V3[Member C]
        V4[Member D]
        V1 <-->|Simplex| V2
        V2 <--> V3
        V3 <--> V4
        V4 <--> V1
    end
    App --> Trust
    App --> Defra
    Trust -->|Native requests and verified evidence| Vera
    Defra -->|Native client: ACP and certified state| Vera
    Defra -->|Threshold service client| Orbis
    Orbis -->|ACP, ring records, bulletin| Vera
    Defra --- Documents[(Regolith document storage)]
    classDef service fill:#e8f1ff,stroke:#526c94,color:#142d50
    classDef storage fill:#e6f4ee,stroke:#527a68,color:#173d2c
    class Trust,Defra,Orbis,V1,V2,V3,V4 service
    class Documents storage
```

The consensus links are illustrative; they do not prescribe a ring topology.
Trust is optional for clients that authenticate and sign native requests directly.
It is a separate service, never part of consensus. Its native gateway currently
exposes identity and ACP operations; native bulletin and Orbis routes are not
integrated there. Direct Rust clients use those services independently.

## Inside one member

```mermaid
flowchart TB
    RPC[Native RPC] --> Admission[Bounded admission and pending requests]
    Admission --> Gossip[Authenticated peer transport]
    Gossip --> Consensus[Commonware Simplex]
    Consensus <-->|Propose and verify| Execute[Deterministic execution]
    Execute --> Modules[ACP · identity · bulletin<br/>membership · threshold records]
    Execute --> QMDB[(Commonware QMDB<br/>authenticated state)]
    Consensus --> Finalize[Durable finalization]
    Finalize --> QMDB
    Finalize --> History[(History and receipts<br/>RocksDB or optional Regolith)]
    Finalize --> Views[Published query state]
    Views --> Evidence[Read proofs and certified receipts]
    QMDB --> Evidence
    History --> Evidence
    Evidence --> RPC
    Membership[Finalized committee selections] --> DKG[Commonware DKG and resharing]
    DKG -->|Epoch signing material| Consensus
    Modules --> Membership
    classDef service fill:#e8f1ff,stroke:#526c94,color:#142d50
    classDef storage fill:#e6f4ee,stroke:#527a68,color:#173d2c
    class Consensus,Execute,DKG,Modules service
    class QMDB,History,Views storage
```

ACP is implemented in Rust through the local `acp`, `zanzibar`, and `identity`
crates. See [ACP v1 operations, authority and compatibility](acp-v1.md).
All members re-execute proposals against isolated state before accepting
them. Durable finalization precedes publication of query results.

QMDB commits seven persistent partitions: accounts, storage, code, ACP, bulletin,
Vera records, and native signer sequences. A coordinated commitment binds the
native state root to their selected operation-log targets. Regolith is an optional
**history** backend; it does not replace QMDB's authenticated state. Query module
views currently materialize live records in memory, so dataset growth still
affects memory use. See [storage](history-storage.md).

## Write, confirmation, and retry

```mermaid
sequenceDiagram
    participant Caller
    participant Gateway as Trust API
    participant Member as Vera member
    participant Group as Consensus group
    Caller->>Caller: Persist operation ID and exact request
    Caller->>Gateway: Authenticated mutation
    Gateway->>Gateway: Verify identity, limits, and relay scope
    Gateway->>Gateway: Journal signed submission and signer sequence
    Gateway->>Member: Submit native request
    Member->>Group: Gossip admitted request
    Group->>Group: Order, re-execute, finalize, persist
    Gateway->>Member: Request receipt and operation evidence
    Member-->>Gateway: Certified result
    Gateway->>Gateway: Verify evidence with Rust verifier
    Gateway-->>Caller: Original result and certified revision
    opt Response lost or confirmation uncertain
        Caller->>Gateway: Recover using the same operation ID and request
        Gateway->>Member: Read certified outcome or retry authorized request
        Member-->>Gateway: Original completed outcome, when retained
        Gateway-->>Caller: Verified result or explicit uncertainty
    end
```

Admission is not confirmation. A timeout does not establish failure. Supported
delegated ACP operations bind the caller's operation ID and exact arguments to
their result; authorized retries return the original successful outcome without
reapplying its effects. Expired IDs cannot execute again. See
[operation identities](operation-identities.md).

Native Vera still enforces sequences per signing identity. Independent gateway
signers provide concurrent submission lanes; their durable journals prevent
sequence reuse after restart. Fee provisioning is unnecessary for this native
path. Reads and local policy validation do not allocate a submission lane.

## ACP reads

```mermaid
sequenceDiagram
    participant Client as Client or gateway
    participant Member as Vera member
    participant Verify as Local Rust verifier
    Client->>Member: Permission query and minimum revision
    Member->>Member: Capture one finalized state and bounded evidence
    Member-->>Client: Revision certificate and complete ACP evidence
    Client->>Verify: Independently configured trust and evidence
    Verify->>Verify: Verify certificate, state root, records and completeness
    Verify->>Verify: Evaluate the Rust ACP policy
    Verify-->>Client: Allowed or denied at the certified revision
```

A remote permission boolean alone is insufficient. A permission read describes
the selected revision; it does not reserve future authority. Mutations check
authorization during execution. Stored access decisions have explicit issuance
and expiry semantics. See [permission proofs](permission-proofs.md) and
[access decisions](access-decisions.md).

## Operator-managed membership (PoA)

PoA describes who may join the consensus group. Commonware Simplex supplies
Byzantine fault-tolerant agreement within that group. Operator approval authority,
ACP permission to manage membership, and consensus signing shares are distinct.

```mermaid
flowchart TD
    Operators[Configured operator approval quorum]
    Operators --> Policy[Initialize membership-management ACP policy]
    Policy --> Request[Authorized register, deactivate, or remove request]
    Request --> Receipt[Certified registry update]
    Receipt --> Cutoff[End of epoch e: record roster for e + 3]
    Cutoff --> Announce[End of e + 1: publish lookahead selection]
    Announce --> Reshare[Distributed resharing]
    Reshare --> Outcome{Ceremony succeeds?}
    Outcome -->|Yes| Effective[New committee becomes effective]
    Outcome -->|No| Retain[Prior signing output retained]
    Effective --> Verify[Verify effective committee and current share readiness]
```

A registry receipt alone does not prove admission. Operators must verify the
effective committee and the incoming process's current signing readiness before
reducing the existing quorum. Epoch length also limits committee size; the
registry's protocol cap is 64 entries. See [membership](consensus-membership.md).

## Two separate threshold systems

| System | Purpose | Authority and secrets |
|---|---|---|
| Commonware consensus DKG | Generate consensus shares and reshare across membership changes | Consensus group; local consensus secret store |
| Orbis application protocols | Application signing, encrypted secret recovery, participant replacement | Application rings; ACP permissions; separate application shares |

The bulletin carries authorized coordination messages. Vera also records ring,
participant, controller, and report state. Orbis executes the application
protocols. Commonware's DKG primitives do not supply those protocols wholesale;
consensus secrets must never serve as application keys. See
[threshold capabilities](threshold-capabilities.md).

## Snapshot recovery

```mermaid
flowchart LR
    Trust[Provisioned genesis and peers] --> Probe[Discover certified epoch and floor]
    Probe --> Transfer[Transfer authenticated QMDB state]
    Transfer --> History[Recover history at selected state revision]
    History --> Hydrate[Hydrate and validate query state]
    Hydrate --> Ready[Publish service readiness]
    Transfer -. Needs newer finalized targets when peers prune .-> Progress[Consensus and epoch progress]
    Probe --> Reshare[Resharing with certified boundary rosters]
    Reshare --> Progress
    Progress --> Transfer
```

Resharing runs during database initialization so epoch progress can supply newer
transfer targets when peers prune. Before execution rosters are available, the
membership provider reads the requested selection from a finalized epoch boundary
in the consensus archive and validates its height and selected epoch. Admission
and RPC still wait for database and history recovery. Startup supervision and a
configurable deadline bound failures; successful recovery still depends on peer
availability and retention.
Proposals are skipped and verification remains pending until execution state is
ready, before either can request speculative DKG artifacts.
A stale target whose floor has aged out of peer retention can stop marshal's
finalized dispatches; startup watches that progress and, after a configured
stall, re-floors marshal from the newest stored gossiped finalization so
dispatches resume from a retained anchor. The sync completes at its reached
target and settles on the newest one at the first update lull, converging
without requiring network quiescence.
See [snapshot recovery](snapshot-recovery.md) and [history storage](history-storage.md).

## Implementation map

| Concern | Source |
|---|---|
| Actor assembly and startup supervision | [`vera-node`](../crates/vera-node/src/node.rs) |
| Committee selection | [`participants.rs`](../crates/vera-node/src/participants.rs) |
| Proposal execution and finalized state | [`vera-app`](../crates/vera-app/src), [`vera-executor`](../crates/vera-executor/src) |
| Product rules | [`vera-modules`](../crates/vera-modules/src) |
| Native requests and verified reads | [`vera-client`](../crates/vera-client/src) |
| Shared verifier for Go consumers | [`vera-verifier`](../crates/vera-verifier/src) |

For deployment and diagnostics, start with [operating](operating.md). Performance
claims must distinguish submission capacity, finality latency, certified receipt
latency, and completed application workflows; see [workloads](native-workload.md).

See the [native integration baseline](native-integration.md) for exact tested
consumer revisions, build features and reproducible process checks.
