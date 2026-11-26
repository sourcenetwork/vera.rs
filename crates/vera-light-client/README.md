# vera-light-client

Proof-validated ACP reads for applications that gate on Vera state, such as
DefraDB's query gate and Orbis's signing gate. It follows finalized headers,
bounds revision freshness, tracks the active term and caches verified records.
Consumers previously took this crate from the Backbone repository as
`acp-light-client`; the API is unchanged apart from the crate name.

## Installation

```toml
[dependencies]
vera-light-client = "0.2.0"
```

A consumer that keeps its `acp_light_client` imports can rename the package:

```toml
[dependencies]
acp_light_client = { package = "vera-light-client", version = "0.2.0" }
```

## Behaviour

The client verifies native Vera records and permission evidence against a consensus
key provisioned by the operator. It uses `vera_getCurrentRecordProof` for policy
and persisted access-decision records, `vera_getCurrentPolicyPrefixProof` for
ownership and relationship reads, and `vera_getCurrentPermissionProof` for
permission evaluation. Each response pairs the evidence with its certified revision.
Ownership and relationships require a live policy, matching relation generations and
current target-object incarnation at that same revision. Keys use
`relationship/v5/{policy}/{target:016x}/{subject:016x}/` followed by the canonical
`v3` suffix containing the incarnation. Specialized proofs require an `objects`
array of same-root object-state witnesses for non-owner rows; authenticated absence
means initial incarnation zero, while a missing witness is an error. Owner rows use
incarnation zero and need no object witness. Retained cleanup records cannot restore
a grant after relation recreation or object unarchiving. Older namespaces and proof
shapes are rejected; this fresh-state cutover has no backfill. HTTP responses and
header messages are bounded before deserialization.

The verifier accepts up to 256 operations per revision while retaining the
shared encoded-byte limits.

Each request requires at least the latest verified height. A newer certified response
can advance the client's tracked revision ahead of its header subscription. Delayed
headers cannot move that state backward; repeated certificates cannot renew its
monotonic freshness lifetime. A delayed response at a superseded root is rejected.
Cached records are usable only at the same module root and within the configured
height and revision-age bounds. Ownership, relationships and permission results are
evaluated from fetched evidence; physical record cache entries do not establish
policy, generation or incarnation liveness.

`read_relationship` and `cache::keys::relationship_key` require an explicit shared
`RelationPair`. Derive its identities from the current authenticated policy catalogue;
do not use `(0, 0)` for arbitrary relations. The owner helper selects the permanent
owner pair and incarnation zero. Non-owner suffixes require the authenticated current
object incarnation. A retained inactive exact key is an error, while certified absence is
returned as `None`; neither authorizes access.

`read_object_owner` returns an object's live owner, or `None` when it has none.
`read_object_registration` reads the same complete owner evidence and classifies it
with Vera's `verify_object_registration` at one certified revision: `Live(owner)`,
`Archived` or `Absent`. An archived object has no owner and authorizes nothing, but
unlike an absent one it cannot be registered again unless its previous owner
unarchives it. An object without an owner record, or whose policy is absent, is
`Absent`. `ProofClient::read_current_object_registration` performs the same read at a
caller-chosen minimum height and also returns the revision.

`read_policy`, `read_relationship` and `read_access_decision` return authenticated
record data, not an authorization decision. `verify_access` evaluates the full
request with the shared ACP evaluator. `verify_access_decision` checks a persisted
successful decision against its exact submission and expiry; it does not establish
permission after subsequent revocation or authorize a payload by itself.

The default freshness policy permits revisions less than 30 seconds old and at most
15 seconds in the future. Transport operations have a ten-second deadline. A caller
may configure stricter age and clock-skew bounds. Arbitrary historical native record
reads are not provided.

Header synchronization uses `vera_subscribeHeaders` and accepts `vera_header`
notifications only for the acknowledged subscription ID. The acknowledgement
must arrive within ten seconds. Notifications still require independent finality
verification before they can advance cached state.

## License

Licensed under the MIT license. See the included license file.

This crate depends on [`orbis-reporting`](https://crates.io/crates/orbis-reporting),
which is licensed under the Business Source License 1.1. Its terms restrict
managed-service use and change to Apache 2.0 on March 13, 2030; review them
before use.
