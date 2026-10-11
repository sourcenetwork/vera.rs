# Verified record and permission reads

The native node serves a finalized revision and its Commonware permission evidence together through `vera_getCurrentPermissionProof`. `vera_getPermissionProof` accepts a caller-selected revision when its evidence is available. `vera_getCurrentRecordProof` provides native record membership and absence; `vera_getCurrentPrefixProof` proves complete current prefixes. The service exposes authenticated native QMDB evidence only. `vera_getStateProof`
and `vera_getRelationProof` are not registered; record and complete-prefix reads
use the native endpoints below. The server no longer provides JMT storage or
relationship cardinality indexes.

## Native record reads

`vera_getCurrentRecordProof(module, key, minimum_height)` returns
`{ "revision": LightBlock, "record": RecordProof }`. Modules are `acp`,
`bulletin`, `vera` and `native_nonce`; `key` is a hex byte string. The record
contains the exact module and key, an optional value, all four namespace roots
and canonical Commonware membership or exclusion evidence. A missing value is
accepted only with a valid exclusion proof.

The server captures the record under all four partition read locks and releases
those locks before obtaining its matching finalization certificate. Selection
and certificate lookup share a two-second timeout. An unavailable revision or
unmet minimum returns `RESOURCE_UNAVAILABLE`; it is not proven absence. A
deadline exceed is also `RESOURCE_UNAVAILABLE` with `retryable: true`.

`VeraClient::read_current_record` bounds the response before deserialization and
verifies the certificate with the caller's consensus key. `RecordResponse::verify`
binds the requested module and key, minimum revision, combined module root and
record evidence. Callers must provide any additional timestamp or age policy.
An earlier captured record may finish after a later update; callers requiring
that update must supply its finalized revision as the minimum.

Keys are limited to 64 KiB and values to 1 MiB. Serialized record evidence is
limited to 4 MiB; clients may impose a tighter bound. The transport budget adds
`LIGHT_BLOCK_RESPONSE_BYTES` and 1 KiB for the RPC envelope. Merkle and record
field bounds also apply during binary proof decoding. These limits do not
establish aggregate concurrency or throughput guarantees.

These are current-state reads. They do not provide arbitrary historical native
record proofs. Record existence alone does not authorize an operation: consumers
must validate record semantics or use verified permission evaluation.

## Native prefix and owner reads

`vera_getCurrentPrefixProof(module, prefix, minimum_height)` returns
`{ "revision": LightBlock, "prefix": PrefixProof }`. It captures a complete
ordered prefix under the four native partition read locks, then releases them
before fetching the matching certificate. `VeraClient::read_current_prefix`
verifies finality, the requested module/prefix and minimum revision, combined
roots, the prefix boundary and every successor. Omitting the first or last
record, truncating the scan, changing a value or mixing roots fails verification.

Prefix requests allow at most 64 KiB of prefix bytes, 4,096 records, 1 MiB of
prefix/key/value bytes and 4 MiB of serialized evidence. The transport uses
`RECORD_RESPONSE_BYTES`, including bounded finalization artifacts. Oversized
scans fail; they do not return a partial list. Selection and certificate lookup
share a two-second deadline whose exceed is a retryable `RESOURCE_UNAVAILABLE`
error. Callers supply any additional revision-age policy.

Generic record, prefix and page proofs describe physical storage. Deleted policies
can retain relationship records while bounded cleanup runs, so physical inclusion
alone does not establish current ownership or policy membership.

`vera_getCurrentPolicyPrefixProof(policy, prefix, minimum_height)` returns
`PolicyPrefixResponse`: a finalized `revision` and `proof` containing `policy`,
`objects`, and `prefix`. `objects` is a required array of object-incarnation
`RecordProof` witnesses, one per distinct non-owner target in the physical rows,
including obsolete rows. Owner-only prefixes carry an empty array. The server
captures all witnesses under the same partition locks.

`VeraClient::read_current_policy_prefix` and `PolicyPrefixResponse::verify`
authenticate the policy key, requested prefix, identical roots, finality and
minimum revision. Policy and object witnesses share limits of 256 reads, 4,096 present
records, 1 MiB data and 4 MiB serialized-proof budgets with the prefix. Data charges
include selection bytes and every point/relationship key and value. Certified
policy absence returns `None` only after validating the complete evidence;
invalid or unavailable evidence remains an error.

Object points use `object_state/{policy}/{resource_hex}/{object_hex}`. A present
value must be a positive eight-byte big-endian counter; authenticated absence
means initial zero. Missing coverage is an error. Extra or duplicate witnesses,
mixed roots, malformed points, and a row incarnation ahead of its object state
are errors. Every row must carry a mandatory incarnation matching its canonical
v5 key before liveness filtering. Owners always use zero and need no object point.

`object_owner_prefix(policy, object)` constructs the canonical owner prefix.
`PolicyPrefixResponse::verify_object_owner` also checks each relationship against
its canonical key and requested policy/object, returning the single live actor.
Absent policies, empty ownership and entirely archived ownership return `None`.
Malformed records, conflicting live owners and unavailable evidence are errors.
Ownership alone does not replace permission evaluation. Set the minimum revision
to the finalized deletion height when a read must observe that deletion.

`vera_getCurrentPolicyPrefixPageProof(policy, request, minimum_height)` returns
`PolicyPrefixPageResponse` with `policy`, required `objects`, and `page` proofs.
The request selects the ACP module and a prefix belonging to that policy. The
response shares one finalized root and aggregate limits of 256 reads, 4,096
present point/relationship records, 2 MiB of selection/key/value data and 8 MiB
of serialized proof. A page contains at most 128 physical relationship rows;
object witnesses are charged within the aggregate limits, not another allowance.

`VeraClient::read_current_policy_prefix_page` verifies the combined response;
`read_relationship_page` also returns typed records. Certified policy absence
yields no records or continuation. Pages filter obsolete relation generations
and object incarnations while preserving the physical continuation, so an empty
page may still continue. A complete policy-prefix response instead rejects any
inactive row: it cannot expose a filtered subset as a complete successor chain.
The page revision rules below still apply; pages do not create a historical snapshot.

These policy-scoped responses replace raw prefix responses for current ownership
and relationship interpretation. Generic proof endpoints remain physical storage
APIs. The fresh-state [`relationship/v5/` namespace](native-relationship-keys.md),
mandatory record incarnation and object witnesses require matching consumer
verification. There is no legacy dual reader or fallback to raw inclusion.
Receipt/finality formats and transport envelope allowances are unchanged.

## Permission requests

`vera_getCurrentPermissionProof(policy, request, minimum_height)` returns
`{ "revision": LightBlock, "proof": PermissionProof }`. The server selects its
current finalized revision, requires its height to meet the supplied minimum,
and captures permission evidence while holding all four native partition read
locks. It releases those locks before waiting for the selected revision's
certificate. State advancing during that wait does not change the captured
response. If the finalized index temporarily trails the databases, selection
retries after releasing the locks. Selection and certificate waits share a
two-second timeout; this is not a bound on synchronous evaluation or storage
work. Exceeding it returns `RESOURCE_UNAVAILABLE` with `retryable: true`, since
the evidence is delayed rather than absent.

`VeraClient::verify_current_access` fetches this response once, verifies the
certificate against the caller's independently provisioned consensus key,
enforces the minimum height, and evaluates the requested permission using the
authenticated evidence. It returns the verified revision and local decision.
The caller supplies any additional timestamp or age policy. A request captured
before a revocation may finish afterward with the earlier revision; requiring
the revocation's finalized height prevents accepting that earlier response.

An unavailable revision, unmet minimum or expired server timeout returns
`RESOURCE_UNAVAILABLE` (`-32002`), never an access decision. The client applies a
ten-second transport timeout and bounds bytes before JSON deserialization,
including chunked responses. Its response budget is
`LIGHT_BLOCK_RESPONSE_BYTES + limits.proof_bytes + 1024`, covering revision
artifacts, permission evidence and the RPC envelope. Verification separately
checks revision and proof limits. The service uses `PERMISSION_LIMITS` and the
corresponding `PERMISSION_RESPONSE_BYTES` transport bound.

`vera_getPermissionProof(policy, request, height)` returns the policy and relationship evidence needed to evaluate an `AccessRequest` at the requested finalized revision. The request contains an actor DID and one or more operations, each naming an object resource, object ID and permission. The response contains tagged point and complete-prefix reads. It carries no authoritative allow/deny flag.

`vera_permission::verify_permission_proof` authenticates every read against the caller's trusted module root and height, then runs the shared ACP evaluator on the caller's policy ID, actor and operations. Missing coverage remains an error, including within an exclusion. Proven policy absence returns false. Duplicate reads, mixed revisions and malformed records are rejected. Repeated reads consume the evaluation budget even when they use the same evidence.

Permission capture includes object-state point reads through the shared evaluator.
These points consume the existing read budgets and authenticate at the same root
as the policy, directories and relationship prefixes. Missing object coverage is
an error, including for an exclusion; proven absence selects initial incarnation
zero. An archived-away grant cannot authorize through a stale physical row.

Direct entity-set grants follow the referenced object's named relation, including
nested groups and computed permissions. Cycles do not grant access, and revoked
memberships stop granting at the selected revision. Nodes and verifying consumers
must use the same shared ACP evaluator revision; different evaluator versions can
disagree even when they authenticate the same state.

`VeraClient::verify_access_at` verifies a supplied finalized revision against an independently configured consensus key, fetches bounded evidence and evaluates it locally. It checks the HTTP response size before deserialization, including chunked responses, checks the JSON-RPC request ID, and applies a ten-second request timeout. The caller controls revision freshness. The method does not fall back to an older revision or interpret unavailable evidence as a denial or grant.

Service limits are 64 operations, 64 KiB of serialized policy ID and request, 256 evaluation reads, 4,096 returned records across those reads, 1 MiB of request-key and returned-record bytes, and 4 MiB of serialized evidence. Client transport permits the proof limit plus 1 KiB for the RPC envelope. Clients may impose tighter limits. These read limits do not bound pure expression work or establish a sustained-throughput guarantee.

The server captures reads from one immutable current module snapshot, generates evidence at the requested revision and verifies the resulting request before returning it. Changes in membership or policy can make historical evidence unavailable. Every successful response nevertheless evaluates entirely against the requested revision. Client verification is independent of the server's capture decisions.

## Ordered Commonware evidence

Permission requests use ordered Commonware QMDB module storage. The native node
configures its server with `with_vera_native_modules`. The service exposes native
record, prefix and permission endpoints.

Permission evidence includes `roots`, the four namespace roots in ACP, bulletin, identity and
sequence order. Their combined commitment must match the caller's verified
revision. Reads use `kind: "current_point"` or `kind: "current_prefix"`, with
canonical Commonware evidence encoded as hex bytes. A point carries its key and
optional value; absence requires an exclusion proof. A prefix carries an
authenticated boundary followed by the complete ordered successor chain. A
missing successor, reordered record or substituted value invalidates the proof.
Every permission read uses native QMDB evidence and the shared ACP evaluator.
Missing namespace roots and retired JMT read variants are rejected.

Generation holds read locks on all four namespaces and checks the selected root
before reading evidence. Prefix generation walks successors with aggregate record
and byte limits; it does not materialize a complete index bucket. The immutable
query snapshot selects candidate reads only. The server verifies the resulting
evidence before returning it, so a stale snapshot can cause unavailability but
cannot supply unauthenticated permission results.

Binary decoding bounds keys to 64 KiB, values and commit metadata to 1 MiB, Merkle
paths to Commonware's proof limit, and prefix entries to the remaining record
budget. These field limits match native storage. The full serialized response
limit is checked before binary decoding. Transport bounds still apply before JSON
deserialization. Storage may allocate an individual record before generation can
charge it; index collisions, evaluator work and concurrent-request resource use
have not been qualified by sustained-load testing.

Current-state evidence is available only when the live databases match the
requested finalized module root. A changed root returns an error instead of
substituting newer state. This path does not provide retained historical activity
proofs; operation-log history proofs cannot establish historical membership or
absence.

The current-state root can advance during revisions that do not change the
requested relationship. Use `vera_getCurrentPermissionProof` for current reads
to capture the revision and evidence together. A caller using the separate
revision and `vera_getPermissionProof` requests can encounter
`RESOURCE_UNAVAILABLE` between them and must restart the read within its deadline,
preserving its minimum revision and freshness requirements. Neither endpoint
provides arbitrary historical activity proofs.

## Bounded prefix pages

`vera_getCurrentPrefixPageProof(request, minimum_height)` captures one certified
page. The request contains `module`, hex-encoded `prefix` and `start`, and `limit`
(1–128). Start is an inclusive lower bound within the prefix; use the prefix
itself for the first page. `VeraClient::read_current_prefix_page` verifies the
captured certificate, minimum revision, exact request and consecutive membership
witnesses. `PrefixPageResponse::verify` returns entries and an authenticated
continuation key, or no continuation when the prefix ends at that revision.

Record data is limited to 2 MiB and encoded page evidence to 8 MiB, including an
exclusion boundary that can contain a large predecessor value. Byte limits can
shorten a page. Empty nonterminal pages and skipped entries are rejected. Existing
complete-prefix verification continues to require proof through the prefix end.

Each request selects current state independently. Later pages can use newer
revisions, including after a cursor key is deleted. Changes before the cursor
can be missed; pagination does not promise a historical snapshot. Consumers can
carry the preceding revision forward as their next minimum revision.

## Typed bulletin reads

`vera_client::bulletin` provides certified namespace, post and collaborator reads,
plus bounded listings for each record family. Names are unprefixed inputs (for
example, `team` selects the stored `bulletin/team` namespace). A point read
returns a typed value or certified absence, with the revision and timestamp.
Post identifiers bind the namespace and payload hash. Borsh decoders reject
trailing bytes and records that differ from the requested key or namespace.

Listings use the current-prefix page protocol above. Pass `None` for the first
cursor, then use the returned continuation unchanged. Limits are 1–128 records;
byte limits may shorten a page. Each page is independently certified. No snapshot
or proof of namespace existence is implied by an empty post/collaborator page.
Stored collaborator records do not enumerate owner authority. A post's opaque
`proof` bytes are authenticated as stored data; these reads do not validate the
application protocol represented by those bytes.

## Bulletin component encoding

Bulletin composite keys escape `%` as `%25` and literal `|` as `%7C`, then map
`/` to `|`. Thus `a/b`, `a|b` and `a%7Cb` occupy different post and collaborator
prefixes. Keys without literal pipes or percent signs retain their previous
encoding. Namespace record keys and payload-derived post identifiers do not
change.

Native state hydration checks composite keys against the identifiers stored in
each record. An affected legacy key or corrupt identity stops startup/recovery
with a storage error; records are never silently rekeyed. Deployments containing
old records with literal pipes or percent signs require an explicit migration
from verified source records. Earlier collisions may already have overwritten
records, so the retained state alone may not recover every original grant.
All consensus members and bulletin clients must use the same encoding version.
