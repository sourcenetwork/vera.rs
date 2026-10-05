# Native policy reads

`VeraClient::read_policy_page` returns policy records and creation metadata from
certified native state. Callers supply the trusted consensus key, a minimum
revision and a page limit. The client verifies complete-prefix evidence, decodes
each record and checks that its canonical policy ID matches its storage key.
Malformed records fail the page rather than being omitted.

Start with no cursor. Pass the returned continuation to obtain the next page;
no continuation means the selected policy prefix has ended. An empty initial
page proves that no policies existed at its selected revision. Existing proof
limits bound each page's record count and encoded bytes.

Each page includes its finalized revision and timestamp. Later pages may select
newer state, so enumeration does not provide a historical snapshot across pages.
Pass the previous revision as the next minimum to prevent moving backward.
Policy presence alone does not grant access; evaluate permissions using the
certified permission APIs.

`VeraClient::read_policy` selects one policy by its 32-byte ID. It verifies the
record proof and ID binding with the same decoder used by discovery pages,
returning the policy definition and creation metadata or certified absence.
The returned revision and timestamp identify the state used for the read.

The module's `query_filter_relationships` convenience query inspects at most 128
records and 1 MiB of keys and encoded values within the selected policy prefix.
These limits apply before selector filtering. Exceeding either limit returns an
error, never a truncated result. Every inspected record must decode completely
and match its policy and relationship storage key. Larger enumerations use
`vera_getCurrentPolicyPrefixPageProof` with the policy's relationship prefix and
verify policy liveness and each page at the same revision before applying selectors
locally.

`VeraClient::read_relationship_page` provides typed, verified pages for that
relationship prefix. Each record includes the relationship, archive status and
issuance metadata. Apply object, relation, subject and archive filters locally
after verification, and continue until the cursor is absent even if no records
in a page match. Each page includes a witness for the active policy record at the
same root. A deleted or absent policy returns no current relationships or
continuation, even while physical records await cleanup. A live policy may have an
empty relationship page. Pages may select newer revisions; pass the previous
revision as the next minimum.
Enumeration is not a permission decision or a historical snapshot across pages.

Policy lookup and editing reject malformed records or IDs that differ from the
selected key. Grant-management checks likewise reject invalid policy, ownership
or manager records encountered during authorization. Relationship set/delete
validate the existing target before mutation, including when the policy owner
submits the command. These paths preserve damaged records for explicit recovery
instead of treating them as absent or silently overwriting them.

Native state loading validates retained policy and relationship encodings and key
identities, and checks stored ACP parameters and access-decision encodings before
publishing query state. A retained relationship, commitment or amendment must
belong to a live policy or a recognized retirement job whose cleanup phase permits
that record. Retirement markers, queue entries and counters must agree, and
completed phases must be empty. Arbitrary orphan records remain invalid. Amendment
index validation remains part of this check. Validation borrows the retained
store rather than materializing a second prefix copy; it does not repair records
or re-evaluate historical access decisions. The standalone `AcpModule::from_store`
constructor still requires an explicit `validate_restored_state` call when used
outside native state loading.

Restored ACP counters must contain exactly eight big-endian bytes and cannot be
below retained record IDs (or the combined live and pending-retirement policy
count). Missing counters select zero only when no corresponding records remain. Commitment and amendment keys
must carry nonzero, eight-byte IDs. Creation also rejects an already occupied
policy, commitment or amendment ID before changing stored state. Counter repair
is an explicit recovery operation; normal execution never resets counters or
replaces a retained record to resolve a collision.

Commitment recovery checks complete record decoding, nonzero ID/key agreement,
32-byte roots and a live policy or recognized retirement job. Every retained
commitment requires its root and policy indexes; unexpired commitments also
require the exact expiry index. Reverse checks reject dangling or aliased root,
expiry and amendment-policy indexes, unexpected
index values, and expiry entries for already expired commitments. Missing or
inconsistent indexes require explicit recovery or migration; startup does not
rebuild them silently.

The legacy policy-ID query returns at most 128 IDs and rejects malformed stored identifiers. Larger listings use `read_policy_page`; the bounded query never returns a truncated success.

Logical deletion and its bounded physical cleanup are described in
[ACP v1](acp-v1.md#policy-deletion-and-cleanup). Definition edits still scan the
target relationship graph atomically; this deletion mechanism does not bound edit
work.
