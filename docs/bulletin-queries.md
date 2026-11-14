# Bulletin collection queries

Collection queries return complete results only within their work budget:

- At most 128 inspected records.
- At most 1 MiB of inspected storage keys and encoded record values.
- A selection prefix no longer than 64 KiB.
- For glob queries, a pattern no longer than 4 KiB.

The same collector serves namespace lists, namespace collaborators, namespace
posts, all posts and glob-selected posts. Nonmatching glob records count against
the inspection budget. Oversized queries return an explicit error; partial
results are never returned as complete. Malformed records and record/key
mismatches also return errors instead of being skipped.

For larger collections, use `VeraClient::list_bulletin_namespaces`,
`list_bulletin_posts` or `list_bulletin_collaborators`. These existing native APIs
verify certified prefix pages and return continuation cursors. Apply any glob
filter to each verified post page locally. Each page has its own selected
revision; pagination does not pin a historical snapshot.

Globs retain literal matching with `*` spanning any sequence, including `/`.
Matching uses anchored prefix/suffix checks and forward searches for literal
segments, with no recursive backtracking. No other wildcard syntax is interpreted.

These read limits do not cap stored history or establish a measured execution
throughput target. Transport response limits apply separately from stored-byte
inspection limits.

Native startup and snapshot recovery validate complete bulletin records before
publishing query state. Truncated or trailing record bytes, namespace/post/
collaborator key mismatches and invalid policy-ID encoding stop restoration with
a storage error. An absent policy ID remains valid for an uninitialized module. Recovery does not repair or discard corrupt records.

`VeraClient::read_bulletin_policy_id` authenticates the bulletin's ACP policy ID
against caller-provided consensus trust. Before the first namespace initializes
the policy, it returns certified absence. Present IDs must be canonical 64-byte
lowercase hexadecimal strings and are returned as 32-byte values. Use
`read_policy` with that ID and at least the returned revision to inspect the
policy definition. The two reads may select different finalized revisions;
policy presence does not itself grant permission to create posts or manage
collaborators.

Bulletin policy initialization distinguishes absence from invalid stored IDs.
Empty or non-UTF-8 values return errors before creating an ACP policy or changing
bulletin state. Posting and collaborator management use the same fallible reader.
ACP parameter reads also return decoding errors for corrupt stored bytes; defaults
apply only to a missing key. Native recovery checks the value before publishing
query state. The bulletin and Vera modules have no parameters.

Namespace registration, posting, and collaborator changes reject empty namespace names before reading or mutating policy state. Failed empty-name registration does not initialize the bulletin policy.

Namespace inputs accept short names (`team`) and stored IDs (`bulletin/team`).
Registration results can be passed directly to subsequent reads, posting, and
collaborator changes. Both forms select the same namespace and authorization
object; an already prefixed ID is preserved. Verified client reads use the same
normalization and enforce limits on the resulting storage key.

Bulletin events index a namespace by the keccak256 hash of its stored ID
(`bulletin/team`), whichever form the caller wrote. A log filter for the
namespace `team` therefore uses `keccak256("bulletin/team")` as the topic.

Writes bound every caller-supplied field. A stored namespace ID, including its
`bulletin/` prefix, is at most 256 bytes, and so is a collaborator DID as its
caller wrote it. A post payload is 1 byte to 64 KiB, a proof at most 64 KiB and
an artifact label at most 1,024 bytes. Requests beyond
a bound fail before policy state is read. A single post therefore stays well
below the collection work budget; a namespace still exceeds it through the
number of its posts.
