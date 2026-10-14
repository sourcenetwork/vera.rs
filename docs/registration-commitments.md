# Registration commitments

An actor may commit to object registrations before revealing their identifiers.
A reveal can replace an existing owner only if the commitment's revision is no
later than the existing registration's creation revision. The resulting owner
record retains the commitment's creation timestamp, so a later commitment cannot
override an earlier claim after an amendment. Its submission ID and signer identify
the reveal; the amendment event records the reveal's own execution timestamp.

Native and optional EVM execution supply this metadata through the same module
command path. Delegated commands preserve the actor as owner and the worker as
submission signer. Ownership amendment deletes the former owner's relationship
key and writes the new key, keeping permission checks and certified owner-prefix
reads consistent.

Commitments belong to one policy and expire after ten minutes by default, matching
the Go service. The end-of-revision hook marks them expired once the current time
exceeds their creation time plus the configured lifetime. Reveals independently
check that deadline at execution, so a time jump cannot make an expired commitment
usable before the cleanup hook. The deadline itself remains inclusive.

Expiry maintains separate ordered indexes for time and revision deadlines. The
hook processes at most 128 due entries from each index per revision and stops
at the first future deadline. Expired records remain queryable without staying
in the active indexes. Indexes persist in ACP state and restore with it.
Remaining entries are processed in later revisions; no cursor is lost on restart.
Separate budgets prevent a backlog of time deadlines from blocking revision
deadlines. Index inconsistencies return an error before any records in the
batch are expired.

Successful commitment
receipts include `RegistrationsCommitted(commitmentId, policyId, commitment)` so
native callers can obtain the identifier from a certified receipt.

Object IDs must be nonempty for policy commands and commitment generation. IDs
are otherwise preserved as supplied, including spaces, Unicode and slashes.

Commitment generation accepts 1–256 objects and at most 64 KiB of aggregate
encoded leaf bytes, counting the repeated policy and actor strings for each leaf.
It checks these limits before state lookups and proof allocation. Larger sets
must be split into separate commitments. These limits bound this generator's
work; they do not limit the size of a proof supplied for an independently built
commitment beyond the verifier's existing proof-shape checks.

Owner queries inspect at most two records. Missing ownership returns unregistered;
malformed, duplicate or mismatched ownership records return an error. Unarchive
uses the same validation, including actor, policy, object and storage-key binding.
Archived ownership remains reserved for its previous owner.

The registration leaf is `vera/registration-leaf/v1` followed by a zero byte and
the Borsh encoding of four strings: policy ID, resource, object ID and actor DID.
Strings use Borsh's little-endian 32-bit byte lengths and UTF-8 bytes. The leaf
hash is SHA-256 of `0x00 || leaf`; inner hashes use `0x01 || left || right`.
Odd trailing nodes are promoted unchanged. Verification checks the leaf index,
leaf count, 32-byte sibling hashes and exact number of consumed siblings.

This is the release's commitment encoding. All members and consumers use the
same format, starting from fresh state.

## Commitment discovery

Each commitment has a root index entry using
`commitment/indexes/commitment/idx/ || root[32] || / || id_be[8]` with an empty value.
The entry remains after expiry. It is maintained with the primary record and
included in ACP snapshots.

`VeraClient::read_registration_commitment_ids` uses the existing certified native
prefix-page endpoint. Supply the root, optional continuation, a limit from 1 to
128, a minimum revision and trusted consensus key. The result contains verified
IDs in ascending order, its revision and an inclusive continuation for the next
page. A missing root returns a certified empty page. Later pages can select newer
state; the cursor does not pin a historical snapshot.

Read a discovered primary record with `read_current_record`, module `Acp` and
`acp::keys::commitment_key(id)`, using at least the page's revision. Such a read
may select newer state, including a changed expiry flag. The index authenticates
the root-to-ID association, not the primary record's mutable metadata.

The legacy by-value query uses the same index and returns complete results only
when they fit within 128 records and 1 MiB of stored record bytes. Larger results
return an explicit error directing callers to certified pages; they are never
silently truncated. Indexed record corruption is an error rather than absence.

`VeraClient::read_registration_commitment` returns a typed record or certified
absence using caller-provided consensus trust and a minimum revision. The client
checks the requested policy, commitment identifier, root width and complete record
encoding. It preserves issuance metadata and expiry status; record presence is
not a guarantee that a later reveal will succeed.

`vera_client::registrations::generate_registration_commitment` builds bounded
commitment material locally with the same Merkle encoding used during reveal
verification. Object identifiers need not be sent to a node during preparation.
Local generation does not establish policy existence, valid resources or current
ownership; execution checks these when processing the registration commands.

Use `native_commit_registrations` to submit the 32-byte root and
`native_reveal_registration` to submit one typed registration proof. Both use
the native signer and submission path. Their transaction receipts are transport
responses; use `read_receipt` with independently configured consensus trust when
acting on a certified outcome.

Ownership amendments write an empty policy-index entry keyed by policy and
ascending amendment ID. Hijack-history lookup inspects at most 128 indexed
amendments and 1 MiB of combined index, key and record bytes, including unflagged
events. Exceeding either limit returns an error rather than a partial history.
Malformed records, mismatched identities and dangling indexes are errors.

Native recovery requires a matching policy index for every retained amendment.
Missing or inconsistent indexes fail restoration. Index entries participate in
the native state commitment. The limits bound each query, not total retained
history.

`read_amendment_ids` discovers all amendment IDs for a policy through certified
pages, including unflagged events. `read_amendment` binds the selected record to
its policy and identifier, preserving both owners, issuance metadata and the
hijack-report flag. It also supports certified absence. Pages and subsequent
record reads can select different finalized revisions; they do not form a
historical snapshot.

The amendment’s new owner may call `native_flag_hijack_attempt`. That event-only
endpoint resolves the policy from the stored event. For direct, signed and
bearer policy commands, the supplied policy ID must match the amendment; a report cannot change another policy’s
history by referencing its global event ID. Repeated reports preserve the event
metadata and leave the flag set. Other actors
are rejected by execution. A flag records that owner’s allegation; it is not an
independent finding. Verify the submission receipt and read the event at or after
that revision to observe the certified flag.

A successful reveal returns the registration record and an optional amendment
event. A fresh registration has `event: null` and creates no amendment history.
An ownership amendment returns its persisted event with a nonzero ID.

Expiry batch limits are deterministic execution rules. All consensus members
must run the same rules; changing the limits requires a coordinated protocol
upgrade. Delayed maintenance never extends the deadline accepted by reveal
execution. The limits bound record count, not retained history or total node RSS.
