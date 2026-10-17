# Access decisions

A successful access check persists an `AccessDecision`; denied or empty requests do
not produce a grant. The submitting identity may differ from the actor whose
permissions are evaluated.

`DecisionRequest` identifies the deployment, policy, submitting identity, its
authenticated operation sequence, and the actor's ordered operations. The identifier
is SHA-256 of `vera/access-decision/v1\0` followed by the Borsh encoding of that
request. String and vector lengths preserve field boundaries. Requests are limited to 64
operations and 64 KiB of Borsh data; consumers reject records above 128 KiB. A later submission
uses a different sequence and cannot replace an earlier decision under its key.

Issuance time and revision come from finalized execution context. Decision expiry
is measured in revisions: a decision issued at H with delta D is valid only while
`H <= current_height < H + D`. Overflow and zero lifetimes are rejected. The current
issuance defaults remain 100 revisions for decisions and tickets, and 50 for proofs;
these are not wall-clock latency guarantees. Ticket and proof workflows require
their own lifecycle checks.

Consumers must authenticate the stored bytes at a fresh finalized revision and use
`DecisionRequest::verify_record` to check the exact expected request, creator,
sequence, issuance metadata and expiry. Record presence alone is insufficient. A
decision proves successful evaluation at issuance; it does not prove that permission
remains granted after subsequent policy changes or authorize an unrelated payload.

The stored Borsh field layout is unchanged. Historical records remain readable, but
legacy identifiers and zero issuance placeholders do not pass the new verification
rules. Operators must coordinate the execution update and consumer dependency pins;
new and old decision producers derive different identifiers.

`VeraClient::read_access_decision` combines the certified native record read with
`DecisionRequest::verify_record`. Supply the exact expected deployment, policy,
creator, submission sequence, actor and ordered operations, plus independent
consensus trust and a minimum revision. The result includes the selected revision
and timestamp, with either a valid decision or certified absence. Invalid or
expired records return errors. Callers still enforce freshness appropriate to
usage; this method does not prove that an earlier permission remains granted.

The module's decision lookup distinguishes missing keys from invalid records.
Stored values must decode completely within 128 KiB and their decision ID must
match the queried key. Corruption returns an error rather than absence. This
lookup can return expired records awaiting cleanup; current validity requires the
request-bound verification described above.

## Expired-record cleanup

End-block maintenance inspects at most 64 access-decision records and 1 MiB of
encoded keys and values per block. A persisted ordered cursor resumes the sweep
across restarts and wraps at the end of the prefix. Decisions are removed at or
after their exclusive expiry; live decisions are retained and revisited on later
sweeps. Existing records require no new expiry index or bulk migration. Legacy
zero-height placeholders have no trustworthy lifetime and remain for explicit
migration rather than being silently deleted.

Deletion can lag expiry by multiple blocks. The limits bound cleanup work, not
retained state or RSS; sustained arrivals above reclamation capacity can still
grow the backlog. Missing current-state records do not prove that a decision was
never issued. Consumers needing an audit trail must retain their authenticated
issuance evidence; this cleanup does not add historical decision-proof RPCs or
prune finalized history or receipts.

Malformed records encountered by the sweep reject the block's lifecycle work
without publishing partial deletions or cursor advancement. Recovery validates
cursor encoding before publishing query state. Cleanup changes execution roots
and adds `decision_cleanup/cursor` to ACP state. All validators must coordinate
this execution update; older binaries must not continue participating after it
activates. The stored decision encoding and client verification rules are unchanged.
