# Token lifecycle

Token records remain queryable after invalidation. An ordered index contains only
tokens with an expiry and a status other than invalid. Its key is `0x04`, followed
by the expiry time as a big-endian 64-bit integer and the token hash's UTF-8 bytes;
its value is empty. The primary record and existing issuer/account indexes retain
their formats.

Every token write updates the expiry index. Usage updates retain one entry;
revocation removes it. The end-of-revision sweep visits at most 128 due entries
and stops at the first deadline greater than or equal to the execution time.
The stored status remains unchanged at the exact deadline; authorization also
checks the signed token claims. A zero timestamp means no expiry and has no index
entry. Automatic invalidation records its execution timestamp; later sweeps do
not overwrite an operator's invalidation metadata.

The sweep validates due entries before updating records. Missing records, malformed
bytes, mismatched token hashes or inconsistent deadlines fail execution. Ordinary
record reads also validate the stored token hash against the requested key.
Proposal-local failures cannot publish partially updated module state.

Indexes persist with Vera state and recover with its snapshots. Missing or
inconsistent indexes fail restoration. The sweep reads the ordered deadline
index rather than scanning token history. When more than 128 tokens are due, later revisions
continue from the remaining ordered entries, including after restart. The stored
status may await maintenance; authorization and usage checks still enforce the
actual deadline. This does not cap retained history.

Token collection queries inspect at most 128 records and 1 MiB of combined
index, primary-key and record bytes. Larger results return errors instead of
partial lists. Use certified native prefix pages for larger collections.
Malformed index suffixes, unexpected index values, missing records and mismatched
record identities are errors. Account selectors must contain 1–255 bytes; DID
selectors are also capped at 255 bytes. Token writes validate every index
component before changing state, avoiding key-encoder panics and partial writes.

`VeraClient::read_token_record` returns lifecycle metadata or certified absence
for a SHA-256 token hash at a caller-selected minimum revision. It verifies the
certificate, record key and stored token-content hash before returning the record.
After invalidation, read at or after the certified invalidation revision to check
the status, invalidating identity and execution timestamp.

Revoking an unused delegation creates an invalid token record with no first-use
or last-use timestamp. The same certified read verifies that record. Invalidation
by hash requires an existing record; `native_revoke_delegation` accepts the signed
token and can revoke it before first use.

This read does not evaluate signature claims, expiry, delegation scope or provider
grants. Neither record presence nor absence proves that a token can authorize a
new operation.

Native recovery validates token records and their issuer, account, and expiry
indexes before publishing module state. Missing indexes, orphaned entries,
invalid presence markers, malformed records, and mismatched identities stop
recovery with an error. Configuration must also decode successfully. Validation
does not repair or discard retained records.

The token deletion helper removes the expiry entry together with the primary,
issuer, and account entries. Otherwise, a deleted token's deadline would later
make expiry processing fail when it could not find the primary record.
