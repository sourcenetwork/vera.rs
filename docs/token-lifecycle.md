# Token lifecycle

Token records remain queryable after invalidation. Every token names an authorized
account and an expiry time. An ordered index contains the tokens whose status is
not invalid. Its key is `0x04`, followed
by the expiry time as a big-endian 64-bit integer and the token hash's UTF-8 bytes;
its value is empty. The primary record and existing issuer/account indexes retain
their formats. A record and its index keys name a secp256k1 issuer or account by
its [canonical DID](delegated-policies.md#one-actor-per-key); lookups and
revocation accept any spelling of the key.

Every token write updates the expiry index. Usage updates retain one entry;
revocation removes it. The end-of-revision sweep visits at most 128 due entries
and stops at the first deadline greater than or equal to the execution time.
The stored status remains unchanged at the exact deadline; authorization also
checks the signed token claims. Automatic invalidation records its execution timestamp; later sweeps do
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
recovery with an error. A record without an authorized account is malformed.
Validation does not repair or discard retained records.

## Revocation by the issuer

A token's issuer that cannot sign a native request revokes the token through a
worker. The issuer signs an operation token, in the same format as a
[delegation](delegated-policies.md), whose claims name:

| Claim | Value |
|---|---|
| `iss` | The issuer, a secp256k1 (`ES256K`), Ed25519 (`EdDSA`) or P-256 (`ES256`) `did:key` |
| `sub` | The worker that submits the revocation |
| `aud` | `vera:<deployment_id>` |
| `scope` | `vera:token:revoke` |
| `request` | An [operation identity](operation-identities.md): its ID, the genesis identity and the digest of `RevokeToken(tokenHash)` |

The digest is SHA-256 of `vera/acp-operation/v1\0` followed by
`{"RevokeToken":"<tokenHash>"}`, the hash spelled as the record key spells it
(64 lowercase hexadecimal digits). The worker submits
`invalidateJWSByIssuer(tokenHash, operation)` to the Vera module at `0x0812`; the
call returns the updated record as JSON and emits `JWSTokenInvalidated` naming
the issuer.

Execution verifies the operation's signature, worker, deployment, genesis,
validity interval, scope and digest, and that the operation has not itself been
revoked; any of these failing refuses the request as `InvalidToken`. An
operation without an identity is refused the same way. It then requires a
record for the hash (`NotFound` otherwise), compares the signer with the
record's issuer under the [canonical DID](delegated-policies.md#one-actor-per-key)
(`Unauthorized` otherwise) and refuses an already invalid token
(`InvalidToken`). The record names the issuer's canonical DID in
`invalidated_by`.

The identity's deadline lies at most 600 seconds ahead of execution. The first
successful revocation stores its outcome under the issuer and identity, with the
outcome budgets and expiry of every operation identity. A retry under the same
identity, through the same or another worker, returns the original record
without changing state; the same identity with another token hash is refused.
The operation token is recorded as a used token of its issuer, authorized for
the worker. `TokenRevocation` in `vera-client` builds the claims and calldata,
signs them with a secp256k1 key (other keys sign through `UnsignedToken`), and
`VeraClient::native_invalidate_jws_by_issuer` submits them as the worker.
