# Passkey approvals

A P-256 key held by a platform authenticator, a passkey, does not sign a
caller's digest. It signs `authenticatorData || SHA-256(clientDataJSON)`, and
the digest appears only as the client data's `challenge`. Vera accepts such an
assertion wherever a P-256 key approves a digest:

| Use | Digest (the challenge) | Where the assertion travels |
|---|---|---|
| Administrative approval | `AdministrativeRequest::signing_digest` | `OperatorApproval.webauthn` |
| Term approval | `TermChange::signing_digest` | `TermApproval.webauthn` |
| Delegation token | SHA-256 of the token's signing input | the token's third segment |

A passkey is named by its existing P-256 `did:key` (multicodec `0x1200`,
compressed point), in operator policies and as a token issuer, so the account
is one actor whichever form it signs in. The host converts the credential's
COSE key to SEC1 and calls `vera_crypto::actor::p256_did`; Vera parses no COSE
or CBOR. Only ES256 (COSE `-7`) credentials are supported. Every P-256 key
may sign in either form; a raw signature never verifies as an assertion, nor
an assertion's signature as a raw one, without a SHA-256 preimage.

## Wire format

An approval keeps its 64-byte low-S `r || s` signature and adds the
authenticator output. Administrative approvals use lowercase hexadecimal, as
their signature does:

```json
{"signer": 1, "signature": "<128 hex>",
 "webauthn": {"authenticator_data": "<74 hex>", "client_data_json": "<hex of the exact bytes>"}}
```

Term approvals write `0x`-prefixed lowercase hexadecimal, like their other
fields. They decode every field as `alloy_primitives` does, with or without
`0x` and in either case, and compare the decoded bytes: the client data that
is hashed is the decoded bytes, whatever spelling carried them. An approval
without `webauthn` is a raw signature of the digest. In both forms the member
is omitted to say so; `"webauthn": null` does not decode. The credential
id is not carried: a verifier needs only the key.

A passkey delegation names `{"alg":"ES256","typ":"vera-delegation-webauthn-v1+jwt"}`
and keeps three segments. The third is the unpadded base64url of
`authenticatorData (37) || r || s (64) || clientDataJSON`, at most 1,125
bytes. The challenge is `SHA-256(header_b64 "." payload_b64)`, the prehash an
ES256 token signs. Token hashing, the 16 KiB limit, revocation and transport
are unchanged. Relay tokens remain secp256k1.

## Verification rules

For the expected digest `D` and the P-256 key `K`
(`vera_crypto::webauthn::verify`):

1. Authenticator data is exactly 37 bytes: `rpIdHash`, flags, `signCount`.
   Attested credential data (bit 6) and extension data (bit 7) are absent,
   so no CBOR is parsed.
2. User presence (bit 0) and user verification (bit 2) are set.
3. Backed up (bit 4) requires backup eligible (bit 3). The other flag bits,
   including reserved bits 1 and 5, are signed and otherwise ignored.
4. `signCount` is not checked: synced passkeys report 0, and offline verifiers
   hold no per-key state. The digest bounds replay.
5. `rpIdHash` and `origin` are not compared with any configuration: only the
   credential's authenticator holds `K`, and native origins differ by platform.
6. Client data is UTF-8 without a byte order mark, at most 1,024 bytes, and
   one RFC 8259 object followed only by whitespace. A member name appears
   once, whether known or not, compared after unescaping. `type` is
   `"webauthn.get"`. `challenge` equals, as a string, the 43-character
   unpadded base64url of `D`; it is never decoded, so padding and unused
   trailing bits cannot alias. `origin` is a string of at most 512 bytes.
   `crossOrigin` is absent or `false`, and `topOrigin` is absent. Any other
   member has a string, number, boolean or null value. Escapes are decoded
   before comparison and an unpaired surrogate is refused. The bytes are
   hashed exactly as carried and never re-serialized.
7. The signature is 64 bytes, `r` and `s` in `[1, n−1]`, `s ≤ n/2`. DER is
   refused on the wire; clients convert with `canonical_der_signature`.
8. `K` verifies the signature over
   `SHA-256(authenticatorData || SHA-256(clientDataJSON))` as the prehash.
9. A passkey token's issuer is a P-256 key.
10. Every listed approval must verify, as for raw approvals.

The parser is written for these rules (`vera_crypto::webauthn::client_data`)
rather than delegated to a JSON library, whose duplicate-member and number
handling is not part of its contract.

## Bounds and cost

A passkey approval is at most 2,346 bytes of JSON, with 1,024 bytes of
client data. A term certificate verifies only when its JSON encoding is at
most 32 KiB (`vera_domain::MAX_TERM_CERTIFICATE_BYTES`), wherever it is
checked: it holds at least 13 such approvals, about 57 with the 135 bytes of
client data Chrome writes, and an approval from each of the 128 operators a
policy may list when they sign raw. A message between an account's devices
is at most that limit plus 256 bytes, the rest of a status carrying a
certificate, and a longer one is dropped before it is parsed. An
administrative request has its own 32 KiB limit and holds as many. A term
approval whose authenticator data is not 37 bytes, or whose client data
exceeds 1,024 bytes, does not decode. Verifying one costs two SHA-256 passes over at most 1,093 bytes, a parse
of at most 1 KiB, and one P-256 verification, as a raw approval does.
Administrative requests keep their fixed 500,000 gas.

## What a passkey approval does not prove

- There is no attestation. Vera cannot tell a synced passkey from a software
  key that emits assertions; the user-presence and user-verification flags
  are claims made by whoever holds `K`.
- Custody belongs to the platform. Whoever controls the synced account or its
  recovery holds the key.
- The user does not see the challenge. The credential must be dedicated to
  Vera approvals: if it also signs challenges a server chooses, such as a web
  login, that server can obtain an approval of any Vera digest.

Replay is bounded by the digests themselves: an administrative approval binds
`genesis_id`, `sequence` and `expires_at`; a term approval binds `genesis_id`,
the never-decreasing `term`, `holder` and the cut; a token binds
`aud = vera:<deployment>`, `sub`, `nbf` and `exp`, with token records and
[operation identities](operation-identities.md). The namespaces
`vera/admin/v1\0` and `vera/term/v1\0` keep the digests apart, and `type`
excludes registration ceremonies.

## Building approvals

`vera-client` takes the assertion a platform authenticator returns: the
authenticator data, the client data JSON exactly as returned, and the DER
signature. The host passes the 32 digest bytes as the `challenge` of
`navigator.credentials.get` or its platform equivalent, with
`userVerification: "required"`.

- `administration::webauthn_approval` builds an administrative approval and
  checks it against the policy entry.
- `term::webauthn_term_approval` builds a term approval the same way.
- `UnsignedToken::webauthn_challenge` returns the challenge of a P-256
  issuer's delegation under the passkey token type, and
  `UnsignedToken::finish_webauthn` completes and checks the token.

`vera_crypto::webauthn::testing::Authenticator`, behind the `testing`
feature, signs assertions as a platform authenticator does, for tests.
