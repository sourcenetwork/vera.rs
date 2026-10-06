# Native PET state

PET (plaintext equality testing) adds an independently generated threshold key to
an Orbis ring. The main key continues to authorize signing and re-encryption;
the PET key checks an encrypted document's ownership tag during the existing
blinded Orbis protocol. ACP authorizes document access and the additional audit
target permission. Storing a tag does not grant either permission.

## Ring lifecycle

`RingConfig.requires_pet` is required and immutable. `RingPublicKeys` contains
`public_key` and optional `pet_public_key`. Ordinary rings forbid a PET key;
PET rings require one. Both fields use bounded, lowercase hexadecimal encoding.
Curve and proof verification remain Orbis responsibilities.

`RingParticipantCommand::Confirm` signs the complete pair, together with the
existing deployment, ring, participant and expiry fields. A pending ring records
one pair and the sorted participants that confirmed it. Every configured member
must confirm that same pair before activation. A disagreement in either key
produces a terminal conflict, including two confirmations with identical main
keys and different PET keys. Invalid modes or signatures leave state unchanged.
Cancelling or conflicting does not release the ring identity for reuse.

Updates and membership resharing retain both finalized keys. The current Orbis
report-state and reshare signing projections still use the main key; this port
does not change their shared encoding. Certified ring reads authenticate the
immutable pair, and the existing PET context digest binds the PET key used by
Orbis. `read_threshold_ring` returns the full record and captured revision.

## Stored documents

`EncryptedDocument` accepts `pet_tag` and `pet_tag_proof` together. Registration
requires their presence to match the active ring's PET mode. Each attachment is
bounded to 4 KiB before JSON decoding; unknown fields, empty byte arrays and
incomplete pairs are rejected. Registration stores the binding, without claiming
to verify its cryptographic proof.

Document identity uses the existing Orbis canonical encoding. After the original
fields, a present attachment appends the decoded ephemeral point, masked
fingerprint, challenge and response in that order. Whitespace and JSON field
order do not affect identity. An absent attachment appends nothing, so the same
ordinary document inputs retain their existing ID and delegated JSON encoding.
The changed ring identifier still changes IDs of documents created for a new ring.
The SDK encoder and certified object reads retain both attachment fields.

## Fault reports

PET offline reports require a PET ring and current committees. The existing
`invalid_crypto_response` report accepts Orbis's v2 blinded reveal and decrypt
evidence. Vera checks canonical decoding, field bounds, statement domains,
deployment/ring/state/time/attempt bindings, PET mode, the accused member's index
and the current committee. It verifies the aggregate ring signature over the
report, including its opaque context and certificate digests. It does not
reconstruct the private context or verify the individual PET proof.

Orbis co-signers authenticate the accused's response and independently establish
the proof failure before authorizing a report. Decrypt reports also require an out-of-band certificate
whose threshold signed reveals bind the exact canonical polynomial to the
context and current committee. Verification uses that certified polynomial, not
the co-signer's local share generation; a genuine response does not become a
fault merely because the co-signer has refreshed. The full context and
certificate are not submitted to Vera. The signed evidence contains public proof
material, including the decrypt polynomial, while the audit target remains
out-of-band. Protocol participants and report co-signers still receive it.

## Deployment boundary

This is a fresh-state format. Ring identity uses `vera/orbis/ring/v2` followed by
a zero byte; participant signatures use `vera/orbis/ring-participant/v2` followed
by a zero byte. Ring records use `orbis/ring/v2/`. Ordinary rings also change ID
because their canonical configuration includes `requires_pet: false`.

Native genesis fingerprints use `vera/native-genesis/v3` followed by a zero byte
and serialized genesis configuration. Every native genesis block binds this
fingerprint into its identity. Startup rejects prior genesis records and
interrupted initialization markers without rewriting them. Validators and SDK
consumers must use the same schema and a new deployment root; old ring state,
pending worker journals and signed requests cannot be reused. No migration reader
or legacy confirmation type is provided. PET report producers, co-signers and
Vera's Orbis reporting codec must also use the aligned v2 domains. There is no v1
PET evidence fallback; the outer report envelope and non-PET domains are unchanged.

## Qualification boundary

These changes provide native state and report formats. They do not establish
completed PET lifecycle qualification. The existing Orbis protocol still needs
native BLS and Jubjub tests covering stored and inline documents, authorization
and revocation, independent PET refresh, membership replacement and restart.
Fault attribution across share generations also needs adversarial qualification;
matching a polynomial's constant term alone does not authenticate its generation.
