# Consensus keys and application threshold services

Vera uses Commonware for consensus DKG and resharing. Application threshold
services remain in Orbis: replacing a DKG implementation would not replace
Orbis's authorization, encryption, signing, persistence, or service protocols.
The current integration keeps these key domains and memberships separate.

This comparison covers Commonware cryptography 2026.9.0 and Orbis revision
`c613da8651aad16978ec051701625d1bae191b7e`. It is a source-level capability
comparison, not a cryptographic security audit or an interoperability claim.

| Required capability | Commonware integration | Application service |
|---|---|---|
| Generate consensus signing shares | Feldman/Desmedt DKG through bootstrap and the consensus actor graph | No Orbis dependency |
| Change the consensus group | Commonware resharing with operator-approved membership | Separate from application ring membership |
| Generate and refresh application ring shares | DKG primitives overlap in purpose; no adapter to Orbis transcripts or stored shares is implemented | Orbis ring DKG, confirmations, reshare preparation and recovery |
| Sign application data | BLS primitives are available; the consensus signing configuration is different | Orbis threshold signing, derivation, request metadata and signature verification |
| Encrypt and recover document secrets | Consensus DKG does not implement this application protocol | Orbis context-bound encryption, reader-key proof, proxy re-encryption shares and recovery |
| Authorize threshold requests | Consensus authenticates finalized state, not the application's permission decision | ACP policy proofs and Orbis permission/revocation checks |
| Retain shares and resume protocols | Vera persists consensus DKG material through its secret store | Orbis persists application shares and protocol preparation state |
| Coordinate application participants | Consensus membership has its own admission and epoch rules | Native ring/node/controller records, participant attestations, bulletin messages and fault reports |

## Cryptographic compatibility boundary

Vera's consensus provider and bootstrap select Commonware `MinSig`: public keys
are in G2 and signatures in G1. The integrated Orbis BLS implementation uses G1
public keys and G2 signatures with its explicit NUL signature domain and separate
signing-derivation and metadata domains. Commonware also exposes `MinPk`, but
matching group orientation alone would not establish compatibility with Orbis's
share identifiers, polynomial commitments, transcript encoding, signature
messages, encryption proofs, or persistent records.

Commonware 2026.9.0 contains both the synchronous Feldman/Desmedt construction and
the asynchronous Golden construction. Golden is gated to the package's ALPHA
stability configuration; the current Vera consensus bootstrap uses
Feldman/Desmedt. Its presence is not evidence that Vera or Orbis is using it.

Orbis also exposes a separately selected Decaf377 implementation. The current
native integration evidence covers BLS12-381; it does not qualify Decaf377 or a
cross-scheme migration. Neither application keys nor ciphertexts are converted
by changing Vera's consensus implementation.

A future application DKG replacement must establish transcript/share encoding,
participant numbering, group and domain compatibility, retained ciphertext and
signature behavior, interrupted-protocol recovery, and migration of existing
secrets. Until those are implemented and verified, retain the working Orbis
application protocols. Never reuse consensus shares as application secrets.

## Validation scope

The [native distributed threshold workflow](https://github.com/sourcenetwork/orbis-rs/blob/c613da8651aad16978ec051701625d1bae191b7e/bin/orbis-node/tests/native_startup.rs)
exercises document signing, encrypted
secret recovery, authorization and revocation, restart, reshare preparation,
participant replacement and certified reports. These functional checks support
the existing integration. They do not prove security of a new DKG construction,
compatibility with earlier deployed shares, or sustainable service capacity.

The [member-replacement case](https://github.com/sourcenetwork/orbis-rs/blob/7d40cf72795dbdac665337176ca068d4fdddbe0c/bin/orbis-node/tests/support/native_pet/member_replacement.rs)
also stops two old participants, requiring the incoming share for a two-participant
signature. It verifies the derived signature before and after restarting both
remaining participants, then checks that certified revocation denies signing and
regrant restores it. Persisted shares must match the new committee indices.
These assertions passed against Vera `9d5c2b9` in the
[BLS lifecycle job](https://github.com/sourcenetwork/orbis-rs/actions/runs/38142081479/job/114483250187)
and [Jubjub lifecycle job](https://github.com/sourcenetwork/orbis-rs/actions/runs/38142081479/job/114483250194).
The selected suites passed 22 and 21 tests respectively; each skipped two separate
cases, and neither result establishes prolonged membership churn or WAN behavior.

Source references:

- Commonware [DKG modules](https://github.com/commonwarexyz/monorepo/blob/d476a2361ce6840d2b9d0aa6fb30a924429046d4/cryptography/src/bls12381/dkg/mod.rs)
  and [BLS variants](https://github.com/commonwarexyz/monorepo/blob/d476a2361ce6840d2b9d0aa6fb30a924429046d4/cryptography/src/bls12381/primitives/variant.rs).
- Vera's [consensus bootstrap](../crates/vera-node/src/bootstrap.rs),
  [provider](../crates/vera-node/src/provider.rs), and
  [secret store](../crates/vera-node/src/secret_store.rs).
- Orbis [crypto selection](https://github.com/sourcenetwork/orbis-rs/blob/c613da8651aad16978ec051701625d1bae191b7e/crates/crypto/src/lib.rs),
  [application signing](https://github.com/sourcenetwork/orbis-rs/blob/c613da8651aad16978ec051701625d1bae191b7e/crates/crypto/src/bls12_381/sign.rs),
  and [proxy re-encryption](https://github.com/sourcenetwork/orbis-rs/blob/c613da8651aad16978ec051701625d1bae191b7e/crates/crypto/src/bls12_381/pre.rs).
