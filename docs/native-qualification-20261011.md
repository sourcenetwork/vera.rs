# Native qualification: October 11, 2026

This is a historical source set. The [October 13 record](native-qualification-20261013.md)
contains the current compatible sources and focused qualification results.

This source set passed focused Linux consumer qualification with four pipelined
Vera validators, Regolith finalized history and separate Go Trust and Rust Orbis
services. These are immutable tested revisions, rather than moving branch heads.
The deployment requires a fresh native genesis and deployment root; see the
[PET format boundary](native-pet.md#deployment-boundary).

## Tested source set

| Component | Revision | Selection |
| --- | --- | --- |
| Vera daemon and shared verifier | `9d5c2b9ea7cb971a7871028b7b0b22d488a7ecbf` | Rust 1.98.0; native pipelined execution; Regolith history |
| Defra | `8cfd791fe7f3b69777c60b436f6b32c1a4447526` | Native Vera provider and protected replication |
| Backbone | `0a383a36f96ec2ba9eb50762b7c8f9a73993b5ff` | Native proof and threshold consumer fixtures |
| Backbone SDK used by consumers | `7d67ddbbb0d3d671b95dfe322b920e2e943c1daa` | Vera client/verifier pinned to the revision above |
| Trust API | `f4040744d668afeff89318c37005b7b667a0650e` | Separate Go gateway; executable and container modes |
| Orbis normal runtime | `68cf26d15fb554adfbab50df157e8e2d085463d4` | Native backend; BLS12-381 or Jubjub |

Vera's lockfile pins Regolith 0.1.7 at
`e7cf2732d0178defb02d9306cd8d1dae6406e4d8` and Commonware 2026.9.0 at
`0ebcf164594621f2c82769eef7e9f3a21153055f`. The latter revision is in
`iverc/commonware-upstream`. Authenticated state remains in Commonware QMDB.

Merged Vera #209, revision `65cb4d6c5643a67b27cce3228b92225a73b6d38b`, has the
same source tree as qualified PR head `0ad6291f74604630bd61f6a0fb2ddda5b7830e58`.
The [PR's normal release artifact](https://github.com/sourcenetwork/vera.rs/actions/runs/38149211779)
has the same daemon bytes as the independently reproduced normal release built
at the frozen Vera revision above. Its executable SHA-256
is `05c6aa09252762130d135fbdc187ccdc71e186e8095362cd5688ac5e913da7e1`.
The [post-merge Linux artifact](https://github.com/sourcenetwork/vera.rs/actions/runs/38155656839)
was independently verified against the same executable hash, source tree, lockfile,
toolchain and build selection. Its six recovery artifacts contain 31 passing case
records, including repeated readiness checks in separate invocations. This does
not establish the cause of older failures. Executable equality also does not
establish that separately rebuilt consumer libraries or container images have
identical bytes.

## Runtime images

The focused Orbis driver uses these normal Linux amd64 images by digest:

```text
ghcr.io/sourcenetwork/orbis-rs/vera-native@sha256:13100a948d3dc642839aeb29de747d7a0c7d9c78fb018d33bce6bfb3902bebfd
bls12-381: ghcr.io/sourcenetwork/orbis-rs/node-integration@sha256:b0c0c87f9516c51aa1e6db363d602e50b9d00f06fe2338bdc38a7aa185206895
jubjub: ghcr.io/sourcenetwork/orbis-rs/node-integration@sha256:062bcc69615d2c3357839532eaf42ace0eb759887dc3960327165777e8b6e43e
```

Each ring uses one curve consistently. The driver verifies image source, backend
and curve labels and rejects diagnostic features in normal images. The companion
fault tests use separate diagnostic images; those images are outside this normal
runtime set. New fixtures may reuse the normal images only after the driver's
explicit source guard verifies that production code, manifests, locks, protocols
and Dockerfiles remain unchanged. A fixture revision does not repin the runtime.

## Observed consumer behavior

- [Defra run 38124694772](https://github.com/sourcenetwork/defradb.rs/actions/runs/38124694772):
  native provider checks and live policy lifecycle, protected replication/restart,
  peer authorization, reader/writer updates and revoked-delete cases.
- [Backbone run 38133836648](https://github.com/sourcenetwork/backbone/actions/runs/38133836648):
  eleven threshold consumer cases, each on its first attempt, covering both curves,
  identity restart, native documents/signing, PET replacement and scheduled refresh.
- [Trust ring run 38133839517](https://github.com/sourcenetwork/trust-api/actions/runs/38133839517):
  both curves through executable and container gateways with native ring workflows.
  [Standalone gateway run 38133839531](https://github.com/sourcenetwork/trust-api/actions/runs/38133839531)
  checks initial, restarted and revoked-provider phases against Vera and Rust Defra.
- [Orbis member-signing run 38142081479](https://github.com/sourcenetwork/orbis-rs/actions/runs/38142081479):
  both curves verify a derived-key signature using a required incoming share,
  reject the bare ring key and enforce certified signing revocation after restart.
  Its newer fixture preserves the normal runtime's production sources.
- [Orbis soak run 38136573869](https://github.com/sourcenetwork/orbis-rs/actions/runs/38136573869):
  fifteen minutes per curve with verified signing, stored/inline decryption,
  revocation/regrant and three full-member restarts. It keeps membership fixed.

The standalone Trust checks use independently provisioned consensus trust and
exercise rejected proofs. The gateway loads the matching shared verifier; ship
its library and header together as described in [verifier integration](native-verifier.md).
The historical September integration baseline remains in
[native-integration.md](native-integration.md).

## Release limits

This set establishes bounded single-host functional integration. It does not
establish exhaustive upstream API/error parity, long natural refresh or membership
soaks, a steady-state memory bound, overload behavior, multi-host/WAN performance,
physical power-loss durability or a completed security review. Original unexplained
recovery failures remain open despite later passing checks.

The stronger repeated-member test in
[Orbis run 38163214066](https://github.com/sourcenetwork/orbis-rs/actions/runs/38163214066)
failed signing after the first replacement and restart on both curves with
`FailedPrecondition` for insufficient shares. It used candidate runtime
`d80d02d6f2f3606cd0c0a9688c7a5ae09d658bd4`, including a paired-share promotion
fix, rather than the frozen runtime listed above. This candidate has not qualified
repeated reentry or a final replacement consumer set; the signing cause remains
under investigation. Earlier bounded passes do not close this gate.

The normal Linux release bundle includes executable and source provenance, lockfile
and toolchain hashes, runtime library names and checksums. Its bounded verifier and
two clean-build comparison cover packaging; they do not replace the remaining
operational gates. Consult [operations and backup limits](operating.md),
[certified readiness](readiness.md), [history recovery](history-storage.md) and
[measured performance](performance-20261011.md) before relying on a deployment.
