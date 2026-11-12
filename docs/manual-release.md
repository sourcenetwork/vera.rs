# Publishing the first Vera release

The maintainer publishes the nine client/verifier crates from a clean, reviewed
commit. CI validates the package boundary and prepares daemon artifacts; it has
no crates.io upload step or publishing credentials. `verad`, the node internals,
test harnesses and development tools are not published as crates.

## SDK access

The client and verifier `0.1.1` crates are published on crates.io. This
runbook prepares `0.1.2`, which must be published in dependency order before
consumers can resolve that version. `0.1.2` accepts Ed25519 and P-256 actors and
operator keys and records one canonical DID per secp256k1 actor, so results can
name an actor under a different spelling than a request used; see
[delegated policies](delegated-policies.md). Threshold-ring identifiers no
longer include the deployment or the creator, so `RingConfig::id` takes no
arguments and every ring identifier differs from `0.1.1`; ring commands and
updates gain `CancelReshare` and `SetPreShareEndpoints`. Consumers that derive ring
identifiers or match ring commands must be updated together with this version.
Every validator of a deployment must run the same version.

The SDK uses official Commonware `2026.10.0` registry packages. Daemon and
consumer qualification must identify the exact Vera revision and dependencies.

## Prerequisites

Before publishing:

- Qualify the selected `2026.10.0` Commonware registry packages against the
  release candidate. Disclose the deferred DKG midpoint recovery limitation.
- Verify the selected `orbis-reporting` registry package and its license against
  the release record below.
- Inspect the license notices in every package. `vera-identity`,
  `vera-zanzibar`, and `vera-acp` declare `Apache-2.0 OR MIT` and include the
  Apache 2.0 text from their Defra source revision as well as the MIT notice.
  The other packages declare `MIT` and include its notice.
- Confirm ownership and publishing rights for all nine Vera names. Log in to
  crates.io locally with the maintainer account. Do not put publishing tokens
  in workflow secrets, release notes or repository files.

Do not downgrade Commonware to make packaging pass. After the dependency changes,
merge and qualify one final release candidate. Record the exact Vera source,
Commonware and Regolith versions, shared reporting dependency and actual
Defra/Backbone consumer revisions. The Orbis service stack has merged, but its
qualification must identify and test the selected Vera and Orbis revisions.

## Shared reporting crate

Merged Orbis commit `277019f5a15fd645bd0f1e866b2519e622d28a98` has the same
`crates/reporting/src` as Vera's former `06cc2d86` Git dependency. At that merged
commit, all 48 reporting unit tests passed and locked offline packaging succeeded
with Rust 1.99.1. The resulting archive has SHA-256
`996617442e5ba5804850c4d71ec5b402371b4f7f8fbd5afe7442164b7503997e` and includes
the Business Source License 1.1 and Apache 2.0 change license. Its terms restrict
managed-service use and change to Apache 2.0 on March 13, 2030.

Vera selects the published `orbis-reporting` 0.0.2 archive, SHA-256
`9493ea2c91d02f7f3cf32c765082dda1980a5489c4ff989b78d23acc7be6e43a`. Its
`.cargo_vcs_info.json` identifies merged Orbis commit
`77b08bb3d917a25a101ed93e6822af60dcf84578`. Its library source and both license
files are identical to the 0.0.1 archive above; it adds a README. Recheck the
archive when qualifying a release candidate:

```sh
curl -fsSL https://static.crates.io/crates/orbis-reporting/orbis-reporting-0.0.2.crate -o orbis-reporting-0.0.2.crate
shasum -a 256 orbis-reporting-0.0.2.crate
tar -tzf orbis-reporting-0.0.2.crate
tar -xOzf orbis-reporting-0.0.2.crate orbis-reporting-0.0.2/.cargo_vcs_info.json
```

Check `.cargo_vcs_info.json` and the license files in the archive, and record
the source revision and archive checksum.

## Validate the candidate

Use the pinned Rust toolchain and a clean checkout of the selected commit:

```sh
git status --short
python3 .github/scripts/release-packages.py plan --output target/crate-release-plan.json
python3 .github/scripts/release-packages.py check
```

Stop if `check` fails. It inspects the resolved dependency sources as well as
manifest versions and publication metadata. The uploaded CI plan can report
blockers even when the reporting job is green.

Require the candidate's normal CI and relevant recovery checks to pass. Historical
performance and consumer evidence remains bound to its recorded revisions; a
package check does not replace runtime verification. Keep the dependency plan,
checksums, source commit and check results with the release record.

## Publish crates manually

The candidate version is `0.1.2`. Use the dependency order in the generated plan;
for the current graph it is:

| Order | Package |
| --- | --- |
| 1 | `vera-identity` |
| 2 | `vera-zanzibar` |
| 3 | `vera-acp` |
| 4 | `vera-crypto` |
| 5 | `vera-domain` |
| 6 | `vera-modules` |
| 7 | `vera-permission` |
| 8 | `vera-client` |
| 9 | `vera-verifier` |

For each package, verify its archive before uploading it. Start with:

```sh
cargo package --locked --registry crates-io -p vera-identity
shasum -a 256 target/package/vera-identity-0.1.2.crate
cargo publish --locked --registry crates-io -p vera-identity
```

Inspect the archive contents and `.cargo_vcs_info.json`: the source must be the
selected commit and the checkout must be clean. Record the SHA-256 of the archive
actually uploaded. Once the preceding package is available in the registry,
repeat packaging, verification and publication for each remaining package:

```sh
cargo publish --locked --registry crates-io -p vera-zanzibar
cargo publish --locked --registry crates-io -p vera-acp
cargo publish --locked --registry crates-io -p vera-crypto
cargo publish --locked --registry crates-io -p vera-domain
cargo publish --locked --registry crates-io -p vera-modules
cargo publish --locked --registry crates-io -p vera-permission
cargo publish --locked --registry crates-io -p vera-client
cargo publish --locked --registry crates-io -p vera-verifier
```

Run those commands one at a time. Preserve Cargo's package verification; do not
use `--no-verify`, `--allow-dirty` or bypass a failed dependency check. Confirm
registry visibility before publishing a dependent package. If interrupted,
compare the existing registry version's checksum and source with the recorded
archive before resuming at the next unpublished package. Never try to replace an
existing crate version with different contents.

From a clean environment outside this workspace, resolve and compile both SDK
roots using only registry dependencies:

```sh
VERA_RELEASE_SMOKE=$(mktemp -d)
cargo init --lib --name vera_release_smoke "$VERA_RELEASE_SMOKE"
cargo add --manifest-path "$VERA_RELEASE_SMOKE/Cargo.toml" 'vera-client@=0.1.2' 'vera-verifier@=0.1.2'
printf '%s\n' 'pub use vera_client as client;' 'pub use vera_verifier as verifier;' > "$VERA_RELEASE_SMOKE/src/lib.rs"
cargo check --locked --manifest-path "$VERA_RELEASE_SMOKE/Cargo.toml"
cargo metadata --locked --format-version 1 --manifest-path "$VERA_RELEASE_SMOKE/Cargo.toml" > "$VERA_RELEASE_SMOKE/metadata.json"
```

Retain the smoke project's lockfile and metadata. All dependencies apart from the
smoke project itself must resolve from the registry, without local patches or
source replacements. Exercise the published client against the selected daemon
with independently configured finality trust before calling the release accepted.

## Prepare daemon assets

The [Reproducible Linux release workflow](../.github/workflows/reproducible-linux-release.yml)
builds the selected commit twice from clean targets on separate hosted runners
inside the same digest-pinned official `buildpack-deps:noble-curl` container
(Ubuntu 24.04). It compares the complete recorded container environments and
binary/archive hashes and retains the evidence.
Outer runner metadata is recorded separately; job setup logs identify each host
image version. GitHub can assign different host revisions during a rollout.
Build dependencies use a dated [Ubuntu archive snapshot](https://snapshot.ubuntu.com/)
and an exact Protobuf compiler/library version. The snapshot ID and installed
package inventory are recorded in the compilation environment. Update the
container digest and package pins together when qualifying a new build environment;
a rolling repository must not silently change one builder's code generator.
A `vMAJOR.MINOR.PATCH` tag additionally prepares a **draft** GitHub release; the
maintainer reviews and publishes that draft. Crate uploads remain independent
manual actions. A daemon draft alone does not satisfy the registry gates above.

Select the qualified commit already merged into `main`, then create and push the
version tag yourself:

```sh
VERA_RELEASE_SOURCE=$(git rev-parse HEAD)
VERA_RELEASE_TAG=v0.1.2
git tag --annotate "$VERA_RELEASE_TAG" "$VERA_RELEASE_SOURCE" --message "Vera $VERA_RELEASE_TAG"
git push origin "refs/tags/$VERA_RELEASE_TAG"
```

The workflow rejects a tag pointing to a different source or a version that does
not match `verad` and the nine public crates. Source must be in `main`'s history.
It binds the comparison to the checkout's source tree, lockfile and toolchain
file. Only the final draft-release job has repository write permission.
Protect release tags against updates and deletion; do not move an existing tag.

The draft includes:

- `verad-x86_64-unknown-linux-gnu-regolith.tar.gz`, containing the normal native
  release executable and `build.json` with source, compiler, features and runtime
  shared-library requirements.
- `release.json`, containing the source/tag/version and independent-build evidence.
- `SHA256SUMS`, covering the archive and `release.json`.
- The Vera license and a third-party notice inventory tied to the release
  `Cargo.lock`, including build dependencies. Review and update the inventory
  when the lockfile changes; packaging rejects a stale lockfile hash.

Download the draft assets and verify `sha256sum --check SHA256SUMS` on Linux.
Confirm the source and runtime libraries in `build.json`, run the selected binary
against the qualified configuration and review the limitations before publishing.
Only Linux x86-64 is packaged; no other target or `cargo install verad` is promised.

For evidence without a tag, dispatch the workflow with only the full `source`
commit. To retry draft creation, dispatch with that same source and its existing
`release_tag`. The workflow refuses to overwrite any existing GitHub release;
inspect and remove an incomplete draft manually before retrying. Never delete or
replace an already published release to make a rerun pass.

The release notes disclose the DKG midpoint recovery limitation, the
post-release WAN qualification and the excluded Orbis service qualification.
See [release qualification](release-qualification.md) for operating limits,
key/backup handling, recovery evidence and the remaining acceptance gates.
