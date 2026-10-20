# Publishing the first Vera release

The maintainer publishes the nine client/verifier crates from a clean, reviewed
commit. CI validates the package boundary and prepares daemon artifacts; it has
no crates.io upload step or publishing credentials. `verad`, the node internals,
test harnesses and development tools are not published as crates.

## Current Git SDK access

Until compatible registry packages are available, use the client and verifier
from one qualified Vera Git commit. Set `VERA_SDK_REV` to its full commit hash,
then run this in the consuming project:

```sh
cargo add --git https://github.com/sourcenetwork/vera.rs --rev "$VERA_SDK_REV" vera-client vera-verifier
```

Commonware dependencies pin official upstream `96567b26` directly, so consumers
do not need to copy this repository's workspace patches. CI checks a separate
Git consumer's resolved Commonware sources against the qualified graph. The
pending DKG retry is still excluded. Git-based SDK access and daemon artifacts
can be qualified before crates.io publication; the registry prerequisites below
still apply to uploads.

## Prerequisites

Publication is currently blocked by dependencies, not by the deferred DKG fix:

- Publish compatible official Commonware packages containing the APIs and fixes
  qualified by Vera. The current Git source is `96567b26`; published `2026.9.0`
  is older and fails the registry-only SDK build. Update the registry versions
  and lockfile, replace the Git dependencies and requalify that exact release.
- Publish the shared-format `orbis-reporting` package independently of the Orbis
  service stack. Vera currently pins version `0.0.1` at source `fd22c640`. Its
  registry package must match the qualified formats. Replace the Git dependency
  with the verified registry release; a version field alongside a Git URL is
  insufficient.
- Confirm ownership and publishing rights for all nine Vera names. Log in to
  crates.io locally with the maintainer account. Do not put publishing tokens
  in workflow secrets, release notes or repository files.

Do not downgrade Commonware to make packaging pass. After the dependency changes,
merge and qualify one final release candidate. Record the exact Vera source,
Commonware and Regolith versions, shared reporting dependency and actual
Defra/Backbone consumer revisions. The unmerged Orbis service stack is excluded
from this release's qualification claim.

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

The candidate version is `0.1.0`. Use the dependency order in the generated plan;
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
shasum -a 256 target/package/vera-identity-0.1.0.crate
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
cargo add --manifest-path "$VERA_RELEASE_SMOKE/Cargo.toml" 'vera-client@=0.1.0' 'vera-verifier@=0.1.0'
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
builds the selected commit twice from clean targets, compares the recorded
compilation environments and binary/archive hashes, and retains the evidence.
Build dependencies use a dated [Ubuntu archive snapshot](https://snapshot.ubuntu.com/)
and an exact Protobuf compiler/library version. The snapshot ID and installed
package inventory are recorded in the compilation environment. Update those pins
together when qualifying a new build environment; a rolling repository must not
silently change one builder's code generator.
A `vMAJOR.MINOR.PATCH` tag additionally prepares a **draft** GitHub release; the
maintainer reviews and publishes that draft. Crate uploads remain independent
manual actions. A daemon draft alone does not satisfy the registry gates above.

Select the qualified commit already merged into `main`, then create and push the
version tag yourself:

```sh
VERA_RELEASE_SOURCE=$(git rev-parse HEAD)
VERA_RELEASE_TAG=v0.1.0
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

Download the draft assets and verify `sha256sum --check SHA256SUMS` on Linux.
Confirm the source and runtime libraries in `build.json`, run the selected binary
against the qualified configuration and review the limitations before publishing.
Only Linux x86-64 is packaged; no other target or `cargo install verad` is promised.

For evidence without a tag, dispatch the workflow with only the full `source`
commit. To retry draft creation, dispatch with that same source and its existing
`release_tag`. The workflow refuses to overwrite any existing GitHub release;
inspect and remove an incomplete draft manually before retrying. Never delete or
replace an already published release to make a rerun pass.

The release notes disclose the unpatched DKG boundary-recovery limitation, the
post-release WAN qualification and the excluded Orbis service qualification.
See [release qualification](release-qualification.md) for operating limits,
key/backup handling, recovery evidence and the remaining acceptance gates.
