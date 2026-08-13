# Releasing the Go module/source product

`release/v1alpha1.json` is the only release source of truth. The first version
is `v0.1.0`; the compatibility declaration remains Go 1.24. The repository
ships the Go module and tracked source, not prebuilt binaries or a platform
matrix.

## Five-asset contract

The exact release asset set is:

- `agent-runtime-v0.1.0-source.tar.gz`
- `agent-runtime-v0.1.0.spdx.json`
- `release-notes-v0.1.0.md`
- `release-manifest-v0.1.0.json`
- `SHA256SUMS`

The builder reads the exact Git commit tree. It rejects symlinks, gitlinks,
special files, unsafe or colliding paths and bounded-size violations. Tar and
gzip order, ownership, modes and timestamps are normalized. The SPDX 2.3 JSON
inventories every archived file; the manifest binds release, commit, module,
Go baseline, workflow, pinned actions and content-asset digests. `SHA256SUMS`
covers every other asset and deliberately does not checksum itself.

## Pre-tag gate

1. Reconcile `CHANGELOG.md`, public docs, schemas and the Goal journal.
2. Run `go run ./cmd/check-module-tidy`. This is the authoritative non-mutating
   module gate: it executes `GOTOOLCHAIN=local go mod tidy -diff` and uses that
   command's own status and output. It never compares feature work with `HEAD`.
3. Run `go run ./cmd/check-release-contract` and build twice from the same exact
   commit into separate empty directories; require byte equality.
4. Run full tests, race, fuzz seeds, vet, formatting, CI/security/governance
   contracts and pinned `govulncheck` under Go 1.25.
5. Merge a signed PR only after exact-head CI and CodeQL are green. Recheck the
   post-merge `main` runs and reread this contract.
6. Confirm repository immutable releases are enabled, no tag/release exists,
   and the clean local `main` equals `origin/main`.
7. Create an annotated SSH-signed `v0.1.0` tag on that exact commit, verify it
   locally with `.github/release-allowed-signers`, and push only the tag.

The tag workflow rejects reruns, wrong refs or versions, lightweight/unverified
tags, a tag not equal to current `main`, disabled immutable releases, an
existing release, drifted assets, or missing checks. PR/main jobs are read-only
and never publish. The release job alone receives `contents: write`,
`id-token: write`, `attestations: write`, and `artifact-metadata: write`; it
uses no PAT, signing secret, environment or human approval gate.

## Consumer verification

Download all five assets, then run:

```sh
sha256sum -c SHA256SUMS
gh attestation verify agent-runtime-v0.1.0-source.tar.gz -R NDDev-it-com/agent-runtime
gh attestation verify agent-runtime-v0.1.0.spdx.json -R NDDev-it-com/agent-runtime
gh attestation verify release-notes-v0.1.0.md -R NDDev-it-com/agent-runtime
gh attestation verify release-manifest-v0.1.0.json -R NDDev-it-com/agent-runtime
gh attestation verify SHA256SUMS -R NDDev-it-com/agent-runtime
```

Also verify the GitHub tag signature, release commit, API asset digests and
manifest/checksum closure. Discoverability checks use the public Go proxy,
sumdb and pkg.go.dev. Index delay is waiting debt; it never permits republishing.

After publication the tag, transparency-log attestations and immutable assets
are append-only. Fix a defect in a new SemVer release after owner review; never
delete, move, clobber or recreate a published version.
