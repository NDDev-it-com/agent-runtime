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
gzip order, ownership, modes and timestamps are normalized. The published stage
directory and every published asset also have their modes set explicitly, because
`O_CREAT` and `mkdirat` subtract the process umask from a requested mode: without
that, release output would depend on the shell that produced it and a host with a
restrictive umask could not build at all. The SPDX 2.3 JSON
inventories every archived file; the manifest binds release, commit, module,
Go baseline, workflow, pinned actions and content-asset digests. `SHA256SUMS`
covers every other asset and deliberately does not checksum itself.

## Pre-tag gate

1. Reconcile `CHANGELOG.md`, public docs, schemas and the Goal journal.
2. Run `go run ./cmd/check-module-tidy`. This is the authoritative non-mutating
   module gate: it executes `GOTOOLCHAIN=local go mod tidy -diff` and uses that
   command's own status and output. It never compares feature work with `HEAD`.
3. Verify each PR source commit with
   `go run ./cmd/check-signature --commit "$(git rev-parse HEAD)"`. After merge,
   verify the integration graph with
   `GH_TOKEN=... go run ./cmd/check-provenance --integration "$(git rev-parse HEAD)"`.
   The graph has three distinct roles:
   owner SSH-signed source commits, a GitHub OpenPGP-signed two-parent merge
   commit bound to the exact PR base/head/tree and successful exact-head check
   identities, and the owner SSH-signed annotated release tag. The verifier
   uses only the repository-owned `.github/release-allowed-signers` snapshot and
   binds verification to held ancestor directory identities. Where `.git` is a
   pointer file rather than a directory — a submodule or a linked worktree — the
   pointer is held by identity, its `gitdir:` target is resolved against the work
   tree, and that directory is held under the same discipline before Git is given
   it as `--git-dir`. A pointer that is rewritten or replaced after capture fails
   the run. On Darwin, the
   only accepted ancestor alias is the root-owned canonical
   `/var -> private/var` system transition; Linux accepts no ancestor aliases.
   Every alias and directory identity is revalidated before and after Git runs.
   The verifier uses command-local Git configuration; it never reads or writes
   ambient Git trust.
   The contract pins repository, authorized merger, GitHub web-flow signer and
   GitHub Actions app database/node identities. Display names and commit author
   strings are never trust inputs; PR number, base/head/tree/parent order and
   pre-merge check runs remain bound to the exact integration commit.
   REST commit associations discover a bounded candidate set only. Exactly one
   candidate must independently match GitHub's GraphQL merged-PR commit, tree
   and ordered-parent relation plus the REST/local signed commit. The REST
   pull request `merge_commit_sha` is stateful across open/merged state and
   merge methods, so it is retained only as diagnostic API evidence and is
   never normalized, compared, or used as integration authority. Missing,
   duplicate, ambiguous, indirect, squash and rebase relations fail closed.
   Integration verification is native Go on Linux and macOS. Its sole provider
   public key, fingerprint, byte digest, active status and reviewed-change-only
   rotation/revocation policy live in `provenance/v1alpha1.json`; it uses no
   ambient GPG executable, keyring, home directory, global Git configuration or
   author identity. Trust changes require a reviewed contract, schema and key
   update and invalidate old or revoked material fail closed.
   GitHub REST `verification.payload` is the value that was signed and
   `verification.signature` is the extracted signature. The verifier requires
   the provider payload to equal Git's normative unsigned commit payload and
   verifies both the provider pair and the locally embedded signature with the
   pinned key. It does not confuse Git's multiline `gpgsig` header-continuation
   whitespace with the extracted signature contract. Tree, ordered parents,
   author and committer remain exactly bound to REST, GraphQL and the local
   content-addressed commit object.
4. Run `go run ./cmd/check-cold-compile`. It owns a fresh private driver, build
   cache and work root for every supported `darwin/linux` and `amd64/arm64`
   combination, verifies driver identity before and after compilation, and
   compiles all applicable packages without running cross-target test binaries.
5. Run `go run ./cmd/check-release-contract` and build twice from the same exact
   commit. Create only private parent directories and pass distinct non-existent
   final leaves. Use the canonical quoted `parent="$(mktemp -d)"` form; do not
   concatenate separators onto `TMPDIR` or `RUNNER_TEMP`. Each build writes a
   `v1alpha1` result receipt containing the
   canonical artifact root, resolved commit, module/version/license inputs and exact
   ordered asset path/size/SHA-256 closure. Validate each receipt with
   `--verify-result`, then compare the two artifact roots byte-for-byte. Never
   hard-code an inferred contract path or pre-create an output leaf: the builder
   owns staging and publishes each complete bundle with atomic no-replace
   semantics.
6. Run full tests, race, fuzz seeds, vet, formatting, CI/security/governance
   contracts and pinned `govulncheck` under the exact patched Go 1.26.6
   security lane. The module declaration and test/release lanes remain Go 1.24.
   Run `go run ./cmd/check-fuzz` for the active fuzzing gate. It inventories
   every repository fuzz target and runs each exact package/target separately
   with the versioned bounds in `fuzz/v1alpha1.json`; direct multi-package
   `go test -fuzz` commands are not valid or accepted.
   The security lane tracks the current patch rather than a fixed one, because
   `govulncheck` resolves the live vulnerability database: a commit that scanned
   clean can start failing without any change to the repository. Go 1.26.6 fixes
   [GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218) in `net/url`,
   [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) in `crypto/tls` and
   [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) in `encoding/asn1`, all
   of which the runtime reaches; Go 1.26.5 fixed
   [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856) before them. The
   dependency closure pins CIRCL v1.6.3, whose
   [official release](https://github.com/cloudflare/circl/releases/tag/v1.6.3)
   fixes the P-384 defect tracked as GO-2026-4550.
7. Merge a signed PR only after exact-head CI and CodeQL are green. Recheck the
   post-merge `main` runs and reread this contract.
8. Confirm repository immutable releases are enabled, no tag/release exists,
   and the clean local `main` equals `origin/main`.
9. Create an annotated SSH-signed `v0.1.0` tag on that exact commit, verify it
   locally with `go run ./cmd/check-signature --tag "$(git rev-parse
   'v0.1.0^{tag}')" --expected-commit "$(git rev-parse
   'v0.1.0^{commit}')"`, and push only the tag.

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
