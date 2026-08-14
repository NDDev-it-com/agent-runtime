# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and uses an unstable `v1alpha1` manifest until its first stable
contract.

## [Unreleased]

### Added

- `Result.Cancelled` distinguishes a caller-ended run from a Task that exceeded
  its own timeout.

### Changed

- Evidence flags on `goal check`, `goal evidence` and `goal advance` are
  repeatable, so one command can record several evidence records. A single
  triple behaves exactly as before; an unequal count is rejected.
- `agent-runtime` with no arguments prints usage to standard error and exits
  non-zero. `help`, `-h` and `--help` still print to standard output and exit
  zero.
- `NewEmitter` rejects a maximum sensitivity above `internal`. An envelope may
  only carry `public` and `internal` attributes, so a higher maximum let
  redaction pass an attribute that envelope validation then rejected, discarding
  the entire observation instead of the one attribute.
- Identity validation no longer applies the redaction word list. Runtime, sink,
  correlation, subject and actor identifiers are checked against the identity
  grammar only.
- `goal.Phases` is now the function `goal.Phases()` returning a copy, so the
  canonical phase order can no longer be reordered for the whole process.
- `Journal.CompleteItem` appends acceptance evidence instead of replacing it,
  matching the append-only semantics receipts already had.

### Removed

- Unused `canonicalChecks` in the governance contract and the unused `commit`
  parameter of the release SBOM builder.

### Fixed

- Signature and provenance verification runs in a checkout whose `.git` is a
  pointer file. `internal/signatureverify` required `.git` to be a directory, so
  a submodule or a linked worktree — the checkouts `docs/releasing.md` step 3
  tells a maintainer to verify from — failed with `not a directory` before
  reading a single Git object. The pointer's `gitdir:` target is now resolved and
  held under the same no-follow, identity-bound discipline as the work tree, and
  substituting the pointer after capture fails the run.
- The quick start no longer instructs `go install ...@v0.1.0`. The repository has
  no tag and no GitHub release, so that command failed for every reader; it now
  installs from `@main` and says plainly that no version has been published.
- Release output no longer depends on the umask of the shell that built it.
  `O_CREAT` and `mkdirat` subtract the process umask from a requested mode, so
  under `umask 077` every published asset was created `0600`, failed the
  builder's own exact-mode verification, and left residual state. The stage
  directory and every asset now have their modes set explicitly with `fchmod`,
  which the umask does not affect, and a bundle built under `umask 002`, `022`
  and `077` is byte-for-byte identical.
- The canonical module-verifier assertion is per CI lane rather than per file.
  It counted invocations across the whole workflow, so a second lane proving the
  same module closure — a legitimate CI topology — failed the check.
- The test suite no longer depends on the developer's umask. Release output
  fixtures and the JSONL permission fixture inherited it, so the same commit
  passed under `umask 022` and failed under `002` or `077`. The whole module now
  passes under `002`, `022`, `027` and `077`.
- The distributable Goal schema matches the Go contract. Checklist item
  identifiers were unconstrained while the runtime enforced an identifier
  grammar, and receipts accepted any property name while the runtime requires a
  phase, so a journal the runtime rejects still validated against the published
  schema.
- Schema parity now also covers the event `outcome`, `attempt`, subject kind,
  actor kind and handoff role vocabularies, and checks the Goal identifier
  grammar behaviourally against the state machine in both directions.
- A Goal closure carrying both a debt and a risk always emits `goal.completed`.
  The payload was validated before canonicalisation, so the randomised map order
  behind `debt_kinds` rejected roughly one completion in ten and a durably
  completed Goal silently lost its terminal event.
- Task identities the manifest contract accepts are observable again. Applying
  the redaction word list to identities rejected `run-command`, `fetch-url`,
  `provider-sync`, `raw-dump` and `curl`, and the observation was discarded.
- Opening a JSONL sink and replaying a JSONL file now share one definition of a
  valid history. The sink accepted and appended to files whose per-stream
  sequence was not increasing, which `ReplayJSONL` then rejected as corrupt.
- A caller deadline is no longer reported as a Task timeout. Both surface as
  `context.DeadlineExceeded` on the derived context, so the runtime now attaches
  a cancellation cause and attributes the termination from it.
- Caller cancellation is preserved as typed evidence. The returned error wraps
  the cancellation cause instead of only the process exit error, so a cancelled
  run is reported as `cancelled`/`cancellation` rather than a generic execution
  failure.
- The terminal Task observation is delivered on a context detached from the
  caller's. A cancelled run previously dropped its own terminal event because the
  sink received the context that had just been cancelled.
- `max_context_bytes` bounds the instruction read. An oversized file was read
  into memory in full before the limit was compared, and the comparison omitted
  the newline the assembler appends, so the result could exceed the declared
  limit by one byte.
- A completed Goal is immutable through every mutator. `AddReceiptEvidence` was
  missing the state guard its three siblings already had.
- `Store.Update` now validates the semantic transition, not only the resulting
  shape. A caller-supplied mutation can no longer rewrite goal identity, sealed
  receipt summaries, recorded timestamps, prior evidence, acceptance criteria or
  completion status while remaining structurally valid.
- `Store.Create` accepts only a genesis journal, so a fabricated multi-receipt
  history can no longer be persisted without performing a single transition.
- Added `Journal.Clone`. A `Journal` value shares its receipts map and evidence
  slices, so a "before" snapshot taken by assignment silently reflected later
  mutations.

### Security

- Moved the pinned vulnerability-scanning lane from Go 1.26.5 to Go 1.26.6.
  `govulncheck` began reporting three reachable standard-library defects against
  1.26.5 — [GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218) in `net/url`,
  [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) in `crypto/tls` and
  [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) in `encoding/asn1` — none
  of which existed in the database when the lane was pinned. All three are fixed
  in 1.26.6, and the scan is clean on it.

## [0.1.0] - 2026-08-13

### Added

- Strict `v1alpha1` JSON Task manifest and validation API.
- Durable `v1alpha1` Goal journal with an eight-phase state machine, living
  acceptance checklist, typed receipts, atomic updates, and guarded closure.
- Workspace and symlink-confined instruction context assembly.
- Environment allowlisting, timeout, cancellation, and bounded output capture.
- Embeddable Go runner and `validate`, `run`, and `version` CLI commands.
- Race-tested unit, integration, fuzz-seed, CI, security, and public project
  documentation foundations.
- GNU AGPL-3.0-only licensing with source, schema, and documentation parity
  checks against the canonical sibling license text when available.
- Checked CI security-tool contract that preserves Go 1.24 library compatibility
  while running pinned `govulncheck` v1.6.0 under its required Go 1.25 toolchain.
- Versioned, fail-closed repository governance contract and validator for
  PR-only main changes, strict exact CI/CodeQL checks, zero approvals, and
  auto-merge-compatible settings.
- Provider-neutral immutable `v1alpha1` lifecycle envelopes for Task, Goal, and
  Brain/Orchestrator/Dispatcher/Worker handoff observations.
- Fail-closed typed redaction with nested structure, cycle, formatter, unsafe
  value, Unicode/binary, depth, collection, string, attribute, stream, envelope,
  replay, and file bounds.
- Composable synchronous sinks, bounded memory and durable JSONL implementations,
  delivery reports, retry/idempotency/replay semantics, and Task/Goal adapters.
- Event JSON Schema, documentation, and deep race/fuzz/leak/restart/concurrency/
  failure tests.
- Deterministic source/module release contract with SPDX JSON, checksums,
  machine-readable manifest, signed tags and keyless artifact attestations.
- Hermetic three-role provenance verification for owner SSH source commits,
  GitHub OpenPGP integration commits and owner SSH release tags, with pinned
  reviewed public trust and exact PR/check graph binding.
- Patched Go 1.26.5 security scanning and CIRCL v1.6.3 dependency closure while
  retaining Go 1.24 module, test and release compatibility.

### Changed

- Task manifests expose additive `Prepare` validation so observers distinguish
  validation failure from execution without changing Runner behavior.

[Unreleased]: https://github.com/NDDev-it-com/agent-runtime/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NDDev-it-com/agent-runtime/releases/tag/v0.1.0
