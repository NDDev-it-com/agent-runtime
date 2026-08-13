# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and uses an unstable `v1alpha1` manifest until its first stable
contract.

## [Unreleased]

### Fixed

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

### Removed

- Unused `canonicalChecks` in the governance contract and the unused `commit`
  parameter of the release SBOM builder.

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
