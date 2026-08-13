# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and uses an unstable `v1alpha1` manifest until its first stable
contract.

## [Unreleased]

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
