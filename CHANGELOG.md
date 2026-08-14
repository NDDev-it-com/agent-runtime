# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and uses an unstable `v1alpha1` manifest until its first stable
contract.

## [Unreleased]

### Fixed

- A JSONL sink holds one descriptor for its lifetime. It used to open the path
  to scan the existing history, close it, and open it again to append, so a
  rename in between left the recovered duplicate-identity and size state
  describing the first file while every write went to the second. A destination
  whose name no longer resolves to the object just opened is refused rather than
  followed.

### Changed

- The security model records the two check-then-use gaps that remain rather than
  implying they are closed. Workspace resolution and executable resolution both
  validate a pathname and act on it a moment later, so an actor with concurrent
  write access to the running machine can move the used object away from the
  checked one — which also means `executable_path` records what was inspected.
  Both sit outside the stated trust boundary, and the entry says what would make
  them real and what the fix would be if it ever changes.

- Malformed evidence can no longer be staged on a pending checklist item.
  `Validate` checked evidence only on completed items, but acceptance evidence
  is append-only for every item, so a bad record staged on a pending one could
  never be removed and `CompleteItem` — which validates the combined set —
  refused forever. The journal stayed loadable and became impossible to finish
  without editing the file outside the contract. Well-formed staged evidence is
  still accepted and still completes.
- A process that returned its own exit status is no longer attributed to the
  caller. `context.Cause` was read after `Run` returned and any non-nil cause was
  treated as termination, so a command that had already failed on its own was
  reported as cancelled whenever the cancellation landed in the window between:
  measured at five runs in four hundred, against a documented promise that the
  two are never conflated. Termination is now recognised by the process carrying
  no status of its own, which is the one thing a context cannot tell you.
- `max_output_bytes` bounds what a caller receives. Raw bytes were capped on the
  way in, then each isolated invalid byte became a three-byte replacement rune
  on the way out, so a twelve-byte budget returned twenty-four bytes into
  `Result.Output`, its JSON encoding and every downstream event. The limit is
  reapplied after the repair, cut on a rune boundary.
- A timeout or cancellation ends the Task's process group on Linux and macOS,
  not only the process the runtime launched. Work a command backgrounded kept
  touching the workspace after the Runner had returned a terminal result and
  observability had recorded the run as over — measured at 2.7 seconds after a
  300 ms timeout. Owning the group also releases the output pipes at once, so
  that run now returns in 301 ms rather than holding for the full grace period.

### Changed

- The wall-clock ceiling for a run is documented as the manifest timeout plus a
  two-second grace for a terminated process to release its pipes. The grace
  always existed; nothing said so, and `timeout` read as the whole bound.

- A release receipt can no longer attest its own source commit. Verification
  rejected only an empty `source_commit` and then derived the receipt it
  expected from the candidate, so replacing that field with any other forty hex
  characters left `check-release-contract` reporting the bundle valid while it
  claimed a build from a commit that need not exist. The expected commit is now
  resolved from the checkout, bound to the annotated tag and cross-checked
  against the release manifest travelling inside the bundle.
- A Task manifest that states a zero bound is refused instead of widened. On the
  wire, `"timeout": "0s"` and an absent field decode identically in Go, so the
  narrowest possible request was granted the widest possible default: five
  minutes, and a mebibyte each of output and context. A negative value was
  already refused, which made zero the only way to fail open. Defaults now apply
  only to bounds a document left silent; a Go struct literal still reads its
  zero fields as silence, because the language records nothing else.
- `schemas/release-build-result-v1alpha1.schema.json` required `v0.1.0` while
  the producer emitted `v0.1.3`, so a real receipt failed the schema published
  to describe it. Both release schemas are now pinned to the contract version.

### Changed

- Schema parity is executed rather than sampled. The previous test reflected
  over a handful of chosen constants, and the build-result version was simply
  not among them, so it drifted across three releases with every test green.
  Tracked documents are now validated against their published schema with a
  draft-2020-12 validator, and each semantic mutation of a Task manifest must be
  rejected by the schema and by Go alike — a schema that accepts what the
  runtime refuses splits the producer from the consumer as surely as one that
  refuses what the runtime produces.
- Patterns that constrained nothing are typed. Five `pattern` keywords across
  two schemas had no `type`, and a pattern only applies to strings, so a version
  of `12345` or a source commit that was an object passed unexamined.
- `required_checks` in the governance schema had a length and no shape. It now
  states both producer forms exactly, each forbidding the other's fields, which
  is what the Go validator already enforced.
- The release contract distinguishes the build closure from the verified module
  graph. `go.sum` pins a dependency's own requirements even when nothing here
  compiles them, and asserting the two sets were identical forced a test-only
  module of a dependency to be recorded as if this module depended on it.
  `graph_only_modules` names those pins, and both closures stay exact.
- `docs/releasing.md` no longer claims the tag workflow rejects disabled
  immutable releases. It cannot: that endpoint needs admin read and the
  publishing token is deliberately held to `contents`, `id-token` and
  attestation scopes. The pre-tag step is the only check of that setting, it is
  manual, and the guide now says so.

- The CI, release and governance contracts are proven against a parsed GitHub
  Actions model instead of the workflow text. All three verifiers matched
  strings, so a required command kept its evidence value while losing its
  execution: commenting out the entire signed exact-main, signature and
  provenance step left `release.yml` a valid seven-step workflow and all three
  checkers exited zero. Only enabled steps of enabled jobs now count, YAML and
  shell comments are prose, and anchors, aliases and duplicate keys are refused
  rather than approximated. The model also expresses properties text could not:
  pins are counted per lane, `persist-credentials: false` is required on the
  release checkout, write scopes must be enumerated on the publishing job
  alone, publication must be reachable only from a `v*.*.*` tag, and a required
  matrix lane cannot be dropped or renamed out from under its check name.
- `github.com/goccy/go-yaml` enters the dependency closure as the parser behind
  that model. Fixing a hand-rolled-parser defect with a second hand-rolled
  parser would repeat it. The release contract's dependency licence rule, which
  was a single `BSD-3-Clause` constant, is now a closed allowlist.

- The GDS repository anchor declares the status checks the protected branch
  actually requires. `verification.commands` said how the module proves itself
  locally and nothing said what a merge here enforces, so the branch could lose
  a required check without any tracked file changing. The consuming control
  plane now compares the two on every run and reports drift in both directions.

## [0.1.3] - 2026-08-14

### Changed

- `Result.executable_path` records the file a run actually executed. A bare
  command name is resolved through the caller's `PATH`, so the manifest does not
  decide which binary runs (#46) and the run previously discarded the answer —
  two hosts could execute different binaries from the same manifest with nothing
  to show for it. Resolution now happens once, in the runtime, and the resolved
  absolute path is reported. The field is empty when the name does not resolve,
  and that failure keeps the error and exit code it always had.
- The security model documents two boundaries it previously left to inference.
  A bare command name is resolved through the caller's `PATH` before the child
  environment is applied, so the manifest does not decide which binary runs
  (tracked in #46). Redaction is driven by the attribute-name vocabulary rather
  than by inspecting a value for the shape of a secret, so naming an attribute
  honestly is the caller's job — a private key under a neutral name is published
  verbatim. A test now pins the second boundary in both directions.

### Fixed

- Command resolution follows `Runner.LookupEnv`. That field is the Runner's
  single source of environment values, but a bare command name was resolved by
  `exec.Command` against the *process* `PATH`, so an embedder that supplied a
  `PATH` containing no executable still ran one the host provided. Resolution
  now uses the same source as the allowlisted values, and fails before starting
  anything when the name is not found there. Empty and relative `PATH` entries
  are skipped, because both resolve against the runtime's working directory
  rather than the Task's. The default remains `os.LookupEnv`, so CLI behaviour
  is unchanged.
- `check-provenance --integration` no longer fails on a timestamp race. It
  required GitHub's `verified_at` to be at or after the pull request's
  `merged_at`, but `verified_at` records when GitHub *computed* the
  verification, not when the commit was signed, and the API guarantees nothing
  about their order. Across twenty integrations it ran from `merged_at+0s` to
  `merged_at+144s` and once landed at `merged_at-1s`, turning a green `main`
  red and blocking releases for no reason. The binding that matters — the byte
  comparison against the local commit payload, which carries the tree and parent
  SHAs, and OpenPGP verification against the pinned key — is unchanged.

## [0.1.2] - 2026-08-14

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
- Checked CI security-tool contract that pins every external tool by module path
  and version, and holds the compatibility lane to the linter's own minimum Go
  while running the vulnerability scanner under its required patched toolchain.
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
- Patched security scanning on Go 1.26.6 with a dependency closure at CIRCL
  v1.6.5, separate from the Go 1.25 module, test and release compatibility lane.
- Pinned `staticcheck` runs in the `test` job and is declared in
  `security-tools.json` alongside the vulnerability scanner. `check-ci-contract`
  verifies the pin is exact, is invoked only from that lane, and that the
  compatibility toolchain satisfies the linter's own minimum Go.
- `task.cancelled` carries the `cancelled` outcome for a Task ended by its
  caller, so the distinction the runtime now makes between a stopped Task and a
  failed one reaches consumers. It requires cancellation error evidence, an
  unaccepted result and no blocking evidence. A Task that exceeds its own
  timeout stays `task.failed`.
- `Result.Cancelled` distinguishes a caller-ended run from a Task that exceeded
  its own timeout.

### Changed

- Task manifests expose additive `Prepare` validation so observers distinguish
  validation failure from execution without changing Runner behavior.
- The published minimum is now Go 1.25. Go 1.24 has no patched release for the
  four reachable standard-library defects `govulncheck` reports — they are fixed
  only in 1.25.13, 1.26.6 and 1.27.0-rc.3 — so the test lane was running an
  unpatched toolchain. Every direct and pinned dependency has also moved its own
  floor to Go 1.25, so the previous baseline could no longer take an update from
  any of them. Changing it before the first release costs nothing: there are no
  published versions, and a released `go` directive cannot be changed in place.
- Every dependency and pinned tool is at its current release:
  `golang.org/x/mod` v0.40.0, `golang.org/x/sys` v0.47.0, `golang.org/x/crypto`
  v0.55.0, `github.com/cloudflare/circl` v1.6.5, `govulncheck` v1.7.0 and
  `staticcheck` v0.7.0. `govulncheck` now reports 3 uncalled advisories in
  required modules where it previously reported 22.
- `main` allows only two-parent merge commits. The governance contract required
  all three merge methods to stay available while the provenance verifier binds
  an integration commit to an exact PR base, head, tree and ordered parents; the
  first squash or rebase would have produced a `main` that `check-provenance`
  rejects and that no release could be cut from. The published governance schema
  and the live repository ruleset were constrained with it.
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

- Unused `verify` wrapper in `internal/signatureverify`, the duplicate
  `errSecurePublicationUnsupported` in the supported release-filesystem build,
  and an unused archive test helper — the class of dead code `go vet` does not
  report and static analysis now does.
- Unused `canonicalChecks` in the governance contract and the unused `commit`
  parameter of the release SBOM builder.

### Fixed

- The publish job no longer reads the immutable-releases setting. That endpoint
  requires admin read access, which the release token does not have and must not
  be given, so the step failed with HTTP 403 after the contract, tag signature
  and provenance had all verified — and the `v0.1.1` tag was burned the same way
  `v0.1.0` was. The guarantee comes from the organisation ruleset
  `immutable release tags` and from the pre-tag gate, neither of which depends on
  that token; `check-ci-contract` now refuses the endpoint in this lane.
- The release workflow builds again. It pinned Go 1.24 while the module declares
  `go 1.25.0`, so the publish job failed at its first step with
  `go.mod requires go >= 1.25.0 (running go 1.24.13; GOTOOLCHAIN=local)` and
  never produced an asset. `check-ci-contract` read only `ci.yml`, so the release
  lane could drift away from the compatibility toolchain unseen; it now verifies
  both workflows and fails when the release lane and the module's own directive
  disagree.
- The GDS repository anchor lists the verification commands CI actually runs.
  `staticcheck` became a required CI step and `govulncheck` has always been one,
  but neither appeared in `.gds/repository.yaml`, so the control plane's view of
  how this module proves itself was two lanes short of the truth. Nothing
  validates that correspondence, so the drift was silent.
- `check-provenance --integration` runs under a group-writable umask. The
  provider trust anchor was refused unless its permission bits excluded group
  write, but Git records the file `0644` and a checkout materialises it as
  `0644 &^ umask`, so every clone made under the common `umask 002` produced
  `0664` and failed before verifying anything — making step 3 of
  `docs/releasing.md` unrunnable on those machines while CI, at `umask 022`,
  never saw it. World-writable trust material is still refused; the integrity
  binding is the pinned SHA-256 and the `SameFile` window around the read, both
  of which detect substitution regardless of mode.
- `check-governance-contract --snapshot` accepts a live API capture. Ruleset
  rules were compared by raw JSON equality against the request body derived from
  the contract, but GitHub's ruleset read always returns `dismissal_restriction`
  and `required_reviewers`, which it never accepts as input — so the documented
  way to prove the live repository matches the contract could not pass, and the
  hand-written fixture that hid this omitted both fields. Rules are now compared
  through their typed parameters, the two returned fields are asserted to be
  neutral rather than ignored, and any parameter the contract does not model
  fails by name instead of as an unattributed "rules drift".
- The published `cancelled` outcome is reachable. `schemas/lifecycle-event-v1alpha1.schema.json`
  advertised it to every consumer while no event kind mapped to it, so no
  producer could ever emit it.
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

## [0.1.1] - 2026-08-14

Tagged, never published. The release job read the immutable-releases setting,
which its token cannot access, and failed with HTTP 403 before building an
asset. The tag and its Go module proxy entry are immutable, so it is left in
place with no assets and no attestations.

## [0.1.0] - 2026-08-14

Tagged, never published. The release job could not run, and both the tag and the
Go module proxy entry for `v0.1.0` are immutable, so the tag is left in place and
the first published release is `v0.1.1`. Everything listed under `[0.1.1]` was
already present at this tag; only the release lane differs.

[Unreleased]: https://github.com/NDDev-it-com/agent-runtime/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/NDDev-it-com/agent-runtime/releases/tag/v0.1.3
[0.1.2]: https://github.com/NDDev-it-com/agent-runtime/releases/tag/v0.1.2
[0.1.1]: https://github.com/NDDev-it-com/agent-runtime/releases/tag/v0.1.1 (tag only; no release)
[0.1.0]: https://github.com/NDDev-it-com/agent-runtime/releases/tag/v0.1.0 (tag only; no release)
