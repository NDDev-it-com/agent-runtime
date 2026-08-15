# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and uses an unstable `v1alpha1` manifest until its first stable
contract.

## [Unreleased]

## [0.2.0] - 2026-08-15

A minor bump because the contract breaks. Everything here came out of a forensic
review of `main@a656bf7` and the work that followed it, and the shape repeats:
several controls could not fail for the reason they claimed, and several
declared bounds were not the bounds that held.

### Breaking

- A Task manifest that states a zero bound is refused rather than widened. On
  the wire, `"timeout": "0s"` and an absent field decode identically in Go, so
  the narrowest possible request was granted the widest possible default: five
  minutes, and a mebibyte each of output and context. A negative value was
  already refused, which made zero the only way to fail open. Defaults now apply
  only to bounds a document left silent. A Go struct literal still reads its
  zero fields as silence, because the language records nothing else.
- `security-tools.json` no longer accepts `upstream_go_mod`. It was required to
  be non-empty and nothing read, fetched, hashed, parsed or compared it, so
  either URL could have been replaced with arbitrary text and every check stayed
  green.
- The release contract gains `graph_only_modules` and its schema requires it.
  `go.sum` pins a dependency's own requirements even when nothing here compiles
  them, and asserting that closure was identical to the build closure would have
  forced a dependency's test-only module to be recorded as if this module
  depended on it.

### Added

- `cmd/check-goal-journals` holds every tracked Goal journal to the Go contract
  and to the published schema, and is a required CI step recorded in the GDS
  anchor. Every other contract here — CI, governance, release, provenance, fuzz,
  cold compile — was already proven by an executable checker; the Goal contract,
  which is the product rather than a property of the repository, was the one
  without. It refuses to pass on an empty directory, because a gate that
  succeeds by finding nothing to inspect cannot be told from one that inspected
  everything.
- `check-release-contract --expect-commit` takes the commit a bundle must have
  been built from, resolved by the caller from the checkout rather than read out
  of the receipt under test.

### Fixed

- The CI, release and governance contracts are proven against a parsed GitHub
  Actions model instead of the workflow text. All three verifiers matched
  strings, so a required command kept its evidence value while losing its
  execution: commenting out the entire signed exact-main, signature and
  provenance step left `release.yml` a valid seven-step workflow that GitHub
  would run, and all three checkers exited zero. Only enabled steps of enabled
  jobs now count, YAML and shell comments are prose, and anchors, aliases and
  duplicate keys are refused rather than approximated. Pins are counted per
  lane, the release checkout must set `persist-credentials: false`, write scopes
  must be enumerated on the publishing job alone, publication must be reachable
  only from a `v*.*.*` tag, and a required matrix lane cannot be dropped or
  renamed out from under its check name.
- A release receipt can no longer attest its own source commit. Verification
  rejected only an empty `source_commit` and then derived the receipt it
  expected from the candidate, so replacing that field with any other forty hex
  characters left the bundle reported valid while it claimed a build from a
  commit that need not exist. The expected commit is resolved from the checkout,
  bound to the annotated tag, and cross-checked against the release manifest
  travelling inside the bundle.
- Schema parity is executed rather than sampled. The previous test reflected
  over a handful of chosen constants, and the build-result version was not among
  them, so that schema required `v0.1.0` while the producer emitted `v0.1.3`
  across three releases with every test green. Tracked documents are validated
  against their published schema with a draft-2020-12 validator, each semantic
  mutation of a Task manifest must be rejected by the schema and by Go alike,
  and both release schemas are pinned to the contract version.
- Five `pattern` keywords across two schemas had no `type`, and a pattern only
  constrains strings, so a version of `12345` passed unexamined. Governance
  `required_checks` had a length and no shape; it now states both producer forms
  exactly, each forbidding the other's fields.
- Malformed evidence can no longer be staged on a pending checklist item.
  Validation covered evidence only on completed items, but acceptance evidence
  is append-only for every item, so a bad record staged on a pending one could
  never be removed and completion — which validates the combined set — refused
  forever. Well-formed staged evidence is still accepted and still completes.
- A process that returned its own exit status is no longer attributed to the
  caller. The cause was read from the context after the run returned and any
  non-nil cause counted as termination, so a command that had already failed on
  its own was reported as cancelled whenever the cancellation landed in the
  window between — five runs in four hundred, against a documented promise that
  the two are never conflated. Termination is recognised by the process carrying
  no exit status of its own, which is the one thing a context cannot report.
- `max_output_bytes` bounds what a caller receives. Raw bytes were capped on the
  way in, then each isolated invalid byte became a three-byte replacement rune
  on the way out, so a twelve-byte budget returned twenty-four bytes into
  `Result.Output`, its JSON encoding and every downstream event. The limit is
  reapplied after the repair, cut on a rune boundary.
- A timeout or cancellation ends the Task's process group on Linux and macOS,
  not only the process the runtime launched. Work a command backgrounded kept
  touching the workspace after the Runner had returned a terminal result — 2.7
  seconds after a 300 ms timeout. Owning the group also releases the inherited
  pipes at once, so that run now returns in 301 ms rather than holding for the
  full termination grace.
- A JSONL sink holds one descriptor for its lifetime. It used to open the path
  to scan the existing history, close it, and open it again to append, so a
  rename in between left the recovered duplicate-identity and size state
  describing the first file while every write went to the second. A destination
  whose name no longer resolves to the object just opened is refused rather than
  followed.
- `git` and `ssh-keygen` have one definition. `internal/provenance` repeated
  `/usr/bin/git` as a raw literal beside `internal/signatureverify`'s constant,
  and the isolated environment was written out twice — one fact in two places,
  in the code path where drift matters most. Both resolve through
  `internal/trustedexec`, which searches a fixed ordered list of absolute
  directories, never `PATH`, and requires the result to be a regular,
  non-symlink file that is not group or world writable. A Homebrew macOS host
  can now verify, which the single hardcoded path did not allow.
- `.agent-runtime/goals/first-v0-release.json` is a journal this module accepts.
  It recorded each recovery cycle under an invented receipt key, so
  `agent-runtime goal status` refused to load it — and because it is tracked, it
  shipped inside the published source archive and its SPDX inventory. The module
  distributed an artifact its own CLI rejects. Every cycle's summary and
  evidence is preserved, folded into the phase receipt each cycle already named
  in its own `phase` field, replayed through the product's own API. It also now
  states what happened: it had stood at `state: active` with all seven
  acceptance criteria pending, claiming the first release never occurred.

### Changed

- `docs/releasing.md` no longer claims the tag workflow rejects disabled
  immutable releases. It cannot: that endpoint needs admin read and the
  publishing token is held to `contents`, `id-token` and attestation scopes. The
  manual pre-tag step is the only check of that setting, and the guide says so.
- The wall-clock ceiling for a run is documented as the manifest timeout plus a
  two-second grace for a terminated process to release its pipes. The grace
  always existed; nothing said so, and `timeout` read as the whole bound.
- The security model records the two check-then-use gaps that remain rather than
  implying they are closed. Workspace resolution and executable resolution both
  validate a pathname and act on it a moment later, so an actor with concurrent
  write access to the running machine can move the used object away from the
  checked one — which also means `executable_path` records what was inspected.
  Both sit outside the stated trust boundary; the entry names what would make
  them real and what the fix would be. It also states that a host keeping its
  tools outside the resolver's fixed directories, which in practice means Nix
  and Guix, cannot verify at all, and why covering them would be worse.
- `.gds/repository.yaml` states how the module is actually consumed. Its module
  block declared `commit-contract` and `default-branch-commit`, justified by a
  comment saying no semver tag existed — which stopped being true at `v0.1.2`.
  It now declares `semver` and `version-tag`.
- `github.com/goccy/go-yaml` and `github.com/santhosh-tekuri/jsonschema/v6`
  enter the dependency closure, as the Actions parser and the schema validator
  behind the two checks above. Fixing a hand-rolled-parser defect with a second
  hand-rolled parser would repeat it. The release contract's dependency licence
  rule, previously a single `BSD-3-Clause` constant, is now a closed allowlist.

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
