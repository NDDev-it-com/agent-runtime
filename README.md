# agent-runtime

`agent-runtime` provides two vendor-neutral work-unit contracts for agents:

- A **Task** is bounded and atomic, with explicit acceptance represented by a
  versioned Task manifest.
- A **Goal** is complex or long-running and carries a durable, versioned journal,
  living acceptance checklist, ordered phases, and machine-verifiable receipts.

The Go packages can be embedded; the reference CLI is useful in scripts,
contract tests, and restart-safe agent workflows.

The optional `observability` package derives provider-neutral lifecycle events
from those authoritative work units and delivers them through redaction-aware
sinks. It never replaces Task results or Goal journals.

Repository governance is declared by the versioned
[`governance/main-v1alpha1.json`](governance/main-v1alpha1.json) contract and
validated by `go run ./cmd/check-governance-contract`. See
[`docs/repository-governance-v1alpha1.md`](docs/repository-governance-v1alpha1.md).

The initial release focuses on the boundary between a control plane and an
already-installed agent client. It does not implement a model provider, tool
protocol, scheduler, or operating-system sandbox.

## Quick start

Requires Go 1.25 or newer.

```sh
go install github.com/NDDev-it-com/agent-runtime/cmd/agent-runtime@v0.1.2
agent-runtime task validate --manifest examples/basic/agent.json --workspace examples/basic
agent-runtime task run --manifest examples/basic/agent.json --workspace examples/basic
```

The command receives the assembled instruction context on standard input. Its
combined standard output and standard error are returned as one JSON object:

```json
{"agent_id":"example","exit_code":0,"duration_ms":2,"output":"...","truncated":false,"timed_out":false,"cancelled":false,"accepted":true}
```

## Task contract

```json
{
  "schema_version": "v1alpha1",
  "id": "example",
  "description": "Minimal local agent",
  "instructions": ["AGENTS.md"],
  "command": ["sed", "-n", "1,3p"],
  "acceptance": {
    "exit_codes": [0],
    "output_contains": ["AGENTS.md"]
  },
  "workdir": ".",
  "env": ["PATH"],
  "timeout": "30s",
  "max_output_bytes": 1048576,
  "max_context_bytes": 1048576
}
```

Acceptance is explicit and machine-evaluated: the observed exit code must be in
`exit_codes`, and every optional `output_contains` value must occur in the
bounded combined output. Task instruction order is significant. Each file is preceded by a deterministic
`--- path ---` boundary. Unknown fields, duplicate paths or environment names,
invalid identifiers, and unsupported versions are rejected.

Defaults are a five-minute timeout and 1 MiB each for context and captured
output. Maximums are 24 hours, 16 MiB of context, and 64 MiB of output.
`max_context_bytes` bounds the read itself, not only the assembled result, so an
instruction file larger than the budget is rejected from its metadata without
being loaded.

A run that ends early reports why. `timed_out` means the manifest timeout
elapsed; `cancelled` means the caller ended the run, either by cancelling its
context or by reaching its own deadline. The two are never conflated, and the
returned error wraps the caller's cause so `errors.Is` still works.

The canonical distributable schema is
[`schemas/task-manifest-v1alpha1.schema.json`](schemas/task-manifest-v1alpha1.schema.json).

## Releases

The project is released as a Go module/source product. It does not publish
prebuilt platform binaries.

The first published release is `v0.1.2`. `v0.1.0` and `v0.1.1` were tagged but
never published — the first pinned a Go toolchain below the module's own
directive, the second read a repository setting its token cannot access, and
both failed before building an asset. Those tags and their Go module proxy
entries are immutable, so they are left in place carrying no release assets and
no attestations. Use `v0.1.2` or later.

Each tag-only release will contain one deterministic tracked-source archive, an
SPDX 2.3 JSON SBOM, canonical release notes, a release manifest, and
`SHA256SUMS`. The annotated signed tag identifies the exact `main` commit;
each dry-run or publication build also emits a versioned machine-readable build
result that binds its canonical artifact root, source and AGPL license inputs, and exact asset
path/size/digest closure.
GitHub OIDC/Sigstore attestations cover every material asset. See
[`docs/releasing.md`](docs/releasing.md) for verification and rollback rules.
The repository-owned [provenance contract](provenance/v1alpha1.json) separates
owner SSH-signed source commits, GitHub OpenPGP-signed protected-main merge
commits, and owner SSH-signed release tags. Its native verifier pins reviewed
public trust bytes and exact PR, graph, workflow and check identities on both
Linux and macOS without ambient GPG or Git trust configuration.

## Goal contract

Every Goal progresses through exactly these phases:

1. `orient`
2. `gap_plan`
3. `execute`
4. `reconcile`
5. `self_review`
6. `completeness_omission_audit`
7. `verify`
8. `closure`

Each transition requires typed evidence and a phase receipt. Closure additionally
requires an achieved outcome, cleanup record, explicit typed debt/risk list, and
canonical next-work references. All acceptance checklist items must be complete
with evidence. Passing one test or reaching `execute` can never complete a Goal.

```sh
agent-runtime goal init --journal goal.json --id release \
  --intent 'Ship a release-ready runtime' \
  --acceptance build='The binary builds' \
  --non-goal 'Remote orchestration'

agent-runtime goal advance --journal goal.json --revision 1 --phase orient \
  --summary 'Inspected repository and prior attempts' \
  --evidence-type command --evidence-ref 'git status --short' \
  --evidence-result 'clean repository'

agent-runtime goal status --journal goal.json
```

Mutations require the expected journal revision, use an exclusive file lock,
write a synced temporary file, and atomically replace the journal. Loading the
journal restores the full checklist and evidence after restart or compaction.
Goal identity, sealed receipts and recorded acceptance history are immutable:
the store validates the transition itself, so no mutation can rewrite what a
prior phase reported.
The canonical distributable schema is
[`schemas/goal-journal-v1alpha1.schema.json`](schemas/goal-journal-v1alpha1.schema.json).

Evidence discovered later can be appended to an existing receipt with
`goal evidence`; receipt summaries and existing evidence remain immutable. The
`--*-type`, `--*-ref` and `--*-result` flags are repeatable and positional with
respect to each other, so one command can record several evidence records; an
unequal count is rejected rather than silently truncated.

The journal is designed for durable evidence, so commit it when it represents
public project work. The adjacent `*.lock` file is ephemeral and ignored.

## Lifecycle observability

```go
memory, _ := observability.NewMemorySink("events", 100)
emitter, _ := observability.NewEmitter(
    observability.Runtime{ID: "runtime-1", Version: "0.1.0"},
    []observability.Sink{memory}, observability.Options{},
)
observed := observability.TaskRunner{
    Runner: agentruntime.Runner{Workspace: workspace}, Emitter: emitter,
    Context: observability.Context{
        CorrelationID: "request-1",
        Actor: observability.Actor{Kind: observability.ActorWorker, ID: "worker-1"},
        Attempt: observability.AttemptInitial,
    },
}
run := observed.Run(ctx, manifest)
```

`run.Result` and `run.ExecutionError` remain authoritative. `run.Events` and
`run.Delivery` expose immutable observations and every sink outcome. The package
also provides `GoalStore`, explicit handoff events, an in-memory sink, and a
durable JSONL sink. See [`docs/observability-v1alpha1.md`](docs/observability-v1alpha1.md)
and the canonical [event schema](schemas/lifecycle-event-v1alpha1.schema.json).

## Security model

Task manifests and commands are trusted inputs. The runtime resolves the workspace,
working directory, and instruction files through symlinks and rejects paths that
leave the workspace. Child processes receive only environment variables named
by the manifest. Context and captured output are bounded, and cancellation or a
timeout terminates the direct child process.

A bare command name is resolved against the `PATH` the runtime reads through
`Runner.LookupEnv` — the same source that supplies the values named by the
manifest allowlist — so resolution and the child environment come from one
place. An embedder that supplies `LookupEnv` therefore decides which executable
runs; the default reads the process environment, so the CLI still resolves
against the caller's `PATH`. Empty and relative `PATH` entries are skipped
because they resolve against the runtime's working directory rather than the
Task's. `Result.executable_path` records the file that ran.

These controls are not a sandbox. A trusted command can still access files,
processes, credentials, and networks available to its operating-system identity;
descendant-process cleanup is platform dependent. Run untrusted agents in a
container, VM, or OS sandbox with least-privilege credentials. See
[`SECURITY.md`](SECURITY.md) and [`docs/architecture.md`](docs/architecture.md).

Observability defaults to fail-closed redaction, driven by a vocabulary of
attribute names and values rather than by scanning a value for the shape of a
secret: naming an attribute honestly is the caller's job. Attribute sensitivity
must be declared; confidential/secret, raw command/environment/provider content,
credentials, unsafe URLs, binary values, errors/stringers, unknown structures,
and oversize content are never sent to sinks. Redaction decisions report only
reason/count pairs.

## Development

```sh
go test -race ./...
go run ./cmd/check-fuzz
go vet ./...
go build ./cmd/agent-runtime
```

The public API is pre-1.0 and the manifest is explicitly `v1alpha1`. Breaking
contract changes are recorded in [`CHANGELOG.md`](CHANGELOG.md).

## Project policy

- Bugs and scoped feature requests belong in GitHub Issues.
- Larger deferred work is kept in [`ROADMAP.md`](ROADMAP.md), linked to an issue
  before implementation.
- Security reports follow [`SECURITY.md`](SECURITY.md), not public issues.
- Contributions follow [`CONTRIBUTING.md`](CONTRIBUTING.md).

Licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`).
