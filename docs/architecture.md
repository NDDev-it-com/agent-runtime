# Architecture and runtime contract

## Scope

`agent-runtime` has two work-unit mechanisms with distinct lifecycles:

```text
Task manifest -> strict validation -> workspace/context resolver -> bounded process -> result
Goal journal  -> guarded phase transition -> atomic persistence -> next phase or completion
Task/Goal/handoff -> derived lifecycle draft -> redaction -> immutable envelope -> sinks
```

The Task manifest is declarative and provider-neutral. The runtime owns validation,
context framing, path confinement, environment selection, process lifetime, and
result shape. The invoked command owns model calls, tools, and its agent loop.

## Boundaries

`DecodeTaskManifest` rejects unknown JSON fields and trailing values, applies
defaults, then validates semantic limits. `Workspace` resolves the real path of
the root and every selected path. This catches both lexical traversal and
symlink traversal before files are read or a working directory is selected.

`Runner` assembles the context in manifest order, creates a deadline derived
from the caller context, passes context on standard input, constructs a fresh
environment from the allowlist, and captures a bounded combined output stream.
The CLI always emits the result when a process was started, including non-zero
exit and timeout information, then exits non-zero when the run failed.

The `goal` package is the sole Goal state machine. A journal carries one living
acceptance checklist and receipts keyed by the canonical phase enumeration.
Transitions are forward-only and deterministic. Every mutation validates the
whole prior state, requires an optimistic revision, holds an exclusive lock,
increments the revision, syncs a temporary file, atomically renames it, and
syncs the directory. A completed Goal is immutable.

The file lock uses the platform `flock` API available on the supported macOS
and Linux targets. Windows support requires a separate locking implementation
and is not claimed by v0.

## CI toolchain contract

`security-tools.json` is the source of truth for the pinned vulnerability
scanner, its upstream-declared minimum Go version, and the production
compatibility lane. `cmd/check-ci-contract` verifies the workflow projection.
Negative tests reject a scanner lane below the upstream requirement and reject
movement of the Go 1.24 compatibility lane. CI disables automatic toolchain
downloads with `GOTOOLCHAIN=local` and records both tool versions in the job
summary.

Closure is structurally distinct from an ordinary phase receipt. It records the
achieved outcome, cleanup, typed remaining debt/risks, and canonical next work.
The state machine refuses closure unless all eight receipts and every checklist
item have evidence. JSON Schemas are distributable projections of the Go
contract; parity tests lock their versions, states, phases, evidence types, and
license identifier to the implementation.

## Observability boundary

The `observability` package is an additive adapter layer, not a third state
machine. `TaskRunner` wraps the existing Runner. `GoalStore` takes before/after
journal snapshots around the existing revision-guarded Store update. Explicit
handoff drafts represent Brain, Orchestrator, Dispatcher, Worker, and Runtime
roles without naming a provider.

An emitter serializes each operation under a mutex. This gives deterministic
per-subject sequence allocation and sink delivery order; synchronous sink calls
are the explicit backpressure boundary. Streams are bounded and ordered only
per subject. Correlation/causation link streams without claiming a global order.
Event IDs derive from canonical immutable envelope content, so retry and replay
reuse them.

Raw attributes exist only in `Draft`. Redaction recursively copies allowed
scalars, maps, and slices into bounded JSON without calling errors, stringers, or
formatters. Unsafe keys, URLs/token patterns, sensitivities, types, binary data,
cycles, depth, size, and collection overflow are handled before any Sink runs.
Only reason/count summaries leave that boundary.

Memory and JSONL sinks are concurrency-safe and idempotent by event ID. JSONL
uses owner-only regular files, canonical single-line records, append writes,
optional per-record `Sync`, bounded recovery, duplicate/version/corruption
checks, and poison-on-partial-write semantics. Delivery results return to the
observer while Task execution and Goal persistence remain authoritative.

## Compatibility

The Go module follows semantic versioning. The `v1alpha1` Task, Goal, and event schemas are unstable:
fields may change before a stable `v1` contract, with changes documented in the
changelog. Unknown fields are deliberately fatal so configuration errors cannot
silently change runtime behavior.

## Explicit non-goals for v0

- model-provider or tool-protocol integrations;
- network, syscall, filesystem-write, or descendant-process sandboxing;
- remote execution and distributed scheduling;
- secrets storage;
- interactive terminal emulation;
- networked or provider-specific run/event storage.

These need separate threat models and observable contracts. They are tracked in
the roadmap rather than hidden behind incomplete abstractions.
