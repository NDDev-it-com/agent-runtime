# Architecture and runtime contract

## Scope

`agent-runtime` has two work-unit mechanisms with distinct lifecycles:

```text
Task manifest -> strict validation -> workspace/context resolver -> bounded process -> result
Goal journal  -> guarded phase transition -> atomic persistence -> next phase or completion
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

Closure is structurally distinct from an ordinary phase receipt. It records the
achieved outcome, cleanup, typed remaining debt/risks, and canonical next work.
The state machine refuses closure unless all eight receipts and every checklist
item have evidence. JSON Schemas are distributable projections of the Go
contract; parity tests lock their versions, states, phases, evidence types, and
license identifier to the implementation.

## Compatibility

The Go module follows semantic versioning. The `v1alpha1` Task and Goal schemas are unstable:
fields may change before a stable `v1` contract, with changes documented in the
changelog. Unknown fields are deliberately fatal so configuration errors cannot
silently change runtime behavior.

## Explicit non-goals for v0

- model-provider or tool-protocol integrations;
- network, syscall, filesystem-write, or descendant-process sandboxing;
- remote execution and distributed scheduling;
- secrets storage;
- interactive terminal emulation;
- durable run/event storage.

These need separate threat models and observable contracts. They are tracked in
the roadmap rather than hidden behind incomplete abstractions.
