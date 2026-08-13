# Observability contract v1alpha1

This contract implements [issue #3](https://github.com/NDDev-it-com/agent-runtime/issues/3).
It is provider-neutral and deliberately separate from authoritative Task results
and Goal journals.

## Model

An `Envelope` is an immutable observation produced from a validated `Draft`.
It contains a stable content-derived event ID, subject/correlation/causation
identity, per-subject sequence, UTC timestamp, actor/runtime identity, attempt
classification, outcome, typed lifecycle payload, safe attributes, and a
redaction summary.

Sequences create a total order only within one `(subject kind, subject id)`
stream. Correlation and causation express relationships across streams without
inventing a global order. A Goal subject includes its authoritative journal
revision. Retrying delivery reuses the same envelope and event ID. Restart uses
JSONL replay checkpoints to seed each stream's next sequence.

Canonical event kinds are:

- `task.validated`, `task.started`, `task.completed`, `task.failed`,
  `task.blocked`;
- `goal.created`, `goal.checklist_added`, `goal.checklist_completed`,
  `goal.receipt_evidence_added`, `goal.phase_transitioned`, `goal.completed`,
  `goal.blocked`;
- `handoff.dispatched`, `handoff.accepted`, `handoff.completed`,
  `handoff.failed`, `handoff.blocked`.

The adapters derive these events from existing Task results and before/after
Goal journals. They do not own another state machine.

## Redaction boundary

Raw attributes exist only in `Draft`. `Emitter.Emit` applies `Policy` before it
constructs an `Envelope`; every `Sink` receives only an envelope. The default
policy permits bounded `public` and `internal` scalars/collections. It denies
`confidential`, `secret`, unknown sensitivity, binary data, invalid/cyclic or
unsupported structures, errors, formatters/stringers, raw commands,
environment/provider content, credentials, tokens, and URLs.

Nested map keys are reclassified independently. Strings, depth, collection
length, attribute count, and total canonical envelope bytes are bounded.
Redaction summaries expose only deterministic reason/count pairs—never paths,
lengths, hashes, or redacted values.

## Sink and delivery semantics

`Sink` is synchronous and safe for concurrent calls. Synchronous delivery is
the backpressure mechanism: a caller controls the deadline with `context`.
`Write` is idempotent by event ID and returns an explicit duplicate result.
Typed sink errors contain a stable code and retryability, never a raw underlying
message. `Emitter` retries only retryable failures, with a bounded attempt count,
and returns a delivery report for every sink. Delivery failure cannot alter the
Task result or Goal journal and cannot disappear from the caller.

`MemorySink` is bounded and intended for tests or short-lived collection.
`JSONLSink` appends canonical envelopes under a lock, optionally syncs every
record, detects duplicates on restart, rejects unsupported/corrupt/partial
records, becomes poisoned after an uncertain partial write, and has explicit
`Flush`/idempotent `Close` behavior. JSONL is an observability derivative, not a
journal or recovery authority.

## Compatibility and rollback

The package and schema are additive `v1alpha1`. Existing Task/Goal APIs and
schemas are unchanged. Callers opt in by constructing an emitter and lifecycle
adapter. Rollback removes emission/sinks without journal migration. Existing
JSONL remains independently readable by schema version.

## Sources

- [Go memory model](https://go.dev/ref/mem) for synchronization requirements.
- [Go `encoding/json`](https://pkg.go.dev/encoding/json) for deterministic map
  key ordering, UTF-8 coercion, and cyclic-value limitations.
- [Go `os`](https://pkg.go.dev/os) for append/file/sync primitives.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
  for sensitive-data exclusion and event-data sanitization guidance.
