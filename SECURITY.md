# Security policy

## Supported versions

Until 1.0, only the latest tagged release receives security fixes.

## Reporting a vulnerability

Do not open a public issue. Use the repository's
[private security advisory form](https://github.com/NDDev-it-com/agent-runtime/security/advisories/new).
Include the affected version, operating system, reproduction, impact, and any
suggested mitigation. Maintainers aim to acknowledge complete reports within
five business days. Disclosure timing is coordinated after a fix is available.

## Trust boundary

Task manifests and their command arrays must come from trusted, reviewed
sources. Workspace path confinement protects instruction selection; it does not
confine the process that is launched. Environment allowlisting reduces accidental
credential inheritance but is not sufficient isolation. It also does not govern
which executable is selected: a bare command name is resolved against the
caller's `PATH` before the child environment is applied, so the host, not the
manifest, decides which binary runs. Pass an absolute path where that matters.
Use an external sandbox for untrusted code and provide only short-lived,
least-privilege credentials.

Avoid placing secrets in manifests, instructions, command arguments, logs, or
issue reports. Captured command output may contain sensitive data and should be
handled accordingly by callers.

## Release integrity

Official releases originate only from annotated signed `vMAJOR.MINOR.PATCH`
tags on the exact current `main` commit. Verify downloaded assets against
`SHA256SUMS`, inspect the SPDX JSON and release manifest, and run
`gh attestation verify <asset> -R NDDev-it-com/agent-runtime`. Release assets
and tags are append-only; a correction is a new version, never a rewritten tag.

Goal journals may contain repository paths, command names, issue references, and
review findings. Receipts must reference evidence without embedding credentials
or sensitive output. Journal paths are caller-controlled and are not workspace
confined; store them in a trusted directory. Atomic replacement protects against
partial writes, while filesystem permissions and host integrity remain the
caller's responsibility.

Journal locking coordinates cooperating `agent-runtime` processes on macOS and
Linux. It does not defend against a malicious local process that bypasses the
lock or replaces directories concurrently.

## Observability data

Treat every lifecycle attribute as untrusted and potentially secret. Sensitivity
labels are an additional control, not permission to persist credentials: unsafe
names and values are denied at every sensitivity, and an emitter refuses a
maximum sensitivity above `internal` outright. Identities — runtime, sink,
correlation, subject and actor names — are validated against their grammar and
are not attribute values; do not place secrets in them. Events intentionally exclude
Task output, instruction context, command arguments, environment values, Goal
prose, provider payloads, raw errors, and raw sink failures.

Redaction occurs before an immutable envelope reaches a sink. Nested structures
are re-evaluated key by key, bounded, copied, and JSON encoded; custom errors and
stringers are never invoked. Redaction metadata contains only typed reasons and
aggregate counts, not paths, hashes, lengths, or removed values.

JSONL paths are trusted caller configuration. Existing files must be regular,
owner-only, supported-version canonical JSONL. Symlinks, partial records,
duplicates, unsupported versions, oversize files, and corruption fail closed.
The sink does not encrypt data or protect against a compromised host.
