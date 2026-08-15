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
credential inheritance but is not sufficient isolation.

On Linux and macOS a Task runs in its own process group and a timeout or
cancellation terminates that group, so descendants do not continue acting on the
workspace after the run is reported as over. That is bounded ownership of what
the runtime launched, not containment: a process that leaves its group, or a
platform other than these two, is outside it. It also does not govern
which executable is selected: a bare command name is resolved against the
`PATH` the runtime reads through `Runner.LookupEnv`, the same source that
supplies the allowlisted values, so an embedder controls which executable runs
rather than inheriting whatever the host offers. The default reads the process
environment, so a CLI invocation still resolves against the caller's `PATH`;
pass an absolute path, or supply `LookupEnv`, where that must be decided by the
caller. `Result.executable_path` records the file that ran.
Use an external sandbox for untrusted code and provide only short-lived,
least-privilege credentials.

### Paths validated and paths used

Two runtime checks resolve a pathname and act on it a moment later rather than
on the object they examined. Workspace resolution returns a validated string
that `Open`, `Stat` and the child's working directory consume afterwards, and a
command name is resolved by inspecting a candidate file that `exec` opens
later. An actor able to rename or replace a directory or an executable in that
interval can move the used object away from the checked one — so
`Result.executable_path` records what was inspected, which under such a race is
not necessarily what ran.

Both require concurrent write access to the machine already running the Task,
which is outside the trust boundary above: manifests and their commands are
trusted, reviewed inputs, and a party who can rewrite a directory on the PATH
can do so with or without a race. They are recorded here rather than closed
because stating a gap is worth more than a control that does not remove it.

This holds only while that trust boundary does. If this runtime is ever used to
execute commands that are not fully trusted, these become real and the fix is
descriptor-anchored traversal and execution — the mechanism the JSONL sink and
the release publisher already use.

Avoid placing secrets in manifests, instructions, command arguments, logs, or
issue reports. Captured command output may contain sensitive data and should be
handled accordingly by callers.

### Executables the trust path runs

Signature and provenance verification shell out to `git` and `ssh-keygen`, so
which file those names refer to decides what a verdict is worth. They are never
resolved through `PATH`: the runtime searches a fixed, ordered list of absolute
directories — `/usr/bin`, `/bin`, `/usr/local/bin`, `/opt/homebrew/bin` — and
requires the result to be a regular, non-symlink file that is not group or
world writable. Children of the trust path are given exactly those directories
as their `PATH` and nothing they inherited.

The cost is real and deliberate: a host that keeps its tools outside those
directories, which in practice means Nix and Guix, cannot run verification at
all. Every mechanism that would cover them — an environment override, a `PATH`
search — is an ambient input into the one code path that must not have any.
Verification fails with a message naming what was searched rather than an
obscure exec error.

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

JSONL paths are trusted caller configuration. A sink opens its destination once
and holds that descriptor for its lifetime, so the history it recovers and the
records it appends describe one object; a name that no longer resolves to the
object just opened is refused rather than followed. Existing files must be
regular, owner-only, supported-version canonical JSONL. Symlinks, partial records,
duplicates, unsupported versions, oversize files, and corruption fail closed.
The sink does not encrypt data or protect against a compromised host.
