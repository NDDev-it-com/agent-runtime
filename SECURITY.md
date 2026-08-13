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
credential inheritance but is not sufficient isolation. Use an external sandbox
for untrusted code and provide only short-lived, least-privilege credentials.

Avoid placing secrets in manifests, instructions, command arguments, logs, or
issue reports. Captured command output may contain sensitive data and should be
handled accordingly by callers.

Goal journals may contain repository paths, command names, issue references, and
review findings. Receipts must reference evidence without embedding credentials
or sensitive output. Journal paths are caller-controlled and are not workspace
confined; store them in a trusted directory. Atomic replacement protects against
partial writes, while filesystem permissions and host integrity remain the
caller's responsibility.

Journal locking coordinates cooperating `agent-runtime` processes on macOS and
Linux. It does not defend against a malicious local process that bypasses the
lock or replaces directories concurrently.
