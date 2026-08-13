# Releasing

1. Confirm the changelog date and version links.
2. Run `go test -race ./...`, `go vet ./...`, and `go build ./cmd/agent-runtime`.
3. Run `go run ./cmd/check-ci-contract`; this enforces the checked
   [`security-tools.json`](../security-tools.json) contract. It keeps the Go
   1.24 compatibility lane distinct from the toolchain required to execute the
   pinned scanner.
4. Run `govulncheck ./...` with the version pinned in that contract.
5. Confirm CI succeeds on the exact commit. Local checks are not evidence of CI.
6. Create a signed `vMAJOR.MINOR.PATCH` tag and publish release notes derived
   from the changelog.
7. Verify `go install github.com/NDDev-it-com/agent-runtime/cmd/agent-runtime@VERSION`
   from a clean environment.

Do not publish a tag when any required check is pending or failed. Artifact
signing and provenance are roadmap work; release notes must not claim them.
