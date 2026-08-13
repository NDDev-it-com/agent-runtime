# Releasing

1. Confirm the changelog date and version links.
2. Run `go test -race ./...`, `go vet ./...`, and `go build ./cmd/agent-runtime`.
3. Run `govulncheck ./...` with the version pinned in CI.
4. Confirm CI succeeds on the exact commit. Local checks are not evidence of CI.
5. Create a signed `vMAJOR.MINOR.PATCH` tag and publish release notes derived
   from the changelog.
6. Verify `go install github.com/NDDev-it-com/agent-runtime/cmd/agent-runtime@VERSION`
   from a clean environment.

Do not publish a tag when any required check is pending or failed. Artifact
signing and provenance are roadmap work; release notes must not claim them.
