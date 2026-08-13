# Contributing

Open an issue before substantial changes so scope and compatibility can be
agreed. Security reports must follow `SECURITY.md`.

Development requires Go 1.25.0 or newer. Set `GOTOOLCHAIN=local` so an older
ambient toolchain cannot silently download a replacement. Before submitting a
pull request, run:

```sh
go test -race ./...
go run ./cmd/check-fuzz
go vet ./...
go build ./cmd/agent-runtime
go run ./cmd/check-ci-contract
```

Keep the core provider-neutral, add tests for behavior changes, update public
documentation and `CHANGELOG.md`, and avoid introducing dependencies without a
clear maintenance and security benefit. Commits should be focused and
sign-off is not required.
