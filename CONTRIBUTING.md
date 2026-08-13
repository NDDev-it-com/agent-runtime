# Contributing

Open an issue before substantial changes so scope and compatibility can be
agreed. Security reports must follow `SECURITY.md`.

Development requires Go 1.24 or newer. Before submitting a pull request, run:

```sh
go test -race ./...
go vet ./...
go build ./cmd/agent-runtime
```

Keep the core provider-neutral, add tests for behavior changes, update public
documentation and `CHANGELOG.md`, and avoid introducing dependencies without a
clear maintenance and security benefit. Commits should be focused and
sign-off is not required.
