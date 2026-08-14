# Contributing

Open an issue before substantial changes so scope and compatibility can be
agreed. Security reports must follow `SECURITY.md`.

Development requires Go 1.25 or newer. Before submitting a pull request, run:

```sh
go test -race ./...
go run ./cmd/check-fuzz
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go build ./cmd/agent-runtime
go run ./cmd/check-ci-contract
```

The linter version is not a preference: `security-tools.json` pins it and
`check-ci-contract` fails if CI runs a different one. `staticcheck.conf` records
which checks are disabled and why.

Keep the core provider-neutral, add tests for behavior changes, update public
documentation and `CHANGELOG.md`, and avoid introducing dependencies without a
clear maintenance and security benefit. Commits should be focused and
sign-off is not required.
