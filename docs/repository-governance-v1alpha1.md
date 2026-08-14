# Repository governance contract v1alpha1

`governance/main-v1alpha1.json` is the sole checked-in source of truth for the
repository-owned protection of `main`. It intentionally does not copy or own
the organization baseline rulesets that GitHub layers on top.

The contract requires all main changes to arrive through a pull request, with
strict status checks tied to the GitHub Actions integration that produced the
successful PR and main evidence:

- `test (ubuntu-latest)`;
- `test (macos-latest)`;
- `govulncheck`;
- `Analyze (go)`.

The policy requires zero approvals and does not require code-owner review,
last-push approval, conversation resolution, deployments, or a merge queue.
Merge is the only permitted merge method, and repository auto-merge must be
enabled. This keeps autonomous development possible while making CI and CodeQL
non-bypassable at the repository ruleset layer.

The merge-method constraint is not a preference. `internal/provenance` binds an
integration commit to an exact PR base, head, tree and ordered parents, and
requires a two-parent merge. Squash and rebase discard that relation by
construction — neither preserves the PR head as a parent — so a change
integrated either way reaches `main` in a state `check-provenance` must reject,
and `docs/releasing.md` step 3 could not be satisfied. Constraining the ruleset
is the only resolution that keeps the property provenance exists to prove.
The validator also requires the inherited effective deletion,
non-fast-forward, and verified-signature rules to remain present, without
claiming ownership of their organization-level source.

Run the static contract and workflow check with:

```sh
go run ./cmd/check-governance-contract
```

Print the exact REST request body derived from the canonical contract with
`go run ./cmd/check-governance-contract -print-ruleset`. Compare a normalized
API capture with `-snapshot`; comparison fails closed on missing, duplicate,
renamed, wrong-app, inactive, bypassed, loose, or otherwise drifting state.

The local CI workflow is checked for unconditional `pull_request` and main
`push` coverage without path filters, exact required jobs, and its complete
Ubuntu/macOS matrix. GitHub-managed CodeQL has no repository workflow file, so
its workflow ID, active dynamic path, exact check context, and GitHub Actions
integration identity are verified from API evidence instead.

Rollback restores the recorded pre-change repository settings and deletes the
repository-owned ruleset by its recorded ID. The inherited organization
baseline is never part of that rollback.
