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
`go run ./cmd/check-governance-contract -print-ruleset`. Compare an API capture
with `-snapshot`; comparison fails closed on missing, duplicate, renamed,
wrong-app, inactive, bypassed, loose, or otherwise drifting state.

Capture the live state with:

```sh
repo=NDDev-it-com/agent-runtime
branch="$(gh api "repos/$repo" --jq .default_branch)"
{
  gh api "repos/$repo" --jq '{repository:{owner:.owner.login,name:.name,default_branch:.default_branch,allow_auto_merge:.allow_auto_merge}}'
  gh api "repos/$repo/rulesets" --jq '[.[]|select(.target=="branch").id]' | jq -r '.[]' \
    | while read -r id; do gh api "repos/$repo/rulesets/$id"; done \
    | jq -s '{rulesets:[.[]|{source_type,source,name,target,enforcement,bypass_actors:(.bypass_actors//[]),conditions,rules}]}'
  gh api "repos/$repo/commits/$branch/check-runs" --paginate \
    --jq '[.check_runs[]|{context:.name,integration_id:.app.id}]' | jq -s '{available_checks:(add|unique_by(.context))}'
  gh api "repos/$repo/actions/workflows" --jq '{workflows:[.workflows[]|{id,name,path,state}]}'
  gh api "repos/$repo/rules/branches/$branch" \
    --jq '{effective_rules:[.[]|{type,source_type:.ruleset_source_type,source:.ruleset_source}]|map(select(.type=="deletion" or .type=="non_fast_forward" or .type=="required_signatures"))}'
} | jq -s 'add' > /tmp/governance-snapshot.json

go run ./cmd/check-governance-contract --snapshot /tmp/governance-snapshot.json
```

Rules are compared through their typed parameters, not by raw JSON equality. A
live ruleset read carries `dismissal_restriction` and `required_reviewers`,
which the API returns but never accepts as input, so the request body derived
from the contract does not contain them and a byte comparison could never
succeed. Both are real policy surface — a restricted dismissal set or a
required-reviewer list is a governance change this contract does not describe —
so they are asserted to be neutral rather than ignored. Any rule parameter the
contract does not model fails the comparison by name.

The local CI workflow is checked for unconditional `pull_request` and main
`push` coverage without path filters, exact required jobs, and its complete
Ubuntu/macOS matrix. GitHub-managed CodeQL has no repository workflow file, so
its workflow ID, active dynamic path, exact check context, and GitHub Actions
integration identity are verified from API evidence instead.

Rollback restores the recorded pre-change repository settings and deletes the
repository-owned ruleset by its recorded ID. The inherited organization
baseline is never part of that rollback.
