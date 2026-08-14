// SPDX-License-Identifier: AGPL-3.0-only

// Package governance validates the versioned repository-governance contract.
package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const SchemaVersion = "v1alpha1"

type Contract struct {
	SchemaVersion          string          `json:"schema_version"`
	Repository             Repository      `json:"repository"`
	Policy                 Policy          `json:"policy"`
	RequiredEffectiveRules []string        `json:"required_effective_rules"`
	RequiredChecks         []RequiredCheck `json:"required_checks"`
}

type Repository struct {
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	DefaultBranch  string `json:"default_branch"`
	AllowAutoMerge bool   `json:"allow_auto_merge"`
}

type Policy struct {
	Name                          string   `json:"name"`
	Enforcement                   string   `json:"enforcement"`
	Target                        string   `json:"target"`
	Include                       []string `json:"include"`
	Exclude                       []string `json:"exclude"`
	BypassActors                  []Actor  `json:"bypass_actors"`
	Strict                        bool     `json:"strict"`
	RequirePullRequest            bool     `json:"require_pull_request"`
	RequiredApprovals             int      `json:"required_approvals"`
	RequireCodeOwnerReview        bool     `json:"require_code_owner_review"`
	RequireLastPushApproval       bool     `json:"require_last_push_approval"`
	RequireReviewThreadResolution bool     `json:"require_review_thread_resolution"`
	AllowedMergeMethods           []string `json:"allowed_merge_methods"`
	RequireMergeQueue             bool     `json:"require_merge_queue"`
	RequiredDeployments           []string `json:"required_deployments"`
}

type Actor struct {
	ActorID    *int64 `json:"actor_id"`
	ActorType  string `json:"actor_type"`
	BypassMode string `json:"bypass_mode"`
}

type RequiredCheck struct {
	Context       string   `json:"context"`
	IntegrationID int64    `json:"integration_id"`
	Producer      Producer `json:"producer"`
}

type Producer struct {
	Kind       string `json:"kind"`
	Path       string `json:"path,omitempty"`
	Job        string `json:"job,omitempty"`
	MatrixOS   string `json:"matrix_os,omitempty"`
	WorkflowID int64  `json:"workflow_id,omitempty"`
}

type Ruleset struct {
	Name         string        `json:"name"`
	Target       string        `json:"target"`
	Enforcement  string        `json:"enforcement"`
	BypassActors []Actor       `json:"bypass_actors"`
	Conditions   Conditions    `json:"conditions"`
	Rules        []RulesetRule `json:"rules"`
}

type Conditions struct {
	RefName RefName `json:"ref_name"`
}

type RefName struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type RulesetRule struct {
	Type       string          `json:"type"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

type requiredStatusParameters struct {
	DoNotEnforceOnCreate             bool                  `json:"do_not_enforce_on_create"`
	RequiredStatusChecks             []requiredStatusCheck `json:"required_status_checks"`
	StrictRequiredStatusChecksPolicy bool                  `json:"strict_required_status_checks_policy"`
}

type requiredStatusCheck struct {
	Context       string `json:"context"`
	IntegrationID int64  `json:"integration_id"`
}

type pullRequestParameters struct {
	AllowedMergeMethods            []string `json:"allowed_merge_methods"`
	DismissStaleReviewsOnPush      bool     `json:"dismiss_stale_reviews_on_push"`
	RequireCodeOwnerReview         bool     `json:"require_code_owner_review"`
	RequireLastPushApproval        bool     `json:"require_last_push_approval"`
	RequiredApprovingReviewCount   int      `json:"required_approving_review_count"`
	RequiredReviewThreadResolution bool     `json:"required_review_thread_resolution"`
}

func Load(path string) (Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Contract{}, fmt.Errorf("read governance contract: %w", err)
	}
	var contract Contract
	if err := decodeStrict(data, &contract); err != nil {
		return Contract{}, fmt.Errorf("decode governance contract: %w", err)
	}
	if err := contract.Validate(); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

func (c Contract) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", c.SchemaVersion)
	}
	if c.Repository.Owner == "" || c.Repository.Name == "" || c.Repository.DefaultBranch != "main" {
		return errors.New("repository owner, name, and default branch main are required")
	}
	if !c.Repository.AllowAutoMerge {
		return errors.New("auto-merge must remain enabled")
	}
	p := c.Policy
	if p.Name == "" || p.Enforcement != "active" || p.Target != "branch" {
		return errors.New("main ruleset must have a name, branch target, and active enforcement")
	}
	if !equalStrings(p.Include, []string{"~DEFAULT_BRANCH"}) || p.Exclude == nil || len(p.Exclude) != 0 {
		return errors.New("ruleset must target only the default branch")
	}
	if p.BypassActors == nil || len(p.BypassActors) != 0 {
		return errors.New("repository ruleset must declare no bypass actors")
	}
	if !p.Strict || !p.RequirePullRequest {
		return errors.New("strict status checks and pull requests are required")
	}
	if p.RequiredApprovals != 0 || p.RequireCodeOwnerReview || p.RequireLastPushApproval || p.RequireReviewThreadResolution {
		return errors.New("human approval and conversation gates are forbidden")
	}
	if p.RequireMergeQueue || p.RequiredDeployments == nil || len(p.RequiredDeployments) != 0 {
		return errors.New("merge queue and deployment gates are forbidden")
	}
	// The provenance verifier binds an integration commit to an exact PR base,
	// head, tree and ordered parents. Squash and rebase discard that relation by
	// construction: neither preserves the PR head as a parent. Permitting them
	// would let a change reach main that check-provenance must then reject.
	if !equalStrings(p.AllowedMergeMethods, []string{"merge"}) {
		return errors.New("main must allow only two-parent merge commits, which the provenance contract requires")
	}
	if len(c.RequiredChecks) != 4 {
		return errors.New("exactly four required checks are required")
	}
	if !equalStrings(c.RequiredEffectiveRules, []string{"deletion", "non_fast_forward", "required_signatures"}) {
		return errors.New("effective deletion, non-fast-forward, and signature rules are required")
	}
	seen := make(map[string]int64, len(c.RequiredChecks))
	codeQL := 0
	for _, check := range c.RequiredChecks {
		if strings.TrimSpace(check.Context) != check.Context || check.Context == "" || check.IntegrationID <= 0 {
			return errors.New("required check context and integration_id must be explicit")
		}
		if _, exists := seen[check.Context]; exists {
			return fmt.Errorf("ambiguous duplicate required check %q", check.Context)
		}
		seen[check.Context] = check.IntegrationID
		switch check.Producer.Kind {
		case "workflow":
			if check.Producer.Path != ".github/workflows/ci.yml" || check.Producer.Job == "" || check.Producer.WorkflowID != 0 {
				return fmt.Errorf("check %q has invalid repository workflow producer", check.Context)
			}
		case "github_managed_codeql":
			codeQL++
			if check.Producer.WorkflowID <= 0 || check.Producer.Path != "" || check.Producer.Job != "" || check.Producer.MatrixOS != "" {
				return fmt.Errorf("check %q has invalid CodeQL producer", check.Context)
			}
		default:
			return fmt.Errorf("check %q has unsupported producer kind", check.Context)
		}
	}
	if codeQL != 1 {
		return errors.New("exactly one GitHub-managed CodeQL check is required")
	}
	return nil
}

func (c Contract) DesiredRuleset() (Ruleset, error) {
	if err := c.Validate(); err != nil {
		return Ruleset{}, err
	}
	checks := make([]requiredStatusCheck, len(c.RequiredChecks))
	for i, check := range c.RequiredChecks {
		checks[i] = requiredStatusCheck{Context: check.Context, IntegrationID: check.IntegrationID}
	}
	status, err := json.Marshal(requiredStatusParameters{RequiredStatusChecks: checks, StrictRequiredStatusChecksPolicy: true})
	if err != nil {
		return Ruleset{}, err
	}
	pullRequest, err := json.Marshal(pullRequestParameters{AllowedMergeMethods: append([]string(nil), c.Policy.AllowedMergeMethods...)})
	if err != nil {
		return Ruleset{}, err
	}
	return Ruleset{
		Name: c.Policy.Name, Target: c.Policy.Target, Enforcement: c.Policy.Enforcement,
		BypassActors: []Actor{}, Conditions: Conditions{RefName: RefName{Include: append([]string(nil), c.Policy.Include...), Exclude: []string{}}},
		Rules: []RulesetRule{{Type: "pull_request", Parameters: pullRequest}, {Type: "required_status_checks", Parameters: status}},
	}, nil
}

func MarshalDesiredRuleset(c Contract) ([]byte, error) {
	ruleset, err := c.DesiredRuleset()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(ruleset, "", "  ")
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
