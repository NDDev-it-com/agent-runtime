// SPDX-License-Identifier: AGPL-3.0-only

package governance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Snapshot struct {
	Repository      RepositoryState   `json:"repository"`
	Rulesets        []ObservedRuleset `json:"rulesets"`
	AvailableChecks []ObservedCheck   `json:"available_checks"`
	Workflows       []WorkflowState   `json:"workflows"`
	EffectiveRules  []EffectiveRule   `json:"effective_rules"`
}

type RepositoryState struct {
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	DefaultBranch  string `json:"default_branch"`
	AllowAutoMerge bool   `json:"allow_auto_merge"`
}

type ObservedRuleset struct {
	SourceType string `json:"source_type"`
	Source     string `json:"source"`
	Ruleset
}

type ObservedCheck struct {
	Context       string `json:"context"`
	IntegrationID int64  `json:"integration_id"`
}

type WorkflowState struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type EffectiveRule struct {
	Type       string `json:"type"`
	SourceType string `json:"source_type"`
	Source     string `json:"source"`
}

func LoadSnapshot(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read governance snapshot: %w", err)
	}
	var snapshot Snapshot
	if err := decodeStrict(data, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode governance snapshot: %w", err)
	}
	return snapshot, nil
}

func VerifySnapshot(contract Contract, snapshot Snapshot) error {
	if err := contract.Validate(); err != nil {
		return err
	}
	if snapshot.Repository.Owner != contract.Repository.Owner || snapshot.Repository.Name != contract.Repository.Name || snapshot.Repository.DefaultBranch != contract.Repository.DefaultBranch {
		return errors.New("repository identity or default branch drift")
	}
	if snapshot.Repository.AllowAutoMerge != contract.Repository.AllowAutoMerge {
		return errors.New("repository auto-merge setting drift")
	}
	desired, err := contract.DesiredRuleset()
	if err != nil {
		return err
	}
	matches := 0
	for _, observed := range snapshot.Rulesets {
		if observed.SourceType == "Repository" && observed.Source == contract.Repository.Owner+"/"+contract.Repository.Name && observed.Name == desired.Name {
			matches++
			if err := compareRuleset(desired, observed.Ruleset); err != nil {
				return err
			}
		}
	}
	if matches != 1 {
		return fmt.Errorf("expected exactly one matching repository ruleset, got %d", matches)
	}
	effective := make(map[string]bool, len(snapshot.EffectiveRules))
	for _, rule := range snapshot.EffectiveRules {
		if rule.Type == "" || rule.SourceType == "" || rule.Source == "" {
			return errors.New("effective rule provenance is incomplete")
		}
		effective[rule.Type] = true
	}
	for _, required := range contract.RequiredEffectiveRules {
		if !effective[required] {
			return fmt.Errorf("required effective rule %q is absent", required)
		}
	}
	available := make(map[string]int64, len(snapshot.AvailableChecks))
	for _, check := range snapshot.AvailableChecks {
		if previous, exists := available[check.Context]; exists {
			return fmt.Errorf("ambiguous observed check %q from integrations %d and %d", check.Context, previous, check.IntegrationID)
		}
		available[check.Context] = check.IntegrationID
	}
	for _, required := range contract.RequiredChecks {
		integration, exists := available[required.Context]
		if !exists {
			return fmt.Errorf("required check %q has not been observed", required.Context)
		}
		if integration != required.IntegrationID {
			return fmt.Errorf("required check %q app identity drift: got %d want %d", required.Context, integration, required.IntegrationID)
		}
		if required.Producer.Kind == "github_managed_codeql" {
			found := false
			for _, workflow := range snapshot.Workflows {
				if workflow.ID == required.Producer.WorkflowID && workflow.State == "active" && workflow.Path == "dynamic/github-code-scanning/codeql" {
					found = true
				}
			}
			if !found {
				return errors.New("required GitHub-managed CodeQL workflow is absent, renamed, or inactive")
			}
		}
	}
	return nil
}

func compareRuleset(desired, observed Ruleset) error {
	if observed.Enforcement != "active" {
		return fmt.Errorf("repository ruleset enforcement is %q, not active", observed.Enforcement)
	}
	if observed.Name != desired.Name || observed.Target != desired.Target || !equalStrings(observed.Conditions.RefName.Include, desired.Conditions.RefName.Include) || !equalStrings(observed.Conditions.RefName.Exclude, desired.Conditions.RefName.Exclude) {
		return errors.New("repository ruleset identity, target, or conditions drift")
	}
	if observed.BypassActors == nil || len(observed.BypassActors) != 0 {
		return errors.New("repository ruleset contains an unapproved bypass")
	}
	return compareRules(desired.Rules, observed.Rules)
}

// compareRules compares rules through their typed parameters rather than by raw
// JSON equality. A live ruleset read carries fields the API adds and never
// accepts as input, so byte comparison against the desired ruleset can never
// succeed; it would also turn any future GitHub-side addition into a false
// drift report while leaving a weakening inside an unmodelled field invisible.
func compareRules(desired, observed []RulesetRule) error {
	desiredByType, err := rulesByType(desired)
	if err != nil {
		return fmt.Errorf("desired ruleset: %w", err)
	}
	observedByType, err := rulesByType(observed)
	if err != nil {
		return fmt.Errorf("observed ruleset: %w", err)
	}
	for ruleType := range observedByType {
		if _, expected := desiredByType[ruleType]; !expected {
			return fmt.Errorf("observed ruleset carries unexpected rule %q", ruleType)
		}
	}
	for ruleType, desiredParameters := range desiredByType {
		observedParameters, present := observedByType[ruleType]
		if !present {
			return fmt.Errorf("observed ruleset is missing rule %q", ruleType)
		}
		switch ruleType {
		case "pull_request":
			if err := comparePullRequestRule(desiredParameters, observedParameters); err != nil {
				return err
			}
		case "required_status_checks":
			if err := compareRequiredStatusRule(desiredParameters, observedParameters); err != nil {
				return err
			}
		default:
			return fmt.Errorf("ruleset rule %q has no comparison", ruleType)
		}
	}
	return nil
}

func rulesByType(rules []RulesetRule) (map[string]json.RawMessage, error) {
	byType := make(map[string]json.RawMessage, len(rules))
	for _, rule := range rules {
		if _, exists := byType[rule.Type]; exists {
			return nil, fmt.Errorf("duplicate rule %q", rule.Type)
		}
		byType[rule.Type] = rule.Parameters
	}
	return byType, nil
}

func comparePullRequestRule(desiredParameters, observedParameters json.RawMessage) error {
	var want, got pullRequestParameters
	if err := decodeStrict(desiredParameters, &want); err != nil {
		return fmt.Errorf("decode desired pull_request rule: %w", err)
	}
	if err := decodeStrict(observedParameters, &got); err != nil {
		return fmt.Errorf("decode observed pull_request rule: %w", err)
	}
	if err := got.neutral(); err != nil {
		return err
	}
	if !equalStrings(got.AllowedMergeMethods, want.AllowedMergeMethods) {
		return fmt.Errorf("observed ruleset allows merge methods %v, want %v", got.AllowedMergeMethods, want.AllowedMergeMethods)
	}
	if got.DismissStaleReviewsOnPush != want.DismissStaleReviewsOnPush ||
		got.RequireCodeOwnerReview != want.RequireCodeOwnerReview ||
		got.RequireLastPushApproval != want.RequireLastPushApproval ||
		got.RequiredApprovingReviewCount != want.RequiredApprovingReviewCount ||
		got.RequiredReviewThreadResolution != want.RequiredReviewThreadResolution {
		return errors.New("repository ruleset review gates drift")
	}
	return nil
}

func compareRequiredStatusRule(desiredParameters, observedParameters json.RawMessage) error {
	var want, got requiredStatusParameters
	if err := decodeStrict(desiredParameters, &want); err != nil {
		return fmt.Errorf("decode desired required_status_checks rule: %w", err)
	}
	if err := decodeStrict(observedParameters, &got); err != nil {
		return fmt.Errorf("decode observed required_status_checks rule: %w", err)
	}
	if got.StrictRequiredStatusChecksPolicy != want.StrictRequiredStatusChecksPolicy || got.DoNotEnforceOnCreate != want.DoNotEnforceOnCreate {
		return errors.New("repository ruleset status-check policy drift")
	}
	if len(got.RequiredStatusChecks) != len(want.RequiredStatusChecks) {
		return fmt.Errorf("observed ruleset requires %d checks, want %d", len(got.RequiredStatusChecks), len(want.RequiredStatusChecks))
	}
	observedChecks := make(map[string]int64, len(got.RequiredStatusChecks))
	for _, check := range got.RequiredStatusChecks {
		if _, exists := observedChecks[check.Context]; exists {
			return fmt.Errorf("observed ruleset requires check %q twice", check.Context)
		}
		observedChecks[check.Context] = check.IntegrationID
	}
	for _, check := range want.RequiredStatusChecks {
		integration, present := observedChecks[check.Context]
		if !present {
			return fmt.Errorf("observed ruleset does not require check %q", check.Context)
		}
		if integration != check.IntegrationID {
			return fmt.Errorf("observed ruleset check %q app identity drift: got %d want %d", check.Context, integration, check.IntegrationID)
		}
	}
	return nil
}
