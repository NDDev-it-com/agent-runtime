// SPDX-License-Identifier: AGPL-3.0-only

package governance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
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
	desiredRules, err := normalizedRules(desired.Rules)
	if err != nil {
		return err
	}
	observedRules, err := normalizedRules(observed.Rules)
	if err != nil {
		return err
	}
	if string(desiredRules) != string(observedRules) {
		return errors.New("repository ruleset rules drift")
	}
	return nil
}

func normalizedRules(rules []RulesetRule) ([]byte, error) {
	type normalized struct {
		Type       string          `json:"type"`
		Parameters json.RawMessage `json:"parameters,omitempty"`
	}
	items := make([]normalized, len(rules))
	for i, rule := range rules {
		var value any
		if len(rule.Parameters) > 0 {
			if err := json.Unmarshal(rule.Parameters, &value); err != nil {
				return nil, err
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			items[i] = normalized{Type: rule.Type, Parameters: canonical}
		} else {
			items[i] = normalized{Type: rule.Type}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Type < items[j].Type })
	return json.Marshal(items)
}
