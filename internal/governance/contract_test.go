// SPDX-License-Identifier: AGPL-3.0-only

package governance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryContractAndWorkflow(t *testing.T) {
	t.Parallel()
	c := repositoryContract(t)
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCIWorkflow(c, workflow); err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalDesiredRuleset(c); err != nil {
		t.Fatal(err)
	}
}

func TestPositiveSnapshotMatchesCanonicalRuleset(t *testing.T) {
	t.Parallel()
	if err := VerifySnapshot(repositoryContract(t), loadTestSnapshot(t, "positive.json")); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeSnapshotFixturesFailClosed(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"negative-settings.json", "negative-bypass.json"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if VerifySnapshot(repositoryContract(t), loadTestSnapshot(t, name)) == nil {
				t.Fatal("negative fixture accepted")
			}
		})
	}
}

func TestSnapshotRejectsRequiredCheckAndSettingsDrift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		want   string
	}{
		{"missing CI", func(s *Snapshot) { s.AvailableChecks = s.AvailableChecks[1:] }, "has not been observed"},
		{"missing CodeQL", func(s *Snapshot) { s.AvailableChecks = s.AvailableChecks[:3] }, "Analyze (go)"},
		{"renamed check", func(s *Snapshot) { s.AvailableChecks[0].Context = "test-linux" }, "has not been observed"},
		{"wrong app", func(s *Snapshot) { s.AvailableChecks[0].IntegrationID = 1 }, "app identity drift"},
		{"ambiguous app", func(s *Snapshot) {
			s.AvailableChecks = append(s.AvailableChecks, ObservedCheck{Context: s.AvailableChecks[0].Context, IntegrationID: 1})
		}, "ambiguous"},
		{"CodeQL absent", func(s *Snapshot) { s.Workflows = s.Workflows[:1] }, "CodeQL workflow"},
		{"CodeQL inactive", func(s *Snapshot) { s.Workflows[1].State = "disabled_manually" }, "CodeQL workflow"},
		{"disabled", func(s *Snapshot) { s.Rulesets[0].Enforcement = "disabled" }, "not active"},
		{"evaluate", func(s *Snapshot) { s.Rulesets[0].Enforcement = "evaluate" }, "not active"},
		{"bypass", func(s *Snapshot) {
			id := int64(5)
			s.Rulesets[0].BypassActors = append(s.Rulesets[0].BypassActors, Actor{ActorID: &id, ActorType: "RepositoryRole", BypassMode: "always"})
		}, "bypass"},
		{"loose", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "required_status_checks", "strict_required_status_checks_policy", false)
		}, "status-check policy drift"},
		{"approval", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "pull_request", "required_approving_review_count", float64(1))
		}, "review gates drift"},
		{"merge method widened", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "pull_request", "allowed_merge_methods", []any{"merge", "squash"})
		}, "allows merge methods"},
		{"dismissal restricted", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "pull_request", "dismissal_restriction", map[string]any{"enabled": true, "allowed_actors": []any{}})
		}, "restricts who may dismiss"},
		{"required reviewers", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "pull_request", "required_reviewers", []any{map[string]any{"file_patterns": []any{"**"}}})
		}, "specific reviewer set"},
		{"check dropped", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "required_status_checks", "required_status_checks", []any{
				map[string]any{"context": "test (ubuntu-latest)", "integration_id": float64(15368)},
			})
		}, "requires 1 checks"},
		{"check app swapped", func(s *Snapshot) {
			mutateRuleParameter(t, &s.Rulesets[0], "required_status_checks", "required_status_checks", []any{
				map[string]any{"context": "test (ubuntu-latest)", "integration_id": float64(15368)},
				map[string]any{"context": "test (macos-latest)", "integration_id": float64(15368)},
				map[string]any{"context": "govulncheck", "integration_id": float64(15368)},
				map[string]any{"context": "Analyze (go)", "integration_id": float64(99)},
			})
		}, "app identity drift"},
		{"auto merge", func(s *Snapshot) { s.Repository.AllowAutoMerge = false }, "auto-merge"},
		{"missing signature rule", func(s *Snapshot) { s.EffectiveRules = s.EffectiveRules[:2] }, "required_signatures"},
		{"duplicate ruleset", func(s *Snapshot) { s.Rulesets = append(s.Rulesets, s.Rulesets[0]) }, "exactly one"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := loadTestSnapshot(t, "positive.json")
			tc.mutate(&s)
			err := VerifySnapshot(repositoryContract(t), s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want %q", err, tc.want)
			}
		})
	}
}

func TestContractRejectsSemanticWeakening(t *testing.T) {
	t.Parallel()
	tests := []func(*Contract){
		func(c *Contract) { c.RequiredChecks = c.RequiredChecks[:3] }, func(c *Contract) { c.RequiredChecks[1].Context = c.RequiredChecks[0].Context },
		func(c *Contract) { c.RequiredChecks[0].IntegrationID = 0 }, func(c *Contract) { c.Policy.Enforcement = "disabled" }, func(c *Contract) { c.Policy.Enforcement = "evaluate" },
		func(c *Contract) {
			c.Policy.BypassActors = []Actor{{ActorType: "RepositoryRole", BypassMode: "always"}}
		}, func(c *Contract) { c.Policy.Strict = false },
		func(c *Contract) { c.Policy.RequirePullRequest = false }, func(c *Contract) { c.Policy.RequiredApprovals = 1 }, func(c *Contract) { c.Policy.RequireReviewThreadResolution = true },
		func(c *Contract) { c.Policy.RequireMergeQueue = true }, func(c *Contract) { c.Policy.RequiredDeployments = []string{"production"} }, func(c *Contract) { c.Repository.AllowAutoMerge = false },
		func(c *Contract) { c.RequiredEffectiveRules = c.RequiredEffectiveRules[:2] },
		func(c *Contract) { c.Policy.AllowedMergeMethods = []string{"merge", "squash", "rebase"} },
		func(c *Contract) { c.Policy.AllowedMergeMethods = []string{"merge", "squash"} },
		func(c *Contract) { c.Policy.AllowedMergeMethods = []string{"squash"} },
		func(c *Contract) { c.Policy.AllowedMergeMethods = nil },
	}
	for i, mutate := range tests {
		i, mutate := i, mutate
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			t.Parallel()
			c := repositoryContract(t)
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("weakened contract accepted")
			}
		})
	}
}

func TestWorkflowRejectsTriggerPathAndJobGaps(t *testing.T) {
	t.Parallel()
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"missing PR", func(s string) string { return strings.Replace(s, "  pull_request:\n", "", 1) }, "every pull_request"},
		{"path filter", func(s string) string {
			return strings.Replace(s, "  pull_request:\n", "  pull_request:\n    paths: ['docs/**']\n", 1)
		}, "path filters"},
		{"missing push", func(s string) string { return strings.Replace(s, "  push:\n    branches: [main]\n", "", 1) }, "every push to main"},
		{"missing job", func(s string) string { return strings.Replace(s, "  govulncheck:\n", "  scanner:\n", 1) }, "govulncheck"},
		{"renamed job", func(s string) string {
			return strings.Replace(s, "  govulncheck:\n", "  govulncheck:\n    name: security\n", 1)
		}, "stable check name"},
		{"matrix gap", func(s string) string {
			return strings.Replace(s, "os: [ubuntu-latest, macos-latest]", "os: [ubuntu-latest]", 1)
		}, "exact Ubuntu and macOS"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyCIWorkflow(repositoryContract(t), []byte(tc.edit(string(workflow))))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want %q", err, tc.want)
			}
		})
	}
}

func FuzzGovernanceContractDecode(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("..", "..", "governance", "main-v1alpha1.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Contract
		if decodeStrict(data, &c) == nil {
			_ = c.Validate()
		}
	})
}

func repositoryContract(t *testing.T) Contract {
	t.Helper()
	c, err := Load(filepath.Join("..", "..", "governance", "main-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func loadTestSnapshot(t *testing.T, name string) Snapshot {
	t.Helper()
	s, err := LoadSnapshot(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func mutateRuleParameter(t *testing.T, ruleset *ObservedRuleset, ruleType, key string, value any) {
	t.Helper()
	for i := range ruleset.Rules {
		if ruleset.Rules[i].Type != ruleType {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal(ruleset.Rules[i].Parameters, &p); err != nil {
			t.Fatal(err)
		}
		p[key] = value
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		ruleset.Rules[i].Parameters = data
		return
	}
	t.Fatalf("rule %q not found", ruleType)
}
