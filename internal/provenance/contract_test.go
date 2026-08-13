// SPDX-License-Identifier: AGPL-3.0-only

package provenance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func TestCanonicalContract(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if contract.TrustUpdatePolicy != "reviewed-contract-change" || len(contract.RequiredChecks) != 4 {
		t.Fatalf("canonical contract drift: %#v", contract)
	}
}

func TestRepositorySurfacesUseCanonicalProvenanceVerifier(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	for _, path := range []string{filepath.Join(root, ".github", "workflows", "ci.yml"), filepath.Join(root, ".github", "workflows", "release.yml"), filepath.Join(root, "docs", "releasing.md")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), IntegrationCommand) {
			t.Errorf("%s omits canonical integration verifier", path)
		}
		for _, forbidden := range []string{"git verify-commit", "gpg --verify", "GIT_CONFIG_GLOBAL"} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("%s contains ambient provenance fork %q", path, forbidden)
			}
		}
	}
}

func TestProviderTrustAnchorIsPinnedPublicAndActive(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", contract.IntegrationOpenPGPKey))
	if err != nil {
		t.Fatal(err)
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil || len(entities) != 1 {
		t.Fatalf("provider trust: entities=%d err=%v", len(entities), err)
	}
	entity := entities[0]
	if entity.PrivateKey != nil || entity.Revoked(time.Now()) {
		t.Fatal("provider trust contains private or revoked key material")
	}
	if strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)) != contract.IntegrationOpenPGPFingerprint {
		t.Fatal("provider fingerprint drift")
	}
}

func TestExactHeadChecksFailClosed(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 40)
	merged := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	for _, mutation := range []string{"", "wrong-app", "missing-suite", "rerun", "late", "missing"} {
		mutation := mutation
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.Contains(r.URL.Path, "check-runs") {
					runs := make([]checkRun, 0, len(contract.RequiredChecks))
					for index, required := range contract.RequiredChecks {
						if mutation == "missing" && index == 0 {
							continue
						}
						check := checkRun{ID: int64(index + 1), Name: required.Context, HeadSHA: head, Status: "completed", Conclusion: "success", DetailsURL: "https://github.com/NDDev-it-com/agent-runtime/actions/runs/" + string(rune('1'+index)), CompletedAt: merged.Add(-time.Minute)}
						check.App.ID = required.AppID
						check.App.NodeID = required.AppNodeID
						check.App.Slug = required.AppSlug
						check.CheckSuite.ID = int64(100 + index)
						if mutation == "wrong-app" && index == 0 {
							check.App.ID++
						}
						if mutation == "late" && index == 0 {
							check.CompletedAt = merged.Add(time.Minute)
						}
						if mutation == "missing-suite" && index == 0 {
							check.CheckSuite.ID = 0
						}
						runs = append(runs, check)
					}
					_ = json.NewEncoder(w).Encode(checksResponse{TotalCount: len(runs), CheckRuns: runs})
					return
				}
				var id int
				_, _ = fmt.Sscanf(filepath.Base(r.URL.Path), "%d", &id)
				required := contract.RequiredChecks[id-1]
				attempt := 1
				if mutation == "rerun" && id == 1 {
					attempt = 2
				}
				_ = json.NewEncoder(w).Encode(workflowRun{ID: int64(id), RunAttempt: attempt, Event: required.Event, HeadSHA: head, Status: "completed", Conclusion: "success", WorkflowID: required.WorkflowID, UpdatedAt: merged.Add(-time.Second)})
			}))
			defer server.Close()
			_, _, err := verifyChecks(context.Background(), githubClient{base: server.URL, repository: contract.Repository, token: "test", http: server.Client()}, contract, head, merged)
			if mutation == "" && err != nil {
				t.Fatal(err)
			}
			if mutation != "" && err == nil {
				t.Fatalf("mutation %q accepted", mutation)
			}
		})
	}
}

func TestContractFailsClosed(t *testing.T) {
	t.Parallel()
	canonical, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Contract){
		"revoked":      func(candidate *Contract) { candidate.IntegrationOpenPGPStatus = "revoked" },
		"wrong digest": func(candidate *Contract) { candidate.IntegrationOpenPGPSHA256 = strings.Repeat("0", 64) },
		"broad policy": func(candidate *Contract) { candidate.TrustUpdatePolicy = "automatic-provider-trust" },
		"missing check": func(candidate *Contract) {
			index := requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")
			candidate.RequiredChecks = append(candidate.RequiredChecks[:index:index], candidate.RequiredChecks[index+1:]...)
		},
		"wrong app": func(candidate *Contract) {
			candidate.RequiredChecks[requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")].AppID++
		},
		"wrong app node": func(candidate *Contract) {
			candidate.RequiredChecks[requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")].AppNodeID = "substituted"
		},
		"wrong app slug": func(candidate *Contract) {
			candidate.RequiredChecks[requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")].AppSlug = "substituted"
		},
		"wrong workflow": func(candidate *Contract) {
			candidate.RequiredChecks[requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")].WorkflowID++
		},
		"wrong event": func(candidate *Contract) {
			candidate.RequiredChecks[requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")].Event = "push"
		},
		"wrong context": func(candidate *Contract) {
			candidate.RequiredChecks[requiredCheckIndex(t, candidate.RequiredChecks, "govulncheck")].Context = "security"
		},
	}
	for name, mutate := range cases {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := canonical
			candidate.RequiredChecks = append([]RequiredCheck(nil), canonical.RequiredChecks...)
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("negative fixture did not change the canonical contract")
			}
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(raw, []byte(`"merge_method"`), []byte(`"unknown":true,"merge_method"`), 1)
	if bytes.Equal(unknown, raw) {
		t.Fatal("unknown-field fixture did not mutate canonical JSON")
	}
	path := filepath.Join(t.TempDir(), "contract.json")
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestCapturedPullIdentityAndOneFieldMutations(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	request := VerifyRequest{CommitSHA: strings.Repeat("c", 40), PullRequest: 11}
	canonical := pullResponse{
		ID: 4272531825, NodeID: "PR_kwDOT22ecs7-qalx", Number: 11, State: "closed", Merged: true,
		MergeCommitSHA: request.CommitSHA, MergedAt: time.Date(2026, 8, 13, 15, 35, 29, 0, time.UTC),
		MergedBy: apiActor{Login: contract.OwnerLogin, ID: contract.OwnerDatabaseID, NodeID: contract.OwnerNodeID, Type: "User"},
		Base:     apiRef{Ref: "main", SHA: strings.Repeat("a", 40), Repository: apiRepository{ID: contract.RepositoryDatabaseID, NodeID: contract.RepositoryNodeID}},
		Head:     apiRef{Ref: "fix/provenance-graph", SHA: strings.Repeat("b", 40), Repository: apiRepository{ID: contract.RepositoryDatabaseID, NodeID: contract.RepositoryNodeID}},
		Commits:  1,
	}
	if err := validatePullIdentity(contract, request, canonical); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*pullResponse){
		"pr id":          func(value *pullResponse) { value.ID = 0 },
		"pr node":        func(value *pullResponse) { value.NodeID = "" },
		"number":         func(value *pullResponse) { value.Number++ },
		"state":          func(value *pullResponse) { value.State = "open" },
		"merged":         func(value *pullResponse) { value.Merged = false },
		"merged at":      func(value *pullResponse) { value.MergedAt = time.Time{} },
		"merger login":   func(value *pullResponse) { value.MergedBy.Login = "substituted" },
		"merger id":      func(value *pullResponse) { value.MergedBy.ID++ },
		"merger node":    func(value *pullResponse) { value.MergedBy.NodeID = "substituted" },
		"merger type":    func(value *pullResponse) { value.MergedBy.Type = "Bot" },
		"base ref":       func(value *pullResponse) { value.Base.Ref = "other" },
		"base sha":       func(value *pullResponse) { value.Base.SHA = "invalid" },
		"base repo id":   func(value *pullResponse) { value.Base.Repository.ID++ },
		"base repo node": func(value *pullResponse) { value.Base.Repository.NodeID = "substituted" },
		"head ref":       func(value *pullResponse) { value.Head.Ref = "" },
		"head sha":       func(value *pullResponse) { value.Head.SHA = "invalid" },
		"head repo id":   func(value *pullResponse) { value.Head.Repository.ID++ },
		"head repo node": func(value *pullResponse) { value.Head.Repository.NodeID = "substituted" },
		"commit bound":   func(value *pullResponse) { value.Commits = 0 },
	}
	for _, stateful := range []string{"", "invalid", strings.Repeat("f", 40)} {
		candidate := canonical
		candidate.MergeCommitSHA = stateful
		if err := validatePullIdentity(contract, request, candidate); err != nil {
			t.Fatalf("stateful REST merge_commit_sha %q became attribution authority: %v", stateful, err)
		}
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := canonical
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("negative fixture did not change the candidate")
			}
			if err := validatePullIdentity(contract, request, candidate); err == nil {
				t.Fatal("mutated identity was accepted")
			}
		})
	}
}

func TestSanitizedLiveCapturesMatchTypedIdentity(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pr11-sanitized.json", "pr14-sanitized.json"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				License     string            `json:"x_license"`
				Pull        pullResponse      `json:"pull_request"`
				Integration commitResponse    `json:"integration_commit"`
				Graph       graphPullResponse `json:"graphql_relation"`
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&fixture); err != nil {
				t.Fatal(err)
			}
			request := VerifyRequest{CommitSHA: fixture.Integration.SHA, PullRequest: fixture.Pull.Number}
			if fixture.License != "AGPL-3.0-only" {
				t.Fatal("captured fixture license drift")
			}
			if err := validatePullIdentity(contract, request, fixture.Pull); err != nil {
				t.Fatal(err)
			}
			if err := validateGraphPullIdentity(contract, request, fixture.Pull, fixture.Graph); err != nil {
				t.Fatal(err)
			}
			if err := validateIntegrationIdentity(contract, fixture.Pull, fixture.Graph, fixture.Integration); err != nil {
				t.Fatal(err)
			}
			for _, stateful := range []string{"", "invalid", strings.Repeat("f", 40)} {
				candidate := fixture.Pull
				candidate.MergeCommitSHA = stateful
				if err := validatePullIdentity(contract, request, candidate); err != nil {
					t.Fatalf("stateful REST merge SHA changed immutable attribution: %v", err)
				}
				if err := validateIntegrationIdentity(contract, candidate, fixture.Graph, fixture.Integration); err != nil {
					t.Fatalf("stateful REST merge SHA changed graph attribution: %v", err)
				}
			}
		})
	}
}

func TestIntegrationCommitIdentitySeparatesAuthorMergerAndSigner(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	integrationSHA := strings.Repeat("c", 40)
	pull := pullResponse{MergeCommitSHA: strings.Repeat("e", 40), Base: apiRef{SHA: strings.Repeat("a", 40)}, Head: apiRef{SHA: strings.Repeat("b", 40)}}
	canonical := commitResponse{
		SHA:       integrationSHA,
		Author:    apiActor{Login: contract.OwnerLogin, ID: contract.OwnerDatabaseID, NodeID: contract.OwnerNodeID, Type: "User"},
		Committer: apiActor{Login: contract.IntegrationSignerLogin, ID: contract.IntegrationSignerDatabaseID, NodeID: contract.IntegrationSignerNodeID, Type: "User"},
		Parents:   []apiRef{{SHA: pull.Base.SHA}, {SHA: pull.Head.SHA}},
		Commit:    commitBlock{Tree: apiRef{SHA: strings.Repeat("d", 40)}},
	}
	graph := canonicalGraphPull(contract, pull, canonical)
	if err := validateIntegrationIdentity(contract, pull, graph, canonical); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*commitResponse){
		"sha":          func(value *commitResponse) { value.SHA = strings.Repeat("e", 40) },
		"parent base":  func(value *commitResponse) { value.Parents[0].SHA = strings.Repeat("e", 40) },
		"parent head":  func(value *commitResponse) { value.Parents[1].SHA = strings.Repeat("e", 40) },
		"tree":         func(value *commitResponse) { value.Commit.Tree.SHA = "invalid" },
		"signer login": func(value *commitResponse) { value.Committer.Login = contract.OwnerLogin },
		"signer id":    func(value *commitResponse) { value.Committer.ID++ },
		"signer node":  func(value *commitResponse) { value.Committer.NodeID = "substituted" },
		"signer type":  func(value *commitResponse) { value.Committer.Type = "Bot" },
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := canonical
			candidate.Parents = append([]apiRef(nil), canonical.Parents...)
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("negative fixture did not change the candidate")
			}
			if err := validateIntegrationIdentity(contract, pull, graph, candidate); err == nil {
				t.Fatal("mutated integration identity was accepted")
			}
		})
	}
	// The author is deliberately not the integration signer trust decision.
	candidate := canonical
	candidate.Author = apiActor{Login: "untrusted-display-name"}
	if err := validateIntegrationIdentity(contract, pull, graph, candidate); err != nil {
		t.Fatalf("author string incorrectly became integration trust: %v", err)
	}
}

func canonicalGraphPull(contract Contract, pull pullResponse, commit commitResponse) graphPullResponse {
	var graph graphPullResponse
	graph.Data.Repository.ID = contract.RepositoryNodeID
	graph.Data.Repository.DatabaseID = contract.RepositoryDatabaseID
	graph.Data.Repository.Pull.ID = pull.NodeID
	graph.Data.Repository.Pull.DatabaseID = pull.ID
	graph.Data.Repository.Pull.Number = pull.Number
	graph.Data.Repository.Pull.State = "MERGED"
	graph.Data.Repository.Pull.Merged = true
	graph.Data.Repository.Pull.MergedAt = pull.MergedAt
	graph.Data.Repository.Pull.BaseRef = pull.Base.Ref
	graph.Data.Repository.Pull.BaseOID = pull.Base.SHA
	graph.Data.Repository.Pull.HeadRef = pull.Head.Ref
	graph.Data.Repository.Pull.HeadOID = pull.Head.SHA
	graph.Data.Repository.Pull.MergedBy.Login = contract.OwnerLogin
	graph.Data.Repository.Pull.MergedBy.ID = contract.OwnerNodeID
	graph.Data.Repository.Pull.MergedBy.DatabaseID = contract.OwnerDatabaseID
	graph.Data.Repository.Pull.MergeCommit.OID = commit.SHA
	graph.Data.Repository.Pull.MergeCommit.Tree.OID = commit.Commit.Tree.SHA
	graph.Data.Repository.Pull.MergeCommit.Parents.Nodes = make([]struct {
		OID string `json:"oid"`
	}, len(commit.Parents))
	for index := range commit.Parents {
		graph.Data.Repository.Pull.MergeCommit.Parents.Nodes[index].OID = commit.Parents[index].SHA
	}
	return graph
}

func TestGraphPullRelationFailsClosedForOneFieldMutations(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	request := VerifyRequest{CommitSHA: strings.Repeat("c", 40), PullRequest: 13}
	pull := pullResponse{
		ID: 42, NodeID: "PR_node", Number: 13, State: "closed", Merged: true, MergedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		MergeCommitSHA: strings.Repeat("e", 40),
		MergedBy:       apiActor{Login: contract.OwnerLogin, ID: contract.OwnerDatabaseID, NodeID: contract.OwnerNodeID, Type: "User"},
		Base:           apiRef{Ref: "main", SHA: strings.Repeat("a", 40), Repository: apiRepository{ID: contract.RepositoryDatabaseID, NodeID: contract.RepositoryNodeID}},
		Head:           apiRef{Ref: "feature", SHA: strings.Repeat("b", 40), Repository: apiRepository{ID: contract.RepositoryDatabaseID, NodeID: contract.RepositoryNodeID}}, Commits: 1,
	}
	commit := commitResponse{SHA: request.CommitSHA, Parents: []apiRef{{SHA: pull.Base.SHA}, {SHA: pull.Head.SHA}}, Commit: commitBlock{Tree: apiRef{SHA: strings.Repeat("d", 40)}}}
	canonical := canonicalGraphPull(contract, pull, commit)
	if err := validateGraphPullIdentity(contract, request, pull, canonical); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*graphPullResponse){
		"graphql errors": func(value *graphPullResponse) {
			value.Errors = append(value.Errors, struct {
				Message string `json:"message"`
			}{Message: "failure"})
		},
		"repository node": func(value *graphPullResponse) { value.Data.Repository.ID = "wrong" },
		"repository id":   func(value *graphPullResponse) { value.Data.Repository.DatabaseID++ },
		"pr node":         func(value *graphPullResponse) { value.Data.Repository.Pull.ID = "wrong" },
		"pr id":           func(value *graphPullResponse) { value.Data.Repository.Pull.DatabaseID++ },
		"pr number":       func(value *graphPullResponse) { value.Data.Repository.Pull.Number++ },
		"state":           func(value *graphPullResponse) { value.Data.Repository.Pull.State = "OPEN" },
		"merged":          func(value *graphPullResponse) { value.Data.Repository.Pull.Merged = false },
		"merged at":       func(value *graphPullResponse) { value.Data.Repository.Pull.MergedAt = time.Time{} },
		"merger login":    func(value *graphPullResponse) { value.Data.Repository.Pull.MergedBy.Login = "wrong" },
		"merger node":     func(value *graphPullResponse) { value.Data.Repository.Pull.MergedBy.ID = "wrong" },
		"merger id":       func(value *graphPullResponse) { value.Data.Repository.Pull.MergedBy.DatabaseID++ },
		"base ref":        func(value *graphPullResponse) { value.Data.Repository.Pull.BaseRef = "wrong" },
		"base oid":        func(value *graphPullResponse) { value.Data.Repository.Pull.BaseOID = strings.Repeat("f", 40) },
		"head ref":        func(value *graphPullResponse) { value.Data.Repository.Pull.HeadRef = "wrong" },
		"head oid":        func(value *graphPullResponse) { value.Data.Repository.Pull.HeadOID = strings.Repeat("f", 40) },
		"merge oid":       func(value *graphPullResponse) { value.Data.Repository.Pull.MergeCommit.OID = strings.Repeat("f", 40) },
		"tree":            func(value *graphPullResponse) { value.Data.Repository.Pull.MergeCommit.Tree.OID = "invalid" },
		"parent base": func(value *graphPullResponse) {
			value.Data.Repository.Pull.MergeCommit.Parents.Nodes[0].OID = strings.Repeat("f", 40)
		},
		"parent head": func(value *graphPullResponse) {
			value.Data.Repository.Pull.MergeCommit.Parents.Nodes[1].OID = strings.Repeat("f", 40)
		},
		"squash/rebase": func(value *graphPullResponse) {
			value.Data.Repository.Pull.MergeCommit.Parents.Nodes = value.Data.Repository.Pull.MergeCommit.Parents.Nodes[:1]
		},
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := canonical
			candidate.Data.Repository.Pull.MergeCommit.Parents.Nodes = append([]struct {
				OID string `json:"oid"`
			}(nil), canonical.Data.Repository.Pull.MergeCommit.Parents.Nodes...)
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("negative fixture did not change the candidate")
			}
			if err := validateGraphPullIdentity(contract, request, pull, candidate); err == nil {
				t.Fatal("mutated integration relation accepted")
			}
		})
	}
}

func TestIntegrationCandidateSelectionIsUniqueAndGraphBound(t *testing.T) {
	t.Parallel()
	contract, err := Load(filepath.Join("..", "..", "provenance", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	request := VerifyRequest{Contract: contract, CommitSHA: strings.Repeat("c", 40)}
	for _, test := range []struct {
		name       string
		candidates []int
		wrongGraph bool
		wantOK     bool
	}{
		{name: "stateful REST test merge is reconciled by exact graph", candidates: []int{13}, wantOK: true},
		{name: "missing", candidates: nil},
		{name: "ambiguous", candidates: []int{13, 14}},
		{name: "wrong PR graph", candidates: []int{13}, wrongGraph: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/commits/") && strings.HasSuffix(r.URL.Path, "/pulls") {
					items := make([]commitPull, len(test.candidates))
					for index, number := range test.candidates {
						items[index].Number = number
					}
					_ = json.NewEncoder(w).Encode(items)
					return
				}
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pulls/") {
					number := 0
					_, _ = fmt.Sscanf(filepath.Base(r.URL.Path), "%d", &number)
					_ = json.NewEncoder(w).Encode(candidatePullFixture(contract, number))
					return
				}
				if r.Method == http.MethodPost && r.URL.Path == "/graphql" {
					var input struct {
						Variables struct {
							Number int `json:"number"`
						} `json:"variables"`
					}
					if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
						t.Error(err)
					}
					pull := candidatePullFixture(contract, input.Variables.Number)
					commit := commitResponse{SHA: request.CommitSHA, Parents: []apiRef{{SHA: pull.Base.SHA}, {SHA: pull.Head.SHA}}, Commit: commitBlock{Tree: apiRef{SHA: strings.Repeat("d", 40)}}}
					graph := canonicalGraphPull(contract, pull, commit)
					if test.wrongGraph {
						graph.Data.Repository.Pull.Number++
					}
					_ = json.NewEncoder(w).Encode(graph)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			client := githubClient{base: server.URL, repository: contract.Repository, token: "test", http: server.Client()}
			pull, graph, err := selectIntegrationPull(context.Background(), client, request)
			if test.wantOK {
				if err != nil {
					t.Fatal(err)
				}
				if pull.Number != 13 || graph.Data.Repository.Pull.MergeCommit.OID != request.CommitSHA || pull.MergeCommitSHA != strings.Repeat("e", 40) {
					t.Fatal("selected relation did not preserve stateful REST evidence beside the exact graph")
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid candidate set accepted: pull=%#v", pull)
			}
		})
	}
}

func candidatePullFixture(contract Contract, number int) pullResponse {
	return pullResponse{
		ID: int64(1000 + number), NodeID: fmt.Sprintf("PR_%d", number), Number: number, State: "closed", Merged: true,
		MergeCommitSHA: strings.Repeat("e", 40), MergedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		MergedBy: apiActor{Login: contract.OwnerLogin, ID: contract.OwnerDatabaseID, NodeID: contract.OwnerNodeID, Type: "User"},
		Base:     apiRef{Ref: "main", SHA: strings.Repeat("a", 40), Repository: apiRepository{ID: contract.RepositoryDatabaseID, NodeID: contract.RepositoryNodeID}},
		Head:     apiRef{Ref: fmt.Sprintf("feature-%d", number), SHA: strings.Repeat("b", 40), Repository: apiRepository{ID: contract.RepositoryDatabaseID, NodeID: contract.RepositoryNodeID}},
		Commits:  1,
	}
}

func requiredCheckIndex(t *testing.T, checks []RequiredCheck, context string) int {
	t.Helper()
	for index := range checks {
		if checks[index].Context == context {
			return index
		}
	}
	t.Fatalf("required check fixture %q is absent", context)
	return -1
}

func TestSplitCommitSignature(t *testing.T) {
	t.Parallel()
	raw := []byte("tree 0123456789012345678901234567890123456789\ngpgsig -----BEGIN PGP SIGNATURE-----\n abc\n -----END PGP SIGNATURE-----\n\nmessage\n")
	payload, signature, err := splitCommitSignature(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "gpgsig") || !strings.Contains(string(payload), "message") {
		t.Fatalf("payload=%q", payload)
	}
	if string(signature) != "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n" {
		t.Fatalf("signature=%q", signature)
	}
	for _, invalid := range [][]byte{nil, []byte("tree x\n"), append(raw, raw...)} {
		if _, _, err := splitCommitSignature(invalid); err == nil {
			t.Fatalf("invalid commit accepted: %q", invalid)
		}
	}
}

func TestSplitCommitSignatureNormalizesGitHeaderContinuation(t *testing.T) {
	t.Parallel()
	raw := []byte("tree 0123456789012345678901234567890123456789\ngpgsig -----BEGIN PGP SIGNATURE-----\n abc\n -----END PGP SIGNATURE-----\n \n\nmessage\n")
	payload, signature, err := splitCommitSignature(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(signature) != "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n" {
		t.Fatalf("signature=%q", signature)
	}
	if string(payload) != "tree 0123456789012345678901234567890123456789\n\nmessage\n" {
		t.Fatalf("payload=%q", payload)
	}
}

func TestLocalCommitIdentityMatchesRESTExactly(t *testing.T) {
	t.Parallel()
	payload := []byte("tree " + strings.Repeat("d", 40) + "\nparent " + strings.Repeat("a", 40) + "\nparent " + strings.Repeat("b", 40) + "\nauthor Danil Silantyev <danilsilantyevwork@gmail.com> 1786642425 +0500\ncommitter GitHub <noreply@github.com> 1786642425 +0500\n\nmessage\n")
	stamp := time.Unix(1786642425, 0).UTC()
	canonical := commitResponse{Parents: []apiRef{{SHA: strings.Repeat("a", 40)}, {SHA: strings.Repeat("b", 40)}}, Commit: commitBlock{Tree: apiRef{SHA: strings.Repeat("d", 40)}, Author: apiGitIdentity{Name: "Danil Silantyev", Email: "danilsilantyevwork@gmail.com", Date: stamp}, Committer: apiGitIdentity{Name: "GitHub", Email: "noreply@github.com", Date: stamp}}}
	if err := validateLocalCommitIdentity(payload, canonical); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*commitResponse){
		"tree":      func(v *commitResponse) { v.Commit.Tree.SHA = strings.Repeat("e", 40) },
		"parent":    func(v *commitResponse) { v.Parents[1].SHA = strings.Repeat("e", 40) },
		"author":    func(v *commitResponse) { v.Commit.Author.Email = "wrong@example.com" },
		"committer": func(v *commitResponse) { v.Commit.Committer.Name = "Wrong" },
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := canonical
			candidate.Parents = append([]apiRef(nil), canonical.Parents...)
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("mutation did not change candidate")
			}
			if validateLocalCommitIdentity(payload, candidate) == nil {
				t.Fatal("identity substitution accepted")
			}
		})
	}
}

func TestProviderVerificationMetadataFailsClosed(t *testing.T) {
	t.Parallel()
	merged := time.Date(2026, 8, 13, 17, 33, 45, 0, time.UTC)
	canonical := apiVerification{Verified: true, Reason: "valid", VerifiedAt: merged.Add(5 * time.Second), Payload: "payload", Signature: "signature"}
	for name, mutate := range map[string]func(*apiVerification){
		"unverified":          func(v *apiVerification) { v.Verified = false },
		"wrong reason":        func(v *apiVerification) { v.Reason = "unknown_key" },
		"missing verified at": func(v *apiVerification) { v.VerifiedAt = time.Time{} },
		"stale verified at":   func(v *apiVerification) { v.VerifiedAt = merged.Add(-time.Second) },
		"missing payload":     func(v *apiVerification) { v.Payload = "" },
		"missing signature":   func(v *apiVerification) { v.Signature = "" },
		"substituted payload": func(v *apiVerification) { v.Payload = "different" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := canonical
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("mutation did not change candidate")
			}
			if verifyIntegrationSignatureEvidence("", Contract{}, candidate, []byte("payload"), []byte("signature"), merged) == nil {
				t.Fatal("invalid provider verification evidence accepted")
			}
		})
	}
}

func TestPR15SanitizedSignatureCapture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "pr15-signature-sanitized.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		License      string         `json:"x_license"`
		SHA          string         `json:"sha"`
		Tree         string         `json:"tree"`
		Parents      []string       `json:"parents"`
		Author       apiGitIdentity `json:"author"`
		Committer    apiGitIdentity `json:"committer"`
		Verification struct {
			Verified             bool      `json:"verified"`
			Reason               string    `json:"reason"`
			VerifiedAt           time.Time `json:"verified_at"`
			PayloadBytes         int       `json:"payload_bytes"`
			PayloadSHA256        string    `json:"payload_sha256"`
			SignatureBytes       int       `json:"signature_bytes"`
			SignatureSHA256      string    `json:"signature_sha256"`
			LocalRawCommitBytes  int       `json:"local_raw_commit_bytes"`
			LocalRawCommitSHA256 string    `json:"local_raw_commit_sha256"`
		} `json:"verification"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.License != "AGPL-3.0-only" || !fullSHA.MatchString(fixture.SHA) || !fullSHA.MatchString(fixture.Tree) || len(fixture.Parents) != 2 || !fixture.Verification.Verified || fixture.Verification.Reason != "valid" || fixture.Verification.VerifiedAt.IsZero() || fixture.Verification.PayloadBytes != 398 || fixture.Verification.SignatureBytes != 801 || fixture.Verification.LocalRawCommitBytes != 1223 {
		t.Fatalf("sanitized PR15 signature capture drift: %#v", fixture)
	}
	for _, digest := range []string{fixture.Verification.PayloadSHA256, fixture.Verification.SignatureSHA256, fixture.Verification.LocalRawCommitSHA256} {
		if len(digest) != 64 {
			t.Fatal("captured digest is malformed")
		}
	}
}
