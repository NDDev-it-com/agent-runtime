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
	for _, mutation := range []string{"", "wrong-app", "rerun", "late", "missing"} {
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
						if mutation == "wrong-app" && index == 0 {
							check.App.ID++
						}
						if mutation == "late" && index == 0 {
							check.CompletedAt = merged.Add(time.Minute)
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
			_, err := verifyChecks(context.Background(), githubClient{base: server.URL, repository: contract.Repository, token: "test", http: server.Client()}, contract, head, merged)
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
