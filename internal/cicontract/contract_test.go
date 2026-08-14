// SPDX-License-Identifier: AGPL-3.0-only

package cicontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures below are the repository's own workflows, mutated. A synthetic
// fixture can drift into shapes GitHub would never run, which is how the
// previous suite came to assert against YAML that had no steps at all.
func canonicalCI(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func canonicalRelease(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func repositoryContract(t *testing.T) Contract {
	t.Helper()
	c, err := Load(filepath.Join("..", "..", "security-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// mutate applies one textual edit and fails if it changed nothing, so a test
// cannot silently pass by asserting against an unmodified workflow.
func mutate(t *testing.T, workflow, old, replacement string) string {
	t.Helper()
	out := strings.Replace(workflow, old, replacement, 1)
	if out == workflow {
		t.Fatalf("fixture did not change: %q not found", old)
	}
	return out
}

func TestRepositoryWorkflowMatchesContract(t *testing.T) {
	t.Parallel()
	if err := VerifyWorkflow(repositoryContract(t), []byte(canonicalCI(t))); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsToolchainDrift(t *testing.T) {
	t.Parallel()
	c := repositoryContract(t)
	workflow := canonicalCI(t)
	for name, test := range map[string]struct{ workflow, want string }{
		"scanner below upstream minimum": {
			mutate(t, workflow, "go-version: '1.26.6'", "go-version: '1.24.9'"),
			"below tool minimum",
		},
		"scanner not the patched security release": {
			mutate(t, workflow, "go-version: '1.26.6'", "go-version: '1.26.4'"),
			"patched security Go",
		},
		"compatibility lane drift": {
			mutate(t, workflow, "go-version: '1.25.x'", "go-version: '1.26.x'"),
			"compatibility Go",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := VerifyWorkflow(c, []byte(test.workflow))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestRejectsCompatibilityLaneBelowLinterMinimum(t *testing.T) {
	t.Parallel()
	c := repositoryContract(t)
	c.Staticcheck.MinimumGo = "1.26.0"
	err := VerifyWorkflow(c, []byte(canonicalCI(t)))
	if err == nil || !strings.Contains(err.Error(), "below staticcheck minimum") {
		t.Fatalf("error=%v", err)
	}
}

func TestRejectsMissingOrDuplicatedCanonicalFuzzGate(t *testing.T) {
	t.Parallel()
	c := repositoryContract(t)
	workflow := canonicalCI(t)
	for name, test := range map[string]string{
		"missing":   mutate(t, workflow, "run: go run ./cmd/check-fuzz", "run: go test ./..."),
		"duplicate": mutate(t, workflow, "      - run: go build ./cmd/agent-runtime", "      - run: go run ./cmd/check-fuzz\n      - run: go build ./cmd/agent-runtime"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyWorkflow(c, []byte(test)); err == nil || !strings.Contains(err.Error(), "fuzz verifier") {
				t.Errorf("error=%v", err)
			}
		})
	}
}

func TestRejectsUnpinnedOrMisplacedStaticAnalysis(t *testing.T) {
	t.Parallel()
	const pin = "honnef.co/go/tools/cmd/staticcheck@v0.7.0"
	workflow := canonicalCI(t)
	for name, test := range map[string]struct{ workflow, want string }{
		"absent from the test job": {
			mutate(t, workflow, "          go run "+pin+" ./...\n", ""),
			"exactly twice",
		},
		"floating version": {
			mutate(t, workflow, "go run "+pin+" ./...", "go run honnef.co/go/tools/cmd/staticcheck@latest ./..."),
			"exactly twice",
		},
		"invoked from another lane": {
			mutate(t, workflow, "      - run: go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...", "      - run: go run "+pin+" ./...\n      - run: go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./..."),
			"only from the test job",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := VerifyWorkflow(repositoryContract(t), []byte(test.workflow))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestReleaseReproductionCommandOwnsOnlyParent(t *testing.T) {
	t.Parallel()
	canonical := canonicalCI(t)
	for name, workflow := range map[string]string{
		"missing second build": mutate(t, canonical, `--out "$second" --result "$second_result"`, `--out "$first" --result "$first_result"`),
		"precreated first":     mutate(t, canonical, `          diff -rq "$first" "$second"`, "          mkdir \"$first\"\n          diff -rq \"$first\" \"$second\""),
		"same destination":     mutate(t, canonical, `second="$parent/second"`, `second="$parent/first"`),
		"missing comparison":   mutate(t, canonical, `diff -rq "$first" "$second"`, "true"),
		"hardcoded contract":   mutate(t, canonical, `--build --commit HEAD --out "$first"`, `--contract release/contract.json --build --commit HEAD --out "$first"`),
		"missing result check": mutate(t, canonical, `go run ./cmd/check-release-contract --out "$second" --verify-result "$second_result"`, `true`),
		"unquoted parent":      mutate(t, canonical, `first="$parent/first"`, `first=$parent/first`),
		"manual TMPDIR join":   mutate(t, canonical, `parent="$(mktemp -d)"`, `parent="$(mktemp -d "${TMPDIR}/agent-runtime.XXXXXX")"`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := VerifyWorkflow(repositoryContract(t), []byte(workflow)); err == nil {
				t.Error("reproduction drift accepted")
			}
		})
	}
}

func TestRejectsContractMissingAToolPin(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "security-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, damaged := range map[string]string{
		"no linter version": strings.Replace(string(data), `"version": "v0.7.0"`, `"version": ""`, 1),
		"no linter module":  strings.Replace(string(data), `"module": "honnef.co/go/tools/cmd/staticcheck"`, `"module": ""`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "security-tools.json")
			if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "staticcheck") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

// TestReleaseLaneTracksTheCompatibilityToolchain covers the lane that publishes.
// It is not the same file as the test lane, and until it was read here a bump to
// the module's go directive could leave the release job on a toolchain that
// cannot build the module at all — which is exactly how the v0.1.0 tag ended up
// with no release behind it.
func TestReleaseLaneTracksTheCompatibilityToolchain(t *testing.T) {
	t.Parallel()
	workflow := canonicalRelease(t)
	contract := repositoryContract(t)
	if err := VerifyRelease(contract, []byte(workflow)); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct{ workflow, want string }{
		"lane below the module go directive": {
			mutate(t, workflow, "go-version: '1.25.x'", "go-version: '1.24.x'"),
			"differs from compatibility Go",
		},
		"lane ahead of the compatibility declaration": {
			mutate(t, workflow, "go-version: '1.25.x'", "go-version: '1.26.x'"),
			"differs from compatibility Go",
		},
		"reads a setting the token cannot access": {
			mutate(t, workflow, "          if gh release view", "          test \"$(gh api \"repos/${GITHUB_REPOSITORY}/immutable-releases\" --jq '.enabled')\" = true\n          if gh release view"),
			"no admin access",
		},
		"no release job": {
			mutate(t, workflow, "\n  release:\n", "\n  publish:\n"),
			"has no job",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := VerifyRelease(contract, []byte(test.workflow))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}
