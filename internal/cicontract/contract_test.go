// SPDX-License-Identifier: AGPL-3.0-only

package cicontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NDDev-it-com/agent-runtime/internal/releasecontract"
)

func TestRepositoryWorkflowMatchesContract(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	c, err := Load(filepath.Join(root, "security-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkflow(c, workflow); err != nil {
		t.Fatal(err)
	}
}
func TestRejectsScannerToolchainBelowUpstreamMinimum(t *testing.T) {
	t.Parallel()
	c := testContract()
	err := VerifyWorkflow(c, []byte(testWorkflow("1.24.x")))
	if err == nil || !strings.Contains(err.Error(), "below tool minimum") {
		t.Fatalf("error=%v", err)
	}
}
func TestRejectsCompatibilityLaneDrift(t *testing.T) {
	t.Parallel()
	c := testContract()
	workflow := strings.Replace(testWorkflow("1.26.6"), "test:\n    go-version: '1.25.x'", "test:\n    go-version: '1.26.x'", 1)
	err := VerifyWorkflow(c, []byte(workflow))
	if err == nil || !strings.Contains(err.Error(), "compatibility Go") {
		t.Fatalf("error=%v", err)
	}
}
func TestRejectsUnpatchedSecurityLane(t *testing.T) {
	t.Parallel()
	c := testContract()
	err := VerifyWorkflow(c, []byte(testWorkflow("1.26.4")))
	if err == nil || !strings.Contains(err.Error(), "patched security Go") {
		t.Fatalf("error=%v", err)
	}
}
func TestRejectsMissingOrDuplicatedCanonicalFuzzGate(t *testing.T) {
	t.Parallel()
	c := testContract()
	canonical := "go run ./cmd/check-fuzz"
	for name, workflow := range map[string]string{
		"missing":   strings.Replace(testWorkflow("1.26.6"), canonical, "go test ./...", 1),
		"duplicate": testWorkflow("1.26.6") + canonical + "\n",
	} {
		if err := VerifyWorkflow(c, []byte(workflow)); err == nil || !strings.Contains(err.Error(), "fuzz verifier") {
			t.Errorf("%s error=%v", name, err)
		}
	}
}

func TestReleaseReproductionCommandOwnsOnlyParent(t *testing.T) {
	t.Parallel()
	canonical := testWorkflow("1.26.6")
	if err := VerifyWorkflow(testContract(), []byte(canonical)); err != nil {
		t.Fatal(err)
	}
	for name, workflow := range map[string]string{
		"missing second build": strings.Replace(canonical, `--out "$second"`, `--out "$first"`, 1),
		"precreated first":     strings.Replace(canonical, `diff -rq "$first" "$second"`, "mkdir \"$first\"\n    diff -rq \"$first\" \"$second\"", 1),
		"same destination":     strings.Replace(canonical, `second="$parent/second"`, `second="$parent/first"`, 1),
		"missing comparison":   strings.Replace(canonical, `diff -rq "$first" "$second"`, "true", 1),
		"hardcoded contract":   strings.Replace(canonical, `--build --commit HEAD`, `--contract release/contract.json --build --commit HEAD`, 1),
		"missing result check": strings.Replace(canonical, `--out "$second" --verify-result "$second_result"`, `true`, 1),
		"unquoted parent":      strings.Replace(canonical, `first="$parent/first"`, `first=$parent/first`, 1),
		"manual TMPDIR join":   strings.Replace(canonical, `parent="$(mktemp -d)"`, `parent="$(mktemp -d "${TMPDIR}/agent-runtime.XXXXXX")"`, 1),
	} {
		if workflow == canonical {
			switch name {
			case "missing second build":
				workflow = strings.Replace(canonical, "--out \"$second\"", "--out \"$first\"", 1)
			case "precreated first":
				workflow = strings.Replace(canonical, "diff -rq \"$first\" \"$second\"", "mkdir \"$first\"\n    diff -rq \"$first\" \"$second\"", 1)
			case "same destination":
				workflow = strings.Replace(canonical, "second=\"$parent/second\"", "second=\"$parent/first\"", 1)
			case "missing comparison":
				workflow = strings.Replace(canonical, "diff -rq \"$first\" \"$second\"", "true", 1)
			}
		}
		if workflow == canonical {
			t.Fatalf("%s negative fixture did not change the workflow", name)
		}
		if err := VerifyWorkflow(testContract(), []byte(workflow)); err == nil {
			t.Errorf("%s reproduction drift accepted", name)
		}
	}
}
func testContract() Contract {
	return Contract{SchemaVersion: "v1alpha1", License: releasecontract.CanonicalLicense, Govulncheck: Tool{Module: "golang.org/x/vuln/cmd/govulncheck", Version: "v1.7.0", MinimumGo: "1.25.0", UpstreamGoMod: "https://github.com/golang/vuln/blob/v1.7.0/go.mod"}, Staticcheck: Tool{Module: "honnef.co/go/tools/cmd/staticcheck", Version: "v0.7.0", MinimumGo: "1.25.0", UpstreamGoMod: "https://github.com/dominikh/go-tools/blob/v0.7.0/go.mod"}, SecurityGo: "1.26.6", CompatibilityGo: "1.25"}
}
func testWorkflow(scanner string) string {
	return "env:\n  GOTOOLCHAIN: local\njobs:\n  test:\n    go-version: '1.25.x'\n    lint_version: honnef.co/go/tools/cmd/staticcheck@v0.7.0\n    lint: honnef.co/go/tools/cmd/staticcheck@v0.7.0\n    run: go run ./cmd/check-fuzz\n    reproduce: |\n      parent=\"$(mktemp -d)\"\n      first=\"$parent/first\"\n      second=\"$parent/second\"\n      first_result=\"$parent/first-result.json\"\n      second_result=\"$parent/second-result.json\"\n      go run ./cmd/check-release-contract --build --commit HEAD --out \"$first\" --result \"$first_result\"\n      go run ./cmd/check-release-contract --build --commit HEAD --out \"$second\" --result \"$second_result\"\n      go run ./cmd/check-release-contract --out \"$first\" --verify-result \"$first_result\"\n      go run ./cmd/check-release-contract --out \"$second\" --verify-result \"$second_result\"\n      diff -rq \"$first\" \"$second\"\n  govulncheck:\n    go-version: '" + scanner + "'\n    summary: golang.org/x/vuln/cmd/govulncheck@v1.7.0\n    version: golang.org/x/vuln/cmd/govulncheck@v1.7.0\n    run: golang.org/x/vuln/cmd/govulncheck@v1.7.0\n"
}

func TestRejectsCompatibilityLaneBelowLinterMinimum(t *testing.T) {
	t.Parallel()
	c := testContract()
	c.Staticcheck.MinimumGo = "1.26.0"
	err := VerifyWorkflow(c, []byte(testWorkflow("1.26.6")))
	if err == nil || !strings.Contains(err.Error(), "below staticcheck minimum") {
		t.Fatalf("error=%v", err)
	}
}

func TestRejectsUnpinnedOrMisplacedStaticAnalysis(t *testing.T) {
	t.Parallel()
	const pin = "honnef.co/go/tools/cmd/staticcheck@v0.7.0"
	for name, test := range map[string]struct{ workflow, want string }{
		"absent from the test job": {
			strings.Replace(testWorkflow("1.26.6"), "    lint: "+pin+"\n", "", 1),
			"exactly twice",
		},
		"floating version": {
			strings.Replace(testWorkflow("1.26.6"), "    lint: "+pin, "    lint: honnef.co/go/tools/cmd/staticcheck@latest", 1),
			"exactly twice",
		},
		"invoked from another lane": {
			testWorkflow("1.26.6") + "    lint: " + pin + "\n",
			"only from the test job",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := VerifyWorkflow(testContract(), []byte(test.workflow))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
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
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := Load(filepath.Join("..", "..", "security-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelease(contract, workflow); err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct{ workflow, want string }{
		"lane below the module go directive": {
			strings.Replace(string(workflow), "go-version: '1.25.x'", "go-version: '1.24.x'", 1),
			"differs from compatibility Go",
		},
		"lane ahead of the compatibility declaration": {
			strings.Replace(string(workflow), "go-version: '1.25.x'", "go-version: '1.26.x'", 1),
			"differs from compatibility Go",
		},
		"no release job": {
			strings.Replace(string(workflow), "\n  release:\n", "\n  publish:\n", 1),
			"job release not found",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := VerifyRelease(contract, []byte(test.workflow))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}
