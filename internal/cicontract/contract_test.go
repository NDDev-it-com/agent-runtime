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
	workflow := strings.Replace(testWorkflow("1.26.5"), "test:\n    go-version: '1.25.x'", "test:\n    go-version: '1.24.x'", 1)
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
		"missing":   strings.Replace(testWorkflow("1.26.5"), canonical, "go test ./...", 1),
		"duplicate": testWorkflow("1.26.5") + canonical + "\n",
	} {
		if err := VerifyWorkflow(c, []byte(workflow)); err == nil || !strings.Contains(err.Error(), "fuzz verifier") {
			t.Errorf("%s error=%v", name, err)
		}
	}
}

func TestReleaseReproductionCommandOwnsOnlyParent(t *testing.T) {
	t.Parallel()
	canonical := testWorkflow("1.26.5")
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
	return Contract{SchemaVersion: "v1alpha1", License: releasecontract.CanonicalLicense, Govulncheck: Tool{Module: "golang.org/x/vuln/cmd/govulncheck", Version: "v1.6.0", MinimumGo: "1.25.0", UpstreamGoMod: "https://github.com/golang/vuln/blob/v1.6.0/go.mod"}, SecurityGo: "1.26.5", SecurityArchive: "go1.26.5.darwin-arm64.tar.gz", SecuritySHA256: "efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a", CompatibilityGo: "1.25"}
}
func testWorkflow(scanner string) string {
	return "env:\n  GOTOOLCHAIN: local\njobs:\n  test:\n    go-version: '1.25.x'\n    run: go run ./cmd/check-fuzz\n    reproduce: |\n      parent=\"$(mktemp -d)\"\n      first=\"$parent/first\"\n      second=\"$parent/second\"\n      first_result=\"$parent/first-result.json\"\n      second_result=\"$parent/second-result.json\"\n      go run ./cmd/check-release-contract --build --commit HEAD --out \"$first\" --result \"$first_result\"\n      go run ./cmd/check-release-contract --build --commit HEAD --out \"$second\" --result \"$second_result\"\n      go run ./cmd/check-release-contract --out \"$first\" --verify-result \"$first_result\"\n      go run ./cmd/check-release-contract --out \"$second\" --verify-result \"$second_result\"\n      diff -rq \"$first\" \"$second\"\n  govulncheck:\n    go-version: '" + scanner + "'\n    summary: golang.org/x/vuln/cmd/govulncheck@v1.6.0\n    version: golang.org/x/vuln/cmd/govulncheck@v1.6.0\n    run: golang.org/x/vuln/cmd/govulncheck@v1.6.0\n    test: go test ./...\n    vet: go vet ./...\n    build: go build ./cmd/agent-runtime\n    tidy: go run ./cmd/check-module-tidy\n    ci: go run ./cmd/check-ci-contract\n    release: go run ./cmd/check-release-contract\n"
}
