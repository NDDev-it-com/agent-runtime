// SPDX-License-Identifier: AGPL-3.0-only

package cicontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	workflow := strings.Replace(testWorkflow("1.26.5"), "test:\n    go-version: '1.24.x'", "test:\n    go-version: '1.25.x'", 1)
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
func testContract() Contract {
	return Contract{SchemaVersion: "v1alpha1", License: "AGPL-3.0-only", Govulncheck: Tool{Module: "golang.org/x/vuln/cmd/govulncheck", Version: "v1.6.0", MinimumGo: "1.25.0", UpstreamGoMod: "https://github.com/golang/vuln/blob/v1.6.0/go.mod"}, SecurityGo: "1.26.5", CompatibilityGo: "1.24"}
}
func testWorkflow(scanner string) string {
	return "env:\n  GOTOOLCHAIN: local\njobs:\n  test:\n    go-version: '1.24.x'\n  govulncheck:\n    go-version: '" + scanner + "'\n    summary: golang.org/x/vuln/cmd/govulncheck@v1.6.0\n    version: golang.org/x/vuln/cmd/govulncheck@v1.6.0\n    run: golang.org/x/vuln/cmd/govulncheck@v1.6.0\n"
}
