// SPDX-License-Identifier: AGPL-3.0-only

// Package cicontract verifies that CI matches the checked security-tool contract.
package cicontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/NDDev-it-com/agent-runtime/internal/releasecontract"
)

type Contract struct {
	SchemaVersion   string `json:"schema_version"`
	License         string `json:"license"`
	Govulncheck     Tool   `json:"govulncheck"`
	Staticcheck     Tool   `json:"staticcheck"`
	SecurityGo      string `json:"security_go"`
	CompatibilityGo string `json:"compatibility_go"`
}
type Tool struct {
	Module        string `json:"module"`
	Version       string `json:"version"`
	MinimumGo     string `json:"minimum_go"`
	UpstreamGoMod string `json:"upstream_go_mod"`
}

func Load(path string) (Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Contract{}, fmt.Errorf("read contract: %w", err)
	}
	var c Contract
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return Contract{}, fmt.Errorf("decode contract: %w", err)
	}
	if c.SchemaVersion != "v1alpha1" || c.License != releasecontract.CanonicalLicense || c.SecurityGo == "" || c.CompatibilityGo == "" {
		return Contract{}, errors.New("contract has missing or unsupported fields")
	}
	for name, tool := range map[string]Tool{"govulncheck": c.Govulncheck, "staticcheck": c.Staticcheck} {
		if tool.Module == "" || tool.Version == "" || tool.MinimumGo == "" || tool.UpstreamGoMod == "" {
			return Contract{}, fmt.Errorf("contract tool %q has missing or unsupported fields", name)
		}
	}
	return c, nil
}

func VerifyWorkflow(c Contract, workflow []byte) error {
	text := string(workflow)
	testVersion, err := jobGoVersion(text, "test")
	if err != nil {
		return err
	}
	scannerVersion, err := jobGoVersion(text, "govulncheck")
	if err != nil {
		return err
	}
	if normalizeMinor(testVersion) != normalizeMinor(c.CompatibilityGo) {
		return fmt.Errorf("test job Go %s differs from compatibility Go %s", testVersion, c.CompatibilityGo)
	}
	if compareGo(scannerVersion, c.Govulncheck.MinimumGo) < 0 {
		return fmt.Errorf("govulncheck job Go %s is below tool minimum %s", scannerVersion, c.Govulncheck.MinimumGo)
	}
	if scannerVersion != c.SecurityGo {
		return fmt.Errorf("govulncheck job Go %s differs from patched security Go %s", scannerVersion, c.SecurityGo)
	}
	if compareGo(testVersion, c.Staticcheck.MinimumGo) < 0 {
		return fmt.Errorf("test job Go %s is below staticcheck minimum %s", testVersion, c.Staticcheck.MinimumGo)
	}
	pin := c.Govulncheck.Module + "@" + c.Govulncheck.Version
	if strings.Count(text, pin) != 3 {
		return fmt.Errorf("workflow must reference pinned %s exactly three times (summary, version evidence, and scan)", pin)
	}
	testBody, err := jobBody(text, "test")
	if err != nil {
		return err
	}
	lintPin := c.Staticcheck.Module + "@" + c.Staticcheck.Version
	if strings.Count(testBody, lintPin) != 2 {
		return fmt.Errorf("test job must reference pinned %s exactly twice (version evidence and analysis)", lintPin)
	}
	if strings.Count(text, lintPin) != strings.Count(testBody, lintPin) {
		return fmt.Errorf("pinned %s must be invoked only from the test job", lintPin)
	}
	if !strings.Contains(text, "GOTOOLCHAIN: local") {
		return errors.New("workflow must set GOTOOLCHAIN: local")
	}
	if strings.Count(text, "go run ./cmd/check-fuzz") != 1 {
		return errors.New("workflow must invoke the canonical fuzz verifier exactly once")
	}
	if err := verifyReleaseReproductionCommand(text); err != nil {
		return err
	}
	return nil
}

func verifyReleaseReproductionCommand(workflow string) error {
	required := []string{
		`parent="$(mktemp -d)"`,
		`first="$parent/first"`,
		`second="$parent/second"`,
		`first_result="$parent/first-result.json"`,
		`second_result="$parent/second-result.json"`,
		`--build --commit HEAD --out "$first" --result "$first_result"`,
		`--build --commit HEAD --out "$second" --result "$second_result"`,
		`--out "$first" --verify-result "$first_result"`,
		`--out "$second" --verify-result "$second_result"`,
		`diff -rq "$first" "$second"`,
	}
	for _, token := range required {
		token = strings.ReplaceAll(token, "\\\"", "\"")
		if strings.Count(workflow, token) != 1 {
			return fmt.Errorf("release reproduction command requires exactly one %q", token)
		}
	}
	for _, forbidden := range []string{`release/contract.json`, `${TMPDIR}/`, `${RUNNER_TEMP}/`, `mkdir "$first"`, `mkdir "$second"`, `mkdir -p "$first"`, `mkdir -p "$second"`} {
		forbidden = strings.ReplaceAll(forbidden, "\\\"", "\"")
		if strings.Contains(workflow, forbidden) {
			return errors.New("release reproduction command must not pre-create final output leaves")
		}
	}
	return nil
}
func jobBody(workflow, job string) (string, error) {
	marker := "  " + job + ":\n"
	start := strings.Index(workflow, marker)
	if start < 0 {
		return "", fmt.Errorf("workflow job %s not found", job)
	}
	body := workflow[start+len(marker):]
	jobBoundary := regexp.MustCompile(`(?m)^  [a-zA-Z0-9_-]+:\s*$`)
	if next := jobBoundary.FindStringIndex(body); next != nil {
		body = body[:next[0]]
	}
	return body, nil
}

func jobGoVersion(workflow, job string) (string, error) {
	body, err := jobBody(workflow, job)
	if err != nil {
		return "", err
	}
	version := regexp.MustCompile(`go-version:\s*'([^']+)'`).FindStringSubmatch(body)
	if version == nil {
		return "", fmt.Errorf("workflow job %s has no literal go-version", job)
	}
	return strings.TrimSuffix(version[1], ".x"), nil
}
func normalizeMinor(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}
func compareGo(a, b string) int {
	parse := func(v string) []int {
		v = strings.TrimSuffix(v, ".x")
		parts := strings.Split(v, ".")
		out := make([]int, 3)
		for i := 0; i < len(parts) && i < 3; i++ {
			out[i], _ = strconv.Atoi(parts[i])
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := range x {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}
