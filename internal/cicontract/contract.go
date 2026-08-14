// SPDX-License-Identifier: AGPL-3.0-only

// Package cicontract verifies that CI matches the checked security-tool contract.
package cicontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/NDDev-it-com/agent-runtime/internal/actions"
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

// VerifyRelease holds the release workflow to the same compatibility toolchain
// as the test lane. The release job builds and publishes the module, so a
// release lane below the module's own go directive cannot run at all — and
// nothing noticed, because this contract used to read only ci.yml.
func VerifyRelease(c Contract, workflow []byte) error {
	w, err := actions.Parse(workflow)
	if err != nil {
		return err
	}
	version, err := jobGoVersion(w, "release")
	if err != nil {
		return err
	}
	if normalizeMinor(version) != normalizeMinor(c.CompatibilityGo) {
		return fmt.Errorf("release job Go %s differs from compatibility Go %s", version, c.CompatibilityGo)
	}
	// The publishing job's token is held to contents, id-token and attestation
	// scopes. Reading the immutable-releases setting needs admin read access, so
	// calling it here fails the job with HTTP 403 after every other check has
	// passed. That guarantee belongs to the organisation tag ruleset and to the
	// pre-tag gate, neither of which depends on this token. The comment in the
	// workflow explaining that is prose and is deliberately not evidence here:
	// only an executed command counts.
	if w.CountRunOccurrences("/immutable-releases") != 0 {
		return errors.New("release workflow must not read the immutable-releases setting; its token has no admin access")
	}
	return nil
}

func VerifyWorkflow(c Contract, workflow []byte) error {
	w, err := actions.Parse(workflow)
	if err != nil {
		return err
	}
	testVersion, err := jobGoVersion(w, "test")
	if err != nil {
		return err
	}
	scannerVersion, err := jobGoVersion(w, "govulncheck")
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
	// Each pin is counted per lane, over executed run scripts only. Counting
	// over the whole file let an invocation move to a comment or to another job
	// while the total stayed right.
	scanner, err := w.Job("govulncheck")
	if err != nil {
		return err
	}
	test, err := w.Job("test")
	if err != nil {
		return err
	}
	pin := c.Govulncheck.Module + "@" + c.Govulncheck.Version
	if scanner.CountRunOccurrences(pin) != 3 {
		return fmt.Errorf("govulncheck job must run pinned %s exactly three times (summary, version evidence, and scan)", pin)
	}
	if w.CountRunOccurrences(pin) != 3 {
		return fmt.Errorf("pinned %s must be invoked only from the govulncheck job", pin)
	}
	lintPin := c.Staticcheck.Module + "@" + c.Staticcheck.Version
	if test.CountRunOccurrences(lintPin) != 2 {
		return fmt.Errorf("test job must run pinned %s exactly twice (version evidence and analysis)", lintPin)
	}
	if w.CountRunOccurrences(lintPin) != 2 {
		return fmt.Errorf("pinned %s must be invoked only from the test job", lintPin)
	}
	if w.Env["GOTOOLCHAIN"] != "local" {
		return errors.New("workflow must set GOTOOLCHAIN: local")
	}
	if w.CountRunOccurrences("go run ./cmd/check-fuzz") != 1 {
		return errors.New("workflow must invoke the canonical fuzz verifier exactly once")
	}
	return verifyReleaseReproductionCommand(test)
}

// verifyReleaseReproductionCommand requires the whole reproduction sequence to
// live in one executed step. Spreading it over several steps, or leaving part
// of it in a comment, would leave the two builds uncompared while every token
// was still present somewhere in the file.
func verifyReleaseReproductionCommand(job *actions.Job) error {
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
	var reproduction string
	for _, script := range job.RunScripts() {
		if strings.Contains(script, `diff -rq "$first" "$second"`) {
			if reproduction != "" {
				return errors.New("release reproduction command must be one step")
			}
			reproduction = script
		}
	}
	if reproduction == "" {
		return errors.New("test job must run the release reproduction command")
	}
	for _, token := range required {
		if strings.Count(reproduction, token) != 1 {
			return fmt.Errorf("release reproduction command requires exactly one %q", token)
		}
	}
	for _, forbidden := range []string{`release/contract.json`, `${TMPDIR}/`, `${RUNNER_TEMP}/`, `mkdir "$first"`, `mkdir "$second"`, `mkdir -p "$first"`, `mkdir -p "$second"`} {
		if strings.Contains(reproduction, forbidden) {
			return errors.New("release reproduction command must not pre-create final output leaves")
		}
	}
	return nil
}

// jobGoVersion reads the toolchain a job actually installs, from the setup-go
// step's own input rather than from any `go-version:` text in the job body.
func jobGoVersion(w *actions.Workflow, id string) (string, error) {
	job, err := w.Job(id)
	if err != nil {
		return "", err
	}
	step, ok := job.StepUsing("actions/setup-go@")
	if !ok {
		return "", fmt.Errorf("workflow job %s does not install a Go toolchain", id)
	}
	version := step.With["go-version"]
	if version == "" {
		return "", fmt.Errorf("workflow job %s has no literal go-version", id)
	}
	return strings.TrimSuffix(version, ".x"), nil
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
