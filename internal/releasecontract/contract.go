// SPDX-License-Identifier: AGPL-3.0-only

// Package releasecontract builds and validates the versioned source release.
package releasecontract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/NDDev-it-com/agent-runtime/internal/actions"
	"github.com/NDDev-it-com/agent-runtime/internal/provenance"
	"github.com/NDDev-it-com/agent-runtime/internal/signatureverify"
)

const (
	SchemaVersion    = "v1alpha1"
	CanonicalLicense = "AGPL-3.0-only"
	// CanonicalGoCompatibility is the minimum Go the published module declares.
	// It is the one place the baseline is written in Go; release/v1alpha1.json,
	// the release schema, security-tools.json and go.mod must agree with it.
	CanonicalGoCompatibility = "1.25"
	// ReleaseJob is the only job in the release workflow permitted to hold
	// write scopes, and the job every publication assertion is made against.
	ReleaseJob = "release"
)

var (
	versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	actionPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// permittedDependencyLicenses is a closed allowlist rather than a single
	// constant, because the closure is no longer uniformly BSD. It stays closed
	// so a dependency arriving under an unreviewed licence fails the contract
	// instead of being recorded as whatever its go.mod happened to say.
	permittedDependencyLicenses = map[string]bool{
		"Apache-2.0":   true,
		"BSD-3-Clause": true,
		"MIT":          true,
	}
)

type Contract struct {
	SchemaVersion   string       `json:"schema_version"`
	Version         string       `json:"version"`
	ModulePath      string       `json:"module_path"`
	GoCompatibility string       `json:"go_compatibility"`
	License         string       `json:"license"`
	Dependencies    []Dependency `json:"dependencies"`
	// GraphOnlyModules are pinned in go.sum but provide no package to any
	// build or test of this module. They exist because a dependency's own
	// go.mod names them, so their checksums are part of the verified module
	// graph while their code never runs here. Listing them separately keeps
	// both closures exact: conflating the two forced a test-only module of a
	// dependency to be recorded as if this module depended on it.
	GraphOnlyModules []Dependency `json:"graph_only_modules,omitempty"`
	SourceCommit     string       `json:"source_commit"`
	ArchivePrefix    string       `json:"archive_prefix"`
	Workflow         string       `json:"workflow"`
	AllowedSigners   string       `json:"allowed_signers"`
	Assets           Assets       `json:"assets"`
	Limits           Limits       `json:"limits"`
	Actions          Actions      `json:"actions"`
}

type Assets struct {
	Archive   string `json:"archive"`
	SBOM      string `json:"sbom"`
	Notes     string `json:"notes"`
	Manifest  string `json:"manifest"`
	Checksums string `json:"checksums"`
}

type Limits struct {
	MaxFiles      int   `json:"max_files"`
	MaxFileBytes  int64 `json:"max_file_bytes"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
	MaxPathBytes  int   `json:"max_path_bytes"`
}

type Actions struct {
	Checkout         string `json:"checkout"`
	SetupGo          string `json:"setup_go"`
	AttestProvenance string `json:"attest_provenance"`
	AttestSBOM       string `json:"attest_sbom"`
}

type Dependency struct {
	ModulePath string `json:"module_path"`
	Version    string `json:"version"`
	License    string `json:"license"`
	Indirect   bool   `json:"indirect,omitempty"`
}

func Load(path string) (Contract, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Contract{}, fmt.Errorf("read release contract: %w", err)
	}
	var c Contract
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Contract{}, fmt.Errorf("decode release contract: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Contract{}, errors.New("release contract must contain one JSON value")
	}
	if err := c.Validate(); err != nil {
		return Contract{}, err
	}
	return c, nil
}

func (c Contract) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", c.SchemaVersion)
	}
	if !versionPattern.MatchString(c.Version) {
		return errors.New("version must be canonical vMAJOR.MINOR.PATCH")
	}
	if c.ModulePath != "github.com/NDDev-it-com/agent-runtime" || c.GoCompatibility != CanonicalGoCompatibility || c.License != CanonicalLicense {
		return fmt.Errorf("module path, Go %s compatibility, and AGPL license are canonical", CanonicalGoCompatibility)
	}
	if len(c.Dependencies) == 0 || len(c.Dependencies) > 64 {
		return errors.New("release dependency closure is empty or unbounded")
	}
	seenDependencies := make(map[string]struct{}, len(c.Dependencies))
	for _, dependency := range c.Dependencies {
		if module.CheckPath(dependency.ModulePath) != nil || module.CanonicalVersion(dependency.Version) != dependency.Version || !permittedDependencyLicenses[dependency.License] {
			return errors.New("release dependency identity, version, or license is invalid")
		}
		if _, duplicate := seenDependencies[dependency.ModulePath]; duplicate {
			return errors.New("release dependency path is duplicated")
		}
		seenDependencies[dependency.ModulePath] = struct{}{}
	}
	if c.SourceCommit != "HEAD" || c.Workflow != ".github/workflows/release.yml" || c.AllowedSigners != ".github/release-allowed-signers" {
		return errors.New("release source and workflow identity are invalid")
	}
	if !equalDependencies(c.Dependencies, canonicalDependencies(c.Dependencies)) {
		return errors.New("release dependencies must use canonical module-path order")
	}
	if len(c.GraphOnlyModules) > 64 {
		return errors.New("release graph-only module closure is unbounded")
	}
	for _, pinned := range c.GraphOnlyModules {
		if module.CheckPath(pinned.ModulePath) != nil || module.CanonicalVersion(pinned.Version) != pinned.Version || !permittedDependencyLicenses[pinned.License] {
			return errors.New("release graph-only module identity, version, or license is invalid")
		}
		if _, built := seenDependencies[pinned.ModulePath]; built {
			return fmt.Errorf("module %q is listed as both a dependency and graph-only", pinned.ModulePath)
		}
	}
	if !equalDependencies(c.GraphOnlyModules, canonicalDependencies(c.GraphOnlyModules)) {
		return errors.New("release graph-only modules must use canonical module-path order")
	}
	wantPrefix := "agent-runtime-" + c.Version + "/"
	if c.ArchivePrefix != wantPrefix {
		return fmt.Errorf("archive_prefix must be %q", wantPrefix)
	}
	if err := validateArchivePrefix(c.ArchivePrefix, c.Limits.MaxPathBytes); err != nil {
		return fmt.Errorf("archive_prefix: %w", err)
	}
	wantAssets := Assets{
		Archive:   "agent-runtime-" + c.Version + "-source.tar.gz",
		SBOM:      "agent-runtime-" + c.Version + ".spdx.json",
		Notes:     "release-notes-" + c.Version + ".md",
		Manifest:  "release-manifest-" + c.Version + ".json",
		Checksums: "SHA256SUMS",
	}
	if c.Assets != wantAssets {
		return errors.New("release asset identities drifted from version")
	}
	for _, name := range c.Assets.Names() {
		if err := validatePortableRelativePath(name, c.Limits.MaxPathBytes); err != nil || strings.ContainsRune(name, '/') {
			return fmt.Errorf("release asset name %q is not one portable basename", name)
		}
	}
	if c.Limits.MaxFiles < 1 || c.Limits.MaxFiles > 10000 || c.Limits.MaxFileBytes < 1 || c.Limits.MaxFileBytes > 64<<20 || c.Limits.MaxTotalBytes < c.Limits.MaxFileBytes || c.Limits.MaxTotalBytes > 256<<20 || c.Limits.MaxPathBytes < 64 || c.Limits.MaxPathBytes > 4096 {
		return errors.New("release bounds are missing or unsafe")
	}
	pinnedActions := map[string]string{"checkout": c.Actions.Checkout, "setup_go": c.Actions.SetupGo, "attest_provenance": c.Actions.AttestProvenance, "attest_sbom": c.Actions.AttestSBOM}
	prefixes := map[string]string{"checkout": "actions/checkout@", "setup_go": "actions/setup-go@", "attest_provenance": "actions/attest-build-provenance@", "attest_sbom": "actions/attest@"}
	for name, action := range pinnedActions {
		if !actionPattern.MatchString(action) {
			return fmt.Errorf("action %s must be pinned to a full commit SHA", name)
		}
		if !strings.HasPrefix(action, prefixes[name]) {
			return fmt.Errorf("action %s must use the canonical official repository", name)
		}
	}
	return nil
}

func (a Assets) Names() []string {
	return []string{a.Archive, a.SBOM, a.Notes, a.Manifest, a.Checksums}
}

func (c Contract) VerifyRepository(root string) error {
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	if err := c.verifyGoMod(goMod); err != nil {
		return err
	}
	goSum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return err
	}
	if err := c.verifyGoSum(goSum); err != nil {
		return err
	}
	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		return err
	}
	if strings.Count(string(changelog), "## ["+strings.TrimPrefix(c.Version, "v")+"]") != 1 {
		return errors.New("changelog must contain exactly one release section")
	}
	workflow, err := os.ReadFile(filepath.Join(root, c.Workflow))
	if err != nil {
		return err
	}
	if err := c.VerifyWorkflow(workflow); err != nil {
		return err
	}
	signers, err := os.ReadFile(filepath.Join(root, c.AllowedSigners))
	if err != nil {
		return err
	}
	if err := signatureverify.ValidateTrustAnchor(signers); err != nil {
		return fmt.Errorf("release allowed-signers: %w", err)
	}
	return nil
}

func (c Contract) verifyGoMod(data []byte) error {
	parsed, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return fmt.Errorf("parse go.mod: %w", err)
	}
	if parsed.Module == nil || parsed.Module.Mod.Path != c.ModulePath || parsed.Go == nil || !sameGoCompatibility(parsed.Go.Version, c.GoCompatibility) {
		return errors.New("go.mod module or Go compatibility differs from release contract")
	}
	if parsed.Toolchain != nil || len(parsed.Replace) != 0 || len(parsed.Exclude) != 0 || len(parsed.Retract) != 0 || len(parsed.Tool) != 0 || len(parsed.Godebug) != 0 || len(parsed.Ignore) != 0 {
		return errors.New("go.mod contains an uncontracted semantic directive")
	}
	contractDependencies := make(map[string]Dependency, len(c.Dependencies))
	for _, dependency := range c.Dependencies {
		contractDependencies[dependency.ModulePath] = dependency
	}
	if len(parsed.Require) != len(contractDependencies) {
		return errors.New("go.mod dependency closure differs from release contract")
	}
	actual := make([]Dependency, 0, len(parsed.Require))
	for _, requirement := range parsed.Require {
		dependency, ok := contractDependencies[requirement.Mod.Path]
		if !ok || module.CanonicalVersion(requirement.Mod.Version) != requirement.Mod.Version {
			return errors.New("go.mod dependency identity differs from release contract")
		}
		actual = append(actual, Dependency{ModulePath: requirement.Mod.Path, Version: requirement.Mod.Version, License: dependency.License, Indirect: requirement.Indirect})
	}
	if !equalDependencies(canonicalDependencies(actual), canonicalDependencies(c.Dependencies)) {
		return errors.New("go.mod dependency closure differs from release contract")
	}
	return nil
}

func canonicalDependencies(dependencies []Dependency) []Dependency {
	canonical := append([]Dependency(nil), dependencies...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].ModulePath < canonical[j].ModulePath })
	return canonical
}

func sameGoCompatibility(actual, expected string) bool {
	return actual == expected || actual == expected+".0"
}

func (c Contract) verifyGoSum(data []byte) error {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	// go.sum spans the verified module graph, which is a superset of the build
	// closure: a dependency's own requirements are pinned even when nothing
	// here compiles them.
	want := make([]string, 0, (len(c.Dependencies)+len(c.GraphOnlyModules))*2)
	for _, pinned := range append(append([]Dependency{}, c.Dependencies...), c.GraphOnlyModules...) {
		want = append(want, pinned.ModulePath+" "+pinned.Version, pinned.ModulePath+" "+pinned.Version+"/go.mod")
	}
	sort.Strings(want)
	if len(lines) != len(want) {
		return errors.New("go.sum closure differs from release contract")
	}
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0]+" "+fields[1] != want[index] || !strings.HasPrefix(fields[2], "h1:") {
			return errors.New("go.sum identity/order is malformed")
		}
		digest, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(fields[2], "h1:"))
		if decodeErr != nil || len(digest) != 32 {
			return errors.New("go.sum digest is malformed")
		}
	}
	return nil
}

// VerifyWorkflow proves the publishing lane is what it claims to be. Every
// assertion below is made against the parsed Actions model, so a control that
// has been moved into a comment, a disabled job or a value that never executes
// is absent as far as this contract is concerned — which is the only reading
// under which a green check means anything.
func (c Contract) VerifyWorkflow(data []byte) error {
	w, err := actions.Parse(data)
	if err != nil {
		return err
	}
	if err := c.verifyReleaseTrigger(w); err != nil {
		return err
	}
	if err := c.verifyReleasePermissions(w); err != nil {
		return err
	}
	job, err := w.Job(ReleaseJob)
	if err != nil {
		return err
	}
	if job.If != "github.run_attempt == 1" {
		return errors.New("release job must run only on the first attempt")
	}
	// Actions are pinned by digest, and the pin must be on a step that runs.
	for name, pin := range map[string]string{"checkout": c.Actions.Checkout, "setup_go": c.Actions.SetupGo, "attest_provenance": c.Actions.AttestProvenance, "attest_sbom": c.Actions.AttestSBOM} {
		if !slices.Contains(job.UsesActions(), pin) {
			return fmt.Errorf("release job must use pinned %s action %q", name, pin)
		}
	}
	// The checkout must not leave a usable credential behind for later steps.
	checkout, ok := job.StepUsing(c.Actions.Checkout)
	if !ok || checkout.With["persist-credentials"] != "false" {
		return errors.New("release checkout must set persist-credentials: false")
	}
	// Commands the lane is named after. Each must be in an executed script.
	for _, command := range []string{
		"go run ./cmd/check-release-contract", "go run ./cmd/check-cold-compile",
		"go run ./cmd/check-signature --tag", provenance.IntegrationCommand,
		"--expected-commit", "verification.verified", "refs/heads/main",
		"gh release create", "--verify-tag", "--expect-version",
		`release_parent="$(mktemp -d)"`, `release_dist="${release_parent}/release-dist"`,
		`release_result="${release_parent}/build-result.json"`, `--out "$release_dist"`,
		`--result "$release_result"`, `--verify-result "$release_result"`,
		// The receipt is only proof if the commit it is checked against comes
		// from the checkout rather than from the receipt itself.
		`--expect-commit "$release_commit"`, `release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{commit}")"`,
		`RELEASE_DIST=$release_dist`,
	} {
		if job.CountRunOccurrences(command) == 0 {
			return fmt.Errorf("release job must run %q", command)
		}
	}
	// The attestation steps must consume the bundle the build step exported,
	// which is a step input rather than a command.
	if !slices.ContainsFunc(w.StepValues(), func(value string) bool {
		return strings.Contains(value, "${{ env.RELEASE_DIST }}")
	}) {
		return errors.New("release attestation must take its subject from ${{ env.RELEASE_DIST }}")
	}
	for _, forbidden := range []string{"--clobber", "git config ", "git verify-tag", "${RUNNER_TEMP}/", "${TMPDIR}/"} {
		if w.CountRunOccurrences(forbidden) != 0 {
			return fmt.Errorf("release workflow contains forbidden publication surface %q", forbidden)
		}
	}
	return nil
}

// verifyReleaseTrigger keeps publication reachable only from a version tag.
func (c Contract) verifyReleaseTrigger(w *actions.Workflow) error {
	for _, forbidden := range []string{"pull_request", "workflow_dispatch", "workflow_call", "schedule", "repository_dispatch"} {
		if w.Triggers[forbidden].Present {
			return fmt.Errorf("release workflow must not be reachable from %q", forbidden)
		}
	}
	push := w.Triggers["push"]
	if !push.Present {
		return errors.New("release workflow must trigger on a pushed tag")
	}
	if len(push.Branches) != 0 {
		return errors.New("release workflow must not trigger on a branch push")
	}
	if !slices.Equal(push.Tags, []string{"v*.*.*"}) {
		return fmt.Errorf("release workflow tag filter must be exactly [v*.*.*], got %v", push.Tags)
	}
	return nil
}

// verifyReleasePermissions holds write scopes to the publishing job. A scope
// granted at workflow level would apply to every job that is ever added.
func (c Contract) verifyReleasePermissions(w *actions.Workflow) error {
	if w.Permissions["contents"] != "read" || len(w.Permissions) != 1 {
		return errors.New("release workflow scope must be exactly contents: read")
	}
	wanted := map[string]string{"contents": "write", "id-token": "write", "attestations": "write", "artifact-metadata": "write"}
	for _, job := range w.EnabledJobs() {
		if job.ID != ReleaseJob {
			if job.PermissionsSet {
				return fmt.Errorf("only the %s job may hold write permissions", ReleaseJob)
			}
			continue
		}
		if job.PermissionsBlanket != "" {
			return fmt.Errorf("release job must enumerate its permissions, not %q", job.PermissionsBlanket)
		}
		if !maps.Equal(job.Permissions, wanted) {
			return fmt.Errorf("release job permissions must be exactly %v, got %v", wanted, job.Permissions)
		}
		if job.Environment != "" || job.SecretsSet || job.UsesWorkflow != "" {
			return errors.New("release job must not use an environment, secrets or a called workflow")
		}
	}
	return nil
}
