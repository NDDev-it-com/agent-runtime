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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const SchemaVersion = "v1alpha1"

var (
	versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	actionPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)
)

type Contract struct {
	SchemaVersion   string       `json:"schema_version"`
	Version         string       `json:"version"`
	ModulePath      string       `json:"module_path"`
	GoCompatibility string       `json:"go_compatibility"`
	License         string       `json:"license"`
	Dependencies    []Dependency `json:"dependencies"`
	SourceCommit    string       `json:"source_commit"`
	ArchivePrefix   string       `json:"archive_prefix"`
	Workflow        string       `json:"workflow"`
	AllowedSigners  string       `json:"allowed_signers"`
	Assets          Assets       `json:"assets"`
	Limits          Limits       `json:"limits"`
	Actions         Actions      `json:"actions"`
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
	if c.ModulePath != "github.com/NDDev-it-com/agent-runtime" || c.GoCompatibility != "1.24" || c.License != "AGPL-3.0-only" {
		return errors.New("module path, Go 1.24 compatibility, and AGPL license are canonical")
	}
	wantDependencies := []Dependency{
		{ModulePath: "golang.org/x/mod", Version: "v0.27.0", License: "BSD-3-Clause"},
		{ModulePath: "golang.org/x/sys", Version: "v0.40.0", License: "BSD-3-Clause"},
	}
	if !equalDependencies(c.Dependencies, wantDependencies) {
		return errors.New("release dependency contract must exactly match go.mod")
	}
	if c.SourceCommit != "HEAD" || c.Workflow != ".github/workflows/release.yml" || c.AllowedSigners != ".github/release-allowed-signers" {
		return errors.New("release source and workflow identity are invalid")
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
	actions := map[string]string{"checkout": c.Actions.Checkout, "setup_go": c.Actions.SetupGo, "attest_provenance": c.Actions.AttestProvenance, "attest_sbom": c.Actions.AttestSBOM}
	prefixes := map[string]string{"checkout": "actions/checkout@", "setup_go": "actions/setup-go@", "attest_provenance": "actions/attest-build-provenance@", "attest_sbom": "actions/attest@"}
	for name, action := range actions {
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
	line := strings.TrimSpace(string(signers))
	const canonicalSigner = "danilsilantyevwork@gmail.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM32vxPI+ii/mWp5YOy9osj/uyo5ra0HMy2+6lUOh/b2"
	if line != canonicalSigner || strings.Count(line, "\n") != 0 {
		return errors.New("release allowed-signers file must contain the one canonical SSH signer")
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
	if len(parsed.Require) != len(c.Dependencies) {
		return errors.New("go.mod dependency closure differs from release contract")
	}
	for index, requirement := range parsed.Require {
		dependency := c.Dependencies[index]
		if requirement.Indirect || requirement.Mod.Path != dependency.ModulePath || requirement.Mod.Version != dependency.Version || module.CanonicalVersion(requirement.Mod.Version) != requirement.Mod.Version {
			return errors.New("go.mod dependency identity/order differs from release contract")
		}
	}
	return nil
}

func sameGoCompatibility(actual, expected string) bool {
	return actual == expected || actual == expected+".0"
}

func (c Contract) verifyGoSum(data []byte) error {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	want := make([]string, 0, len(c.Dependencies)*2)
	for _, dependency := range c.Dependencies {
		want = append(want, dependency.ModulePath+" "+dependency.Version, dependency.ModulePath+" "+dependency.Version+"/go.mod")
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

func (c Contract) VerifyWorkflow(data []byte) error {
	s := string(data)
	required := []string{
		"tags: ['v*.*.*']", "if: github.run_attempt == 1", "contents: read", "contents: write", "id-token: write", "attestations: write", "artifact-metadata: write",
		"go run ./cmd/check-release-contract", "git verify-tag", "verification.verified", "refs/heads/main", "gh release create", "--verify-tag", c.Actions.Checkout, c.Actions.SetupGo, c.Actions.AttestProvenance, c.Actions.AttestSBOM,
		"--expect-version",
	}
	for _, token := range required {
		if !strings.Contains(s, token) {
			return fmt.Errorf("release workflow missing required token %q", token)
		}
	}
	for _, forbidden := range []string{"pull_request:", "branches: [main]", "workflow_dispatch:", "--clobber", "permissions: write-all", "secrets:", "environment:"} {
		if strings.Contains(s, forbidden) {
			return fmt.Errorf("release workflow contains forbidden publication surface %q", forbidden)
		}
	}
	if strings.Count(s, "contents: write") != 1 || strings.Count(s, "id-token: write") != 1 || strings.Count(s, "attestations: write") != 1 || strings.Count(s, "artifact-metadata: write") != 1 {
		return errors.New("release write permissions must occur exactly once at job scope")
	}
	return nil
}
