// SPDX-License-Identifier: AGPL-3.0-only

package releasecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

const BuildResultSchemaVersion = "v1alpha1"

// BuildResult is the sole machine-readable description of a published bundle.
type BuildResult struct {
	SchemaVersion string        `json:"schema_version"`
	ArtifactRoot  string        `json:"artifact_root"`
	Version       string        `json:"version"`
	SourceCommit  string        `json:"source_commit"`
	ModulePath    string        `json:"module_path"`
	License       string        `json:"license"`
	Assets        []AssetDigest `json:"assets"`
}

func newBuildResult(out, commit string, c Contract, assets map[string][]byte) (BuildResult, error) {
	abs, err := filepath.Abs(out)
	if err != nil {
		return BuildResult{}, fmt.Errorf("resolve artifact root: %w", err)
	}
	root, err := CanonicalOutputPath(filepath.Dir(abs), filepath.Base(abs))
	if err != nil {
		return BuildResult{}, fmt.Errorf("canonicalize artifact root: %w", err)
	}
	result := BuildResult{SchemaVersion: BuildResultSchemaVersion, ArtifactRoot: root, Version: c.Version, SourceCommit: commit, ModulePath: c.ModulePath, License: CanonicalLicense}
	for _, name := range c.Assets.Names() {
		data, ok := assets[name]
		if !ok {
			return BuildResult{}, fmt.Errorf("build result missing asset %q", name)
		}
		result.Assets = append(result.Assets, digest(name, data))
	}
	return result, nil
}

// ValidateBuildResult fails closed unless the receipt describes this exact
// bundle built from expectedCommit.
//
// expectedCommit must be resolved by the caller from something the receipt
// cannot influence — the checkout, the annotated tag, the release manifest.
// Passing the receipt's own value back in is the defect this parameter exists
// to prevent: validation previously rejected only an empty source commit and
// then derived the expected receipt from the candidate, so replacing
// source_commit with any other forty hex characters left verification
// reporting the bundle as valid while it asserted a build from a commit that
// need not exist.
func ValidateBuildResult(result BuildResult, out string, c Contract, expectedCommit string) error {
	if !commitPattern.MatchString(expectedCommit) {
		return errors.New("expected source commit must be a canonical 40-hex commit")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("resolve expected artifact root: %w", err)
	}
	wantRoot, err := CanonicalOutputPath(filepath.Dir(abs), filepath.Base(abs))
	if err != nil {
		return fmt.Errorf("canonicalize expected artifact root: %w", err)
	}
	if result.SourceCommit != expectedCommit {
		return fmt.Errorf("build result claims source commit %q, expected %q", result.SourceCommit, expectedCommit)
	}
	if result.SchemaVersion != BuildResultSchemaVersion || result.ArtifactRoot != wantRoot || result.Version != c.Version || result.ModulePath != c.ModulePath || result.License != CanonicalLicense || result.License != c.License {
		return errors.New("build result identity mismatch")
	}
	assets, err := readBundleSecure(out, c)
	if err != nil {
		return err
	}
	if err := verifyBundleData(assets, c); err != nil {
		return err
	}
	want, err := newBuildResult(out, expectedCommit, c, assets)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(result, want) {
		return errors.New("build result asset path/digest closure mismatch")
	}
	// The manifest travels inside the bundle and names the commit too. Binding
	// them here means one asset cannot disagree with the receipt about what was
	// built without failing.
	var manifest Manifest
	if err := json.Unmarshal(assets[c.Assets.Manifest], &manifest); err != nil {
		return fmt.Errorf("decode release manifest: %w", err)
	}
	if manifest.SourceCommit != expectedCommit {
		return fmt.Errorf("release manifest names source commit %q, expected %q", manifest.SourceCommit, expectedCommit)
	}
	return nil
}

func WriteBuildResult(path string, result BuildResult) (rootErr error) {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode build result: %w", err)
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create build result: %w", err)
	}
	defer func() { rootErr = errors.Join(rootErr, f.Close()) }()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write build result: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync build result: %w", err)
	}
	return nil
}

func LoadBuildResult(path string) (BuildResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BuildResult{}, fmt.Errorf("read build result: %w", err)
	}
	var result BuildResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return BuildResult{}, fmt.Errorf("decode build result: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BuildResult{}, errors.New("decode build result: multiple JSON values")
	}
	return result, nil
}
