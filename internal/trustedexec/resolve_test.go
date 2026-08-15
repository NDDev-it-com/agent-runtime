// SPDX-License-Identifier: AGPL-3.0-only

package trustedexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvesTheToolsTheTrustPathRuns(t *testing.T) {
	t.Parallel()
	for _, resolve := range []func() (string, error){Git, SSHKeygen} {
		path, err := resolve()
		if err != nil {
			t.Fatalf("a supported host must resolve the trust tools: %v", err)
		}
		if !filepath.IsAbs(path) {
			t.Fatalf("resolved %q is not absolute", path)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("resolved %q is not a regular file: %v", path, err)
		}
	}
}

// TestNeverReadsThePathEnvironment is the property the fixed search exists for:
// whoever can set an environment variable must not be able to choose the
// program that decides whether a commit is signed.
func TestNeverReadsThePathEnvironment(t *testing.T) {
	fake := t.TempDir()
	impostor := filepath.Join(fake, "git")
	if err := os.WriteFile(impostor, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake)
	// Resolution is cached per process, so ask the search directly rather than
	// through the cache to prove the environment is not consulted.
	got := search("git")
	if got.err != nil {
		t.Fatalf("resolution failed: %v", got.err)
	}
	if strings.HasPrefix(got.path, fake) {
		t.Fatalf("resolution followed PATH to %q", got.path)
	}
}

func TestRejectsNamesThatWouldSkipTheSearch(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "/usr/bin/git", "../git", "sub/git"} {
		if _, err := Resolve(name); err == nil {
			t.Errorf("name %q bypassed the search", name)
		}
	}
}

// TestSearchNamesWhatItLookedAt covers the honesty half of the trade: a host
// that keeps its tools elsewhere cannot verify anything, so the failure has to
// say why rather than surfacing as an obscure exec error.
func TestSearchNamesWhatItLookedAt(t *testing.T) {
	t.Parallel()
	got := search("definitely-not-a-real-trust-tool")
	if got.err == nil {
		t.Fatal("a missing tool resolved")
	}
	message := got.err.Error()
	for _, directory := range searchPath {
		if !strings.Contains(message, directory) {
			t.Errorf("the failure does not name %s: %s", directory, message)
		}
	}
	if !strings.Contains(message, "never reads PATH") {
		t.Errorf("the failure does not explain the constraint: %s", message)
	}
}

// TestRefusesAWritableTool covers substitution by anyone who can write the
// binary rather than the directory.
func TestRefusesAWritableTool(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "toolish")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	original := searchPath
	t.Cleanup(func() { searchPath = original })
	searchPath = []string{dir}
	if got := search("toolish"); got.err == nil {
		t.Fatal("a group and world writable tool was accepted")
	}
}
