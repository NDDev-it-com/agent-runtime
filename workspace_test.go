// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildContextPreservesOrder(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, root, "one.md", "one")
	writeTestFile(t, root, "two.md", "two\n")
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.BuildContext([]string{"two.md", "one.md"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "\n--- two.md ---\ntwo\n\n--- one.md ---\none\n" {
		t.Fatalf("unexpected context: %q", got)
	}
}

func TestResolveRejectsEscapeAndSymlink(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "secret")
	writeTestFile(t, parent, "secret", "nope")
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Resolve("../secret"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("escape error: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Resolve("link"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("symlink error: %v", err)
	}
}

func TestBuildContextLimit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, root, "large", strings.Repeat("x", 20))
	w, _ := OpenWorkspace(root)
	if _, err := w.BuildContext([]string{"large"}, 10); err == nil {
		t.Fatal("expected limit error")
	}
}

func TestResolveDirectoryRejectsFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, root, "file", "x")
	w, _ := OpenWorkspace(root)
	if _, err := w.ResolveDirectory("file"); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
