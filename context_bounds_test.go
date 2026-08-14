// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildContextNeverExceedsDeclaredBound(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// header "\n--- A ---\n" is 11 bytes, the body is 1 byte, and BuildContext
	// appends a newline because the body does not end with one: 13 bytes total.
	writeTestFile(t, root, "A", "x")
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	for limit := int64(1); limit <= 20; limit++ {
		out, err := w.BuildContext([]string{"A"}, limit)
		if err != nil {
			continue
		}
		if int64(len(out)) > limit {
			t.Fatalf("limit %d produced %d bytes: %q", limit, len(out), out)
		}
	}
	if _, err := w.BuildContext([]string{"A"}, 12); err == nil {
		t.Fatal("a 12-byte limit accepted a 13-byte assembled context")
	}
	out, err := w.BuildContext([]string{"A"}, 13)
	if err != nil || len(out) != 13 {
		t.Fatalf("exact-fit limit rejected: len=%d err=%v", len(out), err)
	}
}

func TestBuildContextRejectsOversizedInstructionBeforeReadingIt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "BIG.md")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse file consumes no blocks but reports its full size, so reading it
	// unconditionally would allocate half a gigabyte.
	if err := file.Truncate(512 << 20); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.BuildContext([]string{"BIG.md"}, 1024)
	if err == nil {
		t.Fatal("oversized instruction accepted")
	}
	if !strings.Contains(err.Error(), "does not fit the remaining context budget") {
		t.Fatalf("rejection did not come from file metadata, so the read was not bounded: %v", err)
	}
}

func TestBuildContextBoundsTheCumulativeBudget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, root, "one.md", "one\n")
	writeTestFile(t, root, "two.md", "two\n")
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	full, err := w.BuildContext([]string{"one.md", "two.md"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.BuildContext([]string{"one.md", "two.md"}, int64(len(full))-1); err == nil {
		t.Fatal("cumulative budget was not enforced across instructions")
	}
	if _, err := w.BuildContext([]string{"one.md", "two.md"}, int64(len(full))); err != nil {
		t.Fatalf("exact cumulative budget rejected: %v", err)
	}
}

func TestResolveAcceptsWorkspaceRootAndRejectsEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, root, "inside", "x")
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ResolveDirectory("."); err != nil {
		t.Fatalf("workspace root rejected as workdir: %v", err)
	}
	for _, escape := range []string{"..", "../..", "../sibling"} {
		if _, err := w.Resolve(escape); err == nil {
			t.Fatalf("escape %q accepted", escape)
		}
	}
}
