// SPDX-License-Identifier: AGPL-3.0-only

package modverify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyUsesOnlyAuthoritativeTidyDiffCommand(t *testing.T) {
	t.Parallel()
	var got invocation
	runner := runnerFunc(func(_ context.Context, call invocation) error {
		got = call
		return nil
	})
	var stdout, stderr bytes.Buffer
	if err := verify(context.Background(), "/repository", &stdout, &stderr, runner); err != nil {
		t.Fatal(err)
	}
	if got.path != "go" || !reflect.DeepEqual(got.args, []string{"mod", "tidy", "-diff"}) || got.dir != "/repository" {
		t.Fatalf("unexpected invocation: path=%q args=%q dir=%q", got.path, got.args, got.dir)
	}
	if countEnvironment(got.env, "GOTOOLCHAIN=local") != 1 {
		t.Fatalf("GOTOOLCHAIN=local must be set exactly once: %q", got.env)
	}
	if got.stdout != &stdout || got.stderr != &stderr {
		t.Fatal("command output boundaries were not preserved")
	}
}

func TestVerifyIgnoresExpectedAndUnrelatedWorktreeWIPWhenModuleIsTidy(t *testing.T) {
	t.Parallel()
	root := newModule(t, "module example.com/tidy-clean\n\ngo 1.24.0\n")
	writeFile(t, filepath.Join(root, "expected-feature-wip.txt"), "not committed\n")
	writeFile(t, filepath.Join(root, "unrelated-wip.txt"), "also not committed\n")
	before := readModuleFiles(t, root)
	var stdout, stderr bytes.Buffer
	if err := Verify(context.Background(), root, &stdout, &stderr); err != nil {
		t.Fatalf("tidy-clean dirty worktree rejected: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.Bytes(), stderr.Bytes())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("clean check emitted output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if after := readModuleFiles(t, root); !reflect.DeepEqual(after, before) {
		t.Fatal("verification mutated module files")
	}
}

func TestVerifyFailsClosedOnActualTidyDriftWithoutMutation(t *testing.T) {
	t.Parallel()
	root := newModule(t, "module example.com/tidy-drift\n\ngo 1.24.0\n\nrequire example.com/unused v0.0.0\n\nreplace example.com/unused => ./unused\n")
	before := readModuleFiles(t, root)
	var stdout, stderr bytes.Buffer
	err := Verify(context.Background(), root, &stdout, &stderr)
	if err == nil {
		t.Fatal("actual module tidy drift was accepted")
	}
	if stdout.Len() == 0 {
		t.Fatalf("tidy drift output was not preserved: %v", err)
	}
	if after := readModuleFiles(t, root); !reflect.DeepEqual(after, before) {
		t.Fatal("drift verification mutated module files")
	}
}

func TestVerifyPreservesOutputAndRootFailure(t *testing.T) {
	t.Parallel()
	rootFailure := errors.New("command failed")
	runner := runnerFunc(func(_ context.Context, call invocation) error {
		_, _ = ioWriteString(call.stdout, "tidy diff\n")
		_, _ = ioWriteString(call.stderr, "go diagnostic\n")
		return rootFailure
	})
	var stdout, stderr bytes.Buffer
	err := verify(context.Background(), "/repository", &stdout, &stderr, runner)
	if !errors.Is(err, rootFailure) {
		t.Fatalf("root failure was lost: %v", err)
	}
	if stdout.String() != "tidy diff\n" || stderr.String() != "go diagnostic\n" {
		t.Fatalf("output changed: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRepositoryUsesCanonicalModuleVerifier(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", ".."))
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	documentation, err := os.ReadFile(filepath.Join(root, "docs", "releasing.md"))
	if err != nil {
		t.Fatal(err)
	}
	canonical := "go run ./cmd/check-module-tidy"
	if strings.Count(string(workflow), canonical) != 1 {
		t.Fatalf("CI must invoke the canonical module verifier exactly once")
	}
	if strings.Count(string(documentation), canonical) != 1 {
		t.Fatalf("release documentation must name the canonical module verifier exactly once")
	}
	for name, content := range map[string][]byte{"CI workflow": workflow, "release documentation": documentation} {
		if strings.Contains(string(content), "git diff --exit-code -- go.mod") ||
			strings.Contains(string(content), "run: go mod tidy") ||
			strings.Contains(string(content), "run: GOTOOLCHAIN=local go mod tidy") {
			t.Errorf("%s contains a bypass of the canonical module verifier", name)
		}
	}
}

func TestVerifyRejectsInvalidExecutionBoundary(t *testing.T) {
	t.Parallel()
	runner := runnerFunc(func(context.Context, invocation) error {
		t.Fatal("runner called for invalid boundary")
		return nil
	})
	for name, root := range map[string]string{"empty": "", "whitespace": "   "} {
		t.Run(name, func(t *testing.T) {
			if err := verify(context.Background(), root, &bytes.Buffer{}, &bytes.Buffer{}, runner); err == nil {
				t.Fatal("invalid root accepted")
			}
		})
	}
	if err := verify(context.Background(), "/repository", nil, &bytes.Buffer{}, runner); err == nil {
		t.Fatal("nil stdout accepted")
	}
	if err := verify(context.Background(), "/repository", &bytes.Buffer{}, nil, runner); err == nil {
		t.Fatal("nil stderr accepted")
	}
}

type runnerFunc func(context.Context, invocation) error

func (run runnerFunc) run(ctx context.Context, call invocation) error { return run(ctx, call) }

func countEnvironment(environment []string, expected string) int {
	count := 0
	for _, entry := range environment {
		if entry == expected {
			count++
		}
		if strings.HasPrefix(entry, "GOTOOLCHAIN=") && entry != expected {
			return -1
		}
	}
	return count
}

func newModule(t *testing.T, goMod string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), goMod)
	writeFile(t, filepath.Join(root, "module.go"), "// SPDX-License-Identifier: AGPL-3.0-only\n\npackage module\n")
	return root
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readModuleFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		result[name] = data
	}
	return result
}

func ioWriteString(writer interface{ Write([]byte) (int, error) }, value string) (int, error) {
	return writer.Write([]byte(value))
}
