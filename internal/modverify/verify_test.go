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
	// The invariant is per lane, not per file. Counting across the whole workflow
	// encoded a single-lane CI topology and rejected any second lane that proves
	// the same module closure, which is a legitimate thing for CI to do.
	jobs := workflowJobBodies(t, string(workflow))
	proving, inJobs := 0, 0
	for _, job := range jobs {
		count := strings.Count(job.body, canonical)
		if count > 1 {
			t.Errorf("CI job %q invokes the canonical module verifier %d times; a lane proves the closure once", job.name, count)
		}
		if count == 1 {
			proving++
		}
		inJobs += count
	}
	if proving == 0 {
		t.Fatal("no CI job invokes the canonical module verifier")
	}
	if total := strings.Count(string(workflow), canonical); total != inJobs {
		t.Fatalf("CI invokes the canonical module verifier %d times but only %d inside a job", total, inJobs)
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

type workflowJob struct {
	name string
	body string
}

// workflowJobBodies splits the jobs mapping of a GitHub Actions workflow into one
// body per job. It relies only on the two-space job indentation the repository's
// workflows use, which the CI contract already depends on elsewhere.
func workflowJobBodies(t *testing.T, workflow string) []workflowJob {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(workflow, "\r\n", "\n"), "\n")
	start := -1
	for index, line := range lines {
		if line == "jobs:" {
			if start >= 0 {
				t.Fatal("workflow declares jobs twice")
			}
			start = index
		}
	}
	if start < 0 {
		t.Fatal("workflow declares no jobs")
	}
	var jobs []workflowJob
	for index := start + 1; index < len(lines); index++ {
		line := lines[index]
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			break
		}
		if indent != 2 || !strings.HasSuffix(strings.TrimSpace(line), ":") {
			if len(jobs) > 0 {
				jobs[len(jobs)-1].body += line + "\n"
			}
			continue
		}
		jobs = append(jobs, workflowJob{name: strings.TrimSuffix(strings.TrimSpace(line), ":")})
	}
	if len(jobs) == 0 {
		t.Fatal("workflow jobs mapping is empty")
	}
	return jobs
}

func TestCanonicalModuleVerifierInvariantIsPerLane(t *testing.T) {
	t.Parallel()
	canonical := "go run ./cmd/check-module-tidy"
	workflow := func(test, security string) string {
		return "name: CI\n\non:\n  pull_request:\n\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" + test + "  govulncheck:\n    runs-on: ubuntu-latest\n    steps:\n" + security
	}
	once := "      - run: " + canonical + "\n"
	other := "      - run: go vet ./...\n"

	single := workflowJobBodies(t, workflow(once, other))
	if len(single) != 2 {
		t.Fatalf("jobs=%d", len(single))
	}
	counts := map[string]int{}
	for _, job := range single {
		counts[job.name] = strings.Count(job.body, canonical)
	}
	if counts["test"] != 1 || counts["govulncheck"] != 0 {
		t.Fatalf("single-lane counts=%v", counts)
	}

	// A second lane proving the same closure is legitimate; the previous
	// whole-file count rejected it and blocked the Go 1.25 migration.
	both := workflowJobBodies(t, workflow(once, once))
	for _, job := range both {
		if got := strings.Count(job.body, canonical); got != 1 {
			t.Fatalf("job %q counted %d, want 1 per lane", job.name, got)
		}
	}

	// Two invocations inside one lane remain a contract violation.
	duplicated := workflowJobBodies(t, workflow(once+once, other))
	for _, job := range duplicated {
		if job.name == "test" && strings.Count(job.body, canonical) != 2 {
			t.Fatalf("duplicate within a lane was not observed: %q", job.body)
		}
	}
}
