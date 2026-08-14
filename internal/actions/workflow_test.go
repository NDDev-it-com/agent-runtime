// SPDX-License-Identifier: AGPL-3.0-only

package actions

import (
	"strings"
	"testing"
)

const minimal = `name: probe
on:
  pull_request:
  push:
    branches: [main]
env:
  GOTOOLCHAIN: local
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Do the thing
        run: go test ./...
      - name: Skipped
        if: false
        run: go run ./cmd/never
  disabled:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: go run ./cmd/never
`

func parse(t *testing.T, source string) *Workflow {
	t.Helper()
	w, err := Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestModelsTriggersJobsAndSteps(t *testing.T) {
	t.Parallel()
	w := parse(t, minimal)
	if !w.Triggers["pull_request"].Present {
		t.Error("a trigger declared with no filters must still be present")
	}
	if w.Triggers["nope"].Present {
		t.Error("an absent trigger must not be present")
	}
	if got := w.Triggers["push"].Branches; len(got) != 1 || got[0] != "main" {
		t.Errorf("push branches=%v", got)
	}
	if w.Env["GOTOOLCHAIN"] != "local" {
		t.Errorf("env=%v", w.Env)
	}
	if len(w.JobOrder) != 2 || w.JobOrder[0] != "test" {
		t.Errorf("job order=%v, must follow the file", w.JobOrder)
	}
	if enabled := w.EnabledJobs(); len(enabled) != 1 || enabled[0].ID != "test" {
		t.Errorf("enabled jobs=%v, a job with if:false does not run", enabled)
	}
	if _, err := w.Job("disabled"); err == nil {
		t.Error("a disabled job must not be returned as evidence")
	}
	job, err := w.Job("test")
	if err != nil {
		t.Fatal(err)
	}
	if got := job.Matrix["os"]; len(got) != 2 || got[1] != "macos-latest" {
		t.Errorf("matrix os=%v", got)
	}
	// The skipped step's command must not count anywhere.
	if n := w.CountRunOccurrences("go run ./cmd/never"); n != 0 {
		t.Errorf("disabled steps and jobs contributed %d occurrences", n)
	}
	if n := job.CountRunOccurrences("go test ./..."); n != 1 {
		t.Errorf("executed command counted %d times", n)
	}
	step, ok := job.StepUsing("actions/checkout@")
	if !ok || step.With["persist-credentials"] != "false" {
		t.Errorf("checkout step=%v ok=%v; non-string inputs must render as text", step.With, ok)
	}
	if step.With["fetch-depth"] != "0" {
		t.Errorf("numeric input rendered as %q", step.With["fetch-depth"])
	}
}

func TestCommentsAreNotEvidence(t *testing.T) {
	t.Parallel()
	source := strings.Replace(minimal,
		"      - name: Do the thing\n        run: go test ./...\n",
		"      # - run: go test ./...\n", 1)
	w := parse(t, source)
	if n := w.CountRunOccurrences("go test ./..."); n != 0 {
		t.Fatalf("a YAML comment counted as %d executed occurrences", n)
	}
}

func TestShellCommentsAreNotEvidence(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		script string
		want   int
	}{
		"plain comment":            {"# go test ./...\ntrue\n", 0},
		"trailing comment":         {"true # go test ./...\n", 0},
		"executed then commented":  {"go test ./...\n# go test ./...\n", 1},
		"hash inside single quote": {"echo 'go test ./... # not a comment'\n", 1},
		"hash inside double quote": {"echo \"go test ./... # not a comment\"\n", 1},
		"hash without whitespace":  {"echo x#go test ./...\n", 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			job := &Job{Steps: []Step{{Run: test.script}}}
			if got := job.CountRunOccurrences("go test ./..."); got != test.want {
				t.Fatalf("counted %d, want %d, in %q -> %q", got, test.want, test.script, executableScript(test.script))
			}
		})
	}
}

func TestRejectsAmbiguousDocuments(t *testing.T) {
	t.Parallel()
	for name, source := range map[string]string{
		"anchor":         strings.Replace(minimal, "  test:\n", "  test: &anchor\n", 1),
		"duplicate key":  minimal + "  test:\n    runs-on: ubuntu-latest\n",
		"two documents":  minimal + "---\nname: second\n",
		"not a mapping":  "- one\n- two\n",
		"no jobs at all": "name: probe\non:\n  push:\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(source)); err == nil {
				t.Fatal("ambiguous or unmodellable document accepted")
			}
		})
	}
}

func TestBlanketPermissionsAreModelledNotHidden(t *testing.T) {
	t.Parallel()
	w := parse(t, strings.Replace(minimal, "  test:\n", "  test:\n    permissions: write-all\n", 1))
	job := w.Jobs["test"]
	if job.PermissionsBlanket != "write-all" || !job.PermissionsSet {
		t.Fatalf("blanket=%q set=%v; a scalar grant must be visible to a contract", job.PermissionsBlanket, job.PermissionsSet)
	}
}
