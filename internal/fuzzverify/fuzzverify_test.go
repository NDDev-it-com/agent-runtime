// SPDX-License-Identifier: AGPL-3.0-only

package fuzzverify

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

func TestCanonicalInventoryMatchesEveryRepositoryTarget(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	contract, err := Load(filepath.Join(root, "fuzz", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(discovered, contract.Targets) {
		t.Fatalf("inventory drift: discovered=%v contract=%v", discovered, contract.Targets)
	}
}

func TestVerifyConstructsOneBoundedInvocationPerExactTarget(t *testing.T) {
	t.Parallel()
	contract := testContract()
	root := testModule(t, contract.Targets)
	var calls []invocation
	runner := runnerFunc(func(_ context.Context, call invocation) error { calls = append(calls, call); return nil })
	var stdout, stderr bytes.Buffer
	if err := verify(context.Background(), root, contract, &stdout, &stderr, runner); err != nil {
		t.Fatal(err)
	}
	if len(calls) != len(contract.Targets) {
		t.Fatalf("calls=%d targets=%d", len(calls), len(contract.Targets))
	}
	for index, target := range contract.Targets {
		want := []string{"test", target.Package, "-run=^$", "-fuzz=^" + target.Name + "$", "-fuzztime=100x", "-fuzzminimizetime=10x", "-parallel=1", "-timeout=2m"}
		if calls[index].path != "go" || !reflect.DeepEqual(calls[index].args, want) || calls[index].dir != root {
			t.Fatalf("call %d=%#v", index, calls[index])
		}
		if calls[index].stdout != &stdout || calls[index].stderr != &stderr || count(calls[index].env, "GOTOOLCHAIN=local") != 1 {
			t.Fatalf("call %d lost output or environment boundary", index)
		}
	}
}

func TestVerifyFailsClosedOnInventoryAndExecutionDrift(t *testing.T) {
	t.Parallel()
	canonical := testContract()
	for name, mutate := range map[string]func(*Contract){
		"missing": func(value *Contract) { value.Targets = value.Targets[:1] },
		"unexpected": func(value *Contract) {
			value.Targets = append(value.Targets, Target{Package: value.Targets[1].Package, Name: "FuzzUnexpected"})
		},
		"duplicate": func(value *Contract) { value.Targets[1] = value.Targets[0] },
		"unsorted":  func(value *Contract) { value.Targets[0], value.Targets[1] = value.Targets[1], value.Targets[0] },
		"unbounded": func(value *Contract) { value.FuzzTime = "1h" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := canonical
			candidate.Targets = append([]Target(nil), canonical.Targets...)
			mutate(&candidate)
			if reflect.DeepEqual(candidate, canonical) {
				t.Fatal("negative fixture did not change")
			}
			root := testModule(t, canonical.Targets)
			if err := verify(context.Background(), root, candidate, &bytes.Buffer{}, &bytes.Buffer{}, runnerFunc(func(context.Context, invocation) error { t.Fatal("runner called"); return nil })); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}

	rootFailure := errors.New("fuzz process failed")
	root := testModule(t, canonical.Targets)
	var stdout, stderr bytes.Buffer
	err := verify(context.Background(), root, canonical, &stdout, &stderr, runnerFunc(func(_ context.Context, call invocation) error {
		_, _ = call.stdout.Write([]byte("fuzz stdout\n"))
		_, _ = call.stderr.Write([]byte("fuzz stderr\n"))
		return rootFailure
	}))
	if !errors.Is(err, rootFailure) || stdout.String() != "fuzz stdout\n" || stderr.String() != "fuzz stderr\n" {
		t.Fatalf("failure/output lost: err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}

func TestVerifyRejectsOversizedOrUnsafeCorpus(t *testing.T) {
	t.Parallel()
	contract := testContract()
	for name, create := range map[string]func(*testing.T, string){
		"oversized": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "seed"), make([]byte, contract.MaxCorpusBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"nested": func(t *testing.T, directory string) {
			if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		name, create := name, create
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := testModule(t, contract.Targets)
			directory := filepath.Join(root, "testdata", "fuzz", contract.Targets[0].Name)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			create(t, directory)
			if err := verify(context.Background(), root, contract, &bytes.Buffer{}, &bytes.Buffer{}, runnerFunc(func(context.Context, invocation) error { t.Fatal("runner called"); return nil })); err == nil {
				t.Fatal("unsafe corpus accepted")
			}
		})
	}
}

func TestRepositorySurfacesUseOnlyCanonicalFuzzVerifier(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	canonical := "go run ./cmd/check-fuzz"
	for _, path := range []string{filepath.Join(root, ".github", "workflows", "ci.yml"), filepath.Join(root, "docs", "releasing.md"), filepath.Join(root, "CONTRIBUTING.md"), filepath.Join(root, "README.md")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), canonical) != 1 {
			t.Errorf("%s must invoke the canonical fuzz verifier exactly once", path)
		}
		if strings.Contains(string(data), "-fuzz=") {
			t.Errorf("%s contains a direct fuzz invocation", path)
		}
	}
}

type runnerFunc func(context.Context, invocation) error

func (run runnerFunc) run(ctx context.Context, call invocation) error { return run(ctx, call) }

func testContract() Contract {
	return Contract{SchemaVersion: SchemaVersion, FuzzTime: "100x", FuzzMinimizeTime: "10x", Parallel: 1, Timeout: "2m", MaxCorpusFiles: 256, MaxCorpusBytes: 1 << 20, Targets: []Target{{Package: "github.com/NDDev-it-com/agent-runtime", Name: "FuzzAlpha"}, {Package: "github.com/NDDev-it-com/agent-runtime/sub", Name: "FuzzBeta"}}}
}

func testModule(t *testing.T, targets []Target) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/NDDev-it-com/agent-runtime\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		relative := strings.TrimPrefix(target.Package, "github.com/NDDev-it-com/agent-runtime")
		directory := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(relative, "/")))
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, strings.ToLower(target.Name)+"_test.go")
		content := "// SPDX-License-Identifier: AGPL-3.0-only\n\npackage fixture\n\nimport \"testing\"\n\nfunc " + target.Name + "(f *testing.F) {}\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func count(environment []string, expected string) int {
	total := 0
	for _, entry := range environment {
		if entry == expected {
			total++
		}
	}
	return total
}
