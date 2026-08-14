// SPDX-License-Identifier: AGPL-3.0-only

package actions_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NDDev-it-com/agent-runtime/internal/cicontract"
	"github.com/NDDev-it-com/agent-runtime/internal/governance"
	"github.com/NDDev-it-com/agent-runtime/internal/releasecontract"
)

// The mutations here all preserve the text a contract used to look for and
// remove the execution it stands for. Every one of them passed all three
// checkers before the workflow model existed, which is the defect this file
// exists to keep closed: a required check that stays green while the property
// it is named after is gone is worse than no check at all.
//
// The suite that shipped before only ever deleted or renamed a token. Deleting
// is the easy half; relocating is the half that was exploitable.

func read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func relocate(t *testing.T, workflow, old, replacement string) string {
	t.Helper()
	out := strings.Replace(workflow, old, replacement, 1)
	if out == workflow {
		t.Fatalf("mutation is stale: %q no longer appears in the workflow", old)
	}
	return out
}

// verifyCI runs the checker that guards the CI lane.
func verifyCI(t *testing.T, workflow string) error {
	t.Helper()
	contract, err := cicontract.Load(filepath.Join("..", "..", "security-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	return cicontract.VerifyWorkflow(contract, []byte(workflow))
}

func verifyRelease(t *testing.T, workflow string) error {
	t.Helper()
	contract, err := releasecontract.Load(filepath.Join("..", "..", "release", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return contract.VerifyWorkflow([]byte(workflow))
}

func verifyGovernance(t *testing.T, workflow string) error {
	t.Helper()
	contract, err := governance.Load(filepath.Join("..", "..", "governance", "main-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return governance.VerifyCIWorkflow(contract, []byte(workflow))
}

// TestCanonicalWorkflowsAreAccepted anchors the negatives below: if the real
// workflows stopped passing, every rejection here would be meaningless.
func TestCanonicalWorkflowsAreAccepted(t *testing.T) {
	t.Parallel()
	ci, release := read(t, "ci.yml"), read(t, "release.yml")
	if err := verifyCI(t, ci); err != nil {
		t.Errorf("ci contract: %v", err)
	}
	if err := verifyGovernance(t, ci); err != nil {
		t.Errorf("governance: %v", err)
	}
	if err := verifyRelease(t, release); err != nil {
		t.Errorf("release contract: %v", err)
	}
}

func TestControlsMovedOutOfExecutionAreRejected(t *testing.T) {
	t.Parallel()
	ci := read(t, "ci.yml")
	for name, test := range map[string]struct {
		workflow string
		verify   func(*testing.T, string) error
	}{
		// The recorded reproduction: the gate is gone, the token survives.
		"fuzz gate commented out": {
			relocate(t, ci,
				"      - name: Run every contracted fuzz target independently\n        run: go run ./cmd/check-fuzz\n",
				"      # Temporarily disabled:\n      #   run: go run ./cmd/check-fuzz\n"),
			verifyCI,
		},
		// A step name is displayed, never executed.
		"fuzz gate demoted to a step name": {
			relocate(t, ci,
				"      - name: Run every contracted fuzz target independently\n        run: go run ./cmd/check-fuzz\n",
				"      - name: \"go run ./cmd/check-fuzz\"\n        run: \"true\"\n"),
			verifyCI,
		},
		// A disabled job's steps never run, whatever they say.
		"scanner lane disabled by condition": {
			relocate(t, ci, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  govulncheck:\n    if: false\n    runs-on: ubuntu-latest\n"),
			verifyCI,
		},
		"test lane disabled by condition": {
			relocate(t, ci, "  test:\n    strategy:\n", "  test:\n    if: false\n    strategy:\n"),
			verifyCI,
		},
		// The reproduction sequence only proves determinism if it is one script.
		"reproduction split across steps": {
			relocate(t, ci,
				"          go run ./cmd/check-release-contract --out \"$first\" --verify-result \"$first_result\"\n",
				"      - name: Second half\n        run: |\n          go run ./cmd/check-release-contract --out \"$first\" --verify-result \"$first_result\"\n"),
			verifyCI,
		},
		// A renamed job stops producing the required context.
		"required job renamed": {
			relocate(t, ci, "\n  test:\n", "\n  tests:\n"),
			verifyGovernance,
		},
		// The context name carries the lane, so dropping it retires the check.
		"matrix lane dropped": {
			relocate(t, ci, "os: [ubuntu-latest, macos-latest]", "os: [ubuntu-latest]"),
			verifyGovernance,
		},
		// An override detaches the check-run from the required context name.
		"required job renames its check": {
			relocate(t, ci, "  test:\n    strategy:\n", "  test:\n    name: Verify\n    strategy:\n"),
			verifyGovernance,
		},
		// A path filter makes a required check silently skip the diff.
		"path filter on the pull_request trigger": {
			relocate(t, ci, "on:\n  pull_request:\n", "on:\n  pull_request:\n    paths: ['**.go']\n"),
			verifyGovernance,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := test.verify(t, test.workflow); err == nil {
				t.Fatal("mutation accepted: the control is gone and the checker stayed green")
			}
		})
	}
}

func TestReleaseControlsMovedOutOfExecutionAreRejected(t *testing.T) {
	t.Parallel()
	release := read(t, "release.yml")
	identityStep := "      - name: Verify immutable signed exact-main release identity\n"
	for name, workflow := range map[string]string{
		// The recorded reproduction: the whole signature, provenance and
		// exact-main gate becomes a comment block and the file still parses as
		// a workflow GitHub would happily run.
		"identity gate commented out": commentOutStep(t, release, identityStep),
		// Disabling the only job disables everything in it.
		"release job disabled": relocate(t, release, "    if: github.run_attempt == 1\n", "    if: false\n"),
		// Write scope at workflow level applies to every job ever added.
		"write permission relocated to workflow scope": relocate(t, release,
			"permissions:\n  contents: read\n",
			"permissions:\n  contents: write\n  id-token: write\n  attestations: write\n  artifact-metadata: write\n"),
		// A blanket grant is not an enumeration.
		"permissions granted as a blanket scalar": relocate(t, release,
			"    permissions:\n      contents: write\n      id-token: write\n      attestations: write\n      artifact-metadata: write\n",
			"    permissions: write-all\n"),
		// Publication must be reachable only from a version tag.
		"reachable from a branch push": relocate(t, release, "    tags: ['v*.*.*']\n", "    tags: ['v*.*.*']\n    branches: [main]\n"),
		"reachable by hand":            relocate(t, release, "on:\n  push:\n", "on:\n  workflow_dispatch:\n  push:\n"),
		// The checkout must not leave a usable credential for later steps.
		"checkout keeps its credential": relocate(t, release, "          persist-credentials: false\n", "          persist-credentials: true\n"),
		// The signature check demoted to prose.
		"signature check demoted to a step name": relocate(t, release,
			"          go run ./cmd/check-signature --tag \"$tag_object\" --expected-commit \"$tag_commit\"\n",
			"          true # go run ./cmd/check-signature --tag \"$tag_object\" --expected-commit \"$tag_commit\"\n"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := verifyRelease(t, workflow); err == nil {
				t.Fatal("mutation accepted: the control is gone and the checker stayed green")
			}
		})
	}
}

// commentOutStep turns one whole step into comments, preserving every token it
// contained. This is the exact shape of the reproduction recorded against the
// text-matching checkers.
func commentOutStep(t *testing.T, workflow, header string) string {
	t.Helper()
	start := strings.Index(workflow, header)
	if start < 0 {
		t.Fatalf("mutation is stale: step header %q not found", header)
	}
	rest := workflow[start+len(header):]
	end := len(rest)
	for _, boundary := range []string{"      - name:", "      - uses:", "      - run:"} {
		if index := strings.Index(rest, boundary); index >= 0 && index < end {
			end = index
		}
	}
	body := header + rest[:end]
	var commented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		commented.WriteString("      # " + strings.TrimSpace(line) + "\n")
	}
	return workflow[:start] + commented.String() + rest[end:]
}

// TestAmbiguousWorkflowsAreRejected covers YAML that can express one value in
// two places. The model refuses to interpret it rather than guessing, because a
// guess is how a control ends up "present" at a location that never runs.
func TestAmbiguousWorkflowsAreRejected(t *testing.T) {
	t.Parallel()
	ci := read(t, "ci.yml")
	for name, test := range map[string]struct {
		workflow string
		want     string
	}{
		"anchor and alias": {
			relocate(t, ci, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  govulncheck: &scanner\n    runs-on: ubuntu-latest\n") +
				"\n  scanner-copy: *scanner\n",
			"anchors and aliases",
		},
		"duplicate job key": {
			ci + "\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'true'\n",
			"already defined",
		},
		"duplicate step key": {
			relocate(t, ci, "      - run: go vet ./...\n", "      - run: go vet ./...\n        run: 'true'\n"),
			"already defined",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := verifyCI(t, test.workflow)
			if err == nil {
				t.Fatal("ambiguous workflow accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want it to mention %q", err, test.want)
			}
		})
	}
}
