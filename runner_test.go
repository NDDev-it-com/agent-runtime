// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunnerSuccessAndEnvironmentAllowlist(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "be useful")
	m := testManifest(os.Args[0], "echo")
	m.Env = []string{"ALLOWED", "GO_WANT_HELPER_PROCESS"}
	w, _ := OpenWorkspace(root)
	result, err := (Runner{Workspace: w, LookupEnv: func(key string) (string, bool) {
		values := map[string]string{"ALLOWED": "yes", "SECRET": "no", "GO_WANT_HELPER_PROCESS": "1"}
		value, ok := values[key]
		return value, ok
	}}).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Output, "context=35 allowed=yes secret=\n") || result.ExitCode != 0 {
		t.Fatalf("result: %#v", result)
	}
}

func TestRunnerFailureAndTruncation(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "x")
	m := testManifest(os.Args[0], "fail")
	m.MaxOutput = 4
	w, _ := OpenWorkspace(root)
	result, err := (Runner{Workspace: w}).Run(context.Background(), m)
	if err == nil || result.ExitCode != 7 || !result.Truncated || result.Output != "fail" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRunnerTimeout(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "x")
	m := testManifest(os.Args[0], "sleep")
	m.Timeout = Duration{20 * time.Millisecond}
	w, _ := OpenWorkspace(root)
	result, err := (Runner{Workspace: w}).Run(context.Background(), m)
	if err == nil || !result.TimedOut {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func testManifest(executable, action string) TaskManifest {
	return TaskManifest{SchemaVersion: TaskSchemaVersion, ID: "test-agent", Instructions: []string{"instructions.md"}, Command: []string{executable, "-test.run=TestHelperProcess", "--", action}, Acceptance: TaskAcceptance{ExitCodes: []int{0}}, Env: []string{"GO_WANT_HELPER_PROCESS"}, Timeout: Duration{10 * time.Second}, MaxOutput: 1024, MaxContext: 1024}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	action := os.Args[len(os.Args)-1]
	switch action {
	case "echo":
		data, _ := io.ReadAll(os.Stdin)
		fmt.Printf("context=%d allowed=%s secret=%s\n", len(data), os.Getenv("ALLOWED"), os.Getenv("SECRET"))
	case "fail":
		fmt.Print("failure output")
		os.Exit(7)
	case "sleep":
		time.Sleep(time.Second)
	}
	os.Exit(0)
}

// TestResultRecordsTheExecutableItRan pins the evidence a run used to discard.
// A bare command name is resolved through the caller's PATH, so the manifest
// does not decide which binary runs (issue #46); recording the resolved path is
// what makes that choice auditable after the fact.
func TestResultRecordsTheExecutableItRan(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "be useful")
	w, _ := OpenWorkspace(root)

	t.Run("path is passed through", func(t *testing.T) {
		m := testManifest(os.Args[0], "echo")
		m.Env = []string{"GO_WANT_HELPER_PROCESS"}
		result, err := (Runner{Workspace: w, LookupEnv: func(string) (string, bool) { return "1", true }}).Run(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		if result.ExecutablePath != os.Args[0] {
			t.Fatalf("executable path = %q, want %q", result.ExecutablePath, os.Args[0])
		}
	})

	t.Run("bare name records its absolute resolution", func(t *testing.T) {
		want, lookErr := exec.LookPath("true")
		if lookErr != nil {
			t.Skip("no true(1) on this host")
		}
		m := testManifest(os.Args[0], "echo")
		m.Command = []string{"true"}
		result, err := (Runner{Workspace: w}).Run(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		if result.ExecutablePath != want {
			t.Fatalf("executable path = %q, want %q", result.ExecutablePath, want)
		}
		if !filepath.IsAbs(result.ExecutablePath) {
			t.Fatalf("executable path %q is not absolute", result.ExecutablePath)
		}
	})

	t.Run("unresolvable name keeps the previous failure", func(t *testing.T) {
		m := testManifest(os.Args[0], "echo")
		m.Command = []string{"definitely-not-a-real-binary-xyz"}
		result, err := (Runner{Workspace: w}).Run(context.Background(), m)
		if err == nil {
			t.Fatal("unresolvable command did not fail")
		}
		if result.ExecutablePath != "" {
			t.Fatalf("executable path = %q, want empty for an unresolved name", result.ExecutablePath)
		}
		if result.ExitCode != -1 || result.AgentID != m.ID {
			t.Fatalf("failure shape changed: %#v", result)
		}
		if !strings.Contains(err.Error(), "executable file not found") {
			t.Fatalf("error changed: %v", err)
		}
	})
}
