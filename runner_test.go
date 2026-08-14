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

// TestResolutionFollowsLookupEnv closes the gap issue #46 reported. LookupEnv is
// the Runner's single source of environment values, but resolution used to read
// the process PATH through exec.Command, so an embedder that supplied a PATH got
// a binary the host chose. The manifest and the embedder now decide together.
func TestResolutionFollowsLookupEnv(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "be useful")
	w, _ := OpenWorkspace(root)

	bin := t.TempDir()
	tool := filepath.Join(bin, "probe-tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nprintf accepted\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := func(command string) TaskManifest {
		m := testManifest(os.Args[0], "echo")
		m.Command = []string{command}
		m.Acceptance = TaskAcceptance{ExitCodes: []int{0}}
		return m
	}

	t.Run("an empty search path finds nothing", func(t *testing.T) {
		empty := t.TempDir()
		result, err := (Runner{Workspace: w, LookupEnv: func(key string) (string, bool) {
			if key == "PATH" {
				return empty, true
			}
			return "", false
		}}).Run(context.Background(), manifest("probe-tool"))
		if err == nil {
			t.Fatal("resolution ignored the supplied PATH")
		}
		if !strings.Contains(err.Error(), "executable file not found") || result.ExitCode != -1 || result.ExecutablePath != "" {
			t.Fatalf("unexpected failure shape: %#v / %v", result, err)
		}
	})

	t.Run("the supplied search path decides", func(t *testing.T) {
		result, err := (Runner{Workspace: w, LookupEnv: func(key string) (string, bool) {
			if key == "PATH" {
				return bin, true
			}
			return "", false
		}}).Run(context.Background(), manifest("probe-tool"))
		if err != nil {
			t.Fatalf("run: %v (%#v)", err, result)
		}
		if result.ExecutablePath != tool {
			t.Fatalf("executable path = %q, want %q", result.ExecutablePath, tool)
		}
	})

	t.Run("relative and empty entries are skipped", func(t *testing.T) {
		for _, search := range []string{"", ":", "relative/bin", "." + string(os.PathListSeparator) + "also/relative"} {
			_, err := (Runner{Workspace: w, LookupEnv: func(key string) (string, bool) {
				if key == "PATH" {
					return search, true
				}
				return "", false
			}}).Run(context.Background(), manifest("probe-tool"))
			if err == nil {
				t.Fatalf("PATH %q resolved against the runtime working directory", search)
			}
		}
	})
}
