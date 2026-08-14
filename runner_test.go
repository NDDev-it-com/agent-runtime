// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

// TestOutputBoundSurvivesUTF8Repair covers a bound that held on the way in and
// not on the way out. Raw bytes were capped at max_output_bytes, then String
// replaced each isolated invalid byte with a three-byte replacement rune, so a
// twelve-byte budget returned twenty-four bytes into Result.Output, its JSON
// encoding and every downstream event.
func TestOutputBoundSurvivesUTF8Repair(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		limit int64
		raw   []byte
	}{
		"alternating invalid bytes": {12, []byte{0xff, 'a', 0xff, 'b', 0xff, 'c', 0xff, 'd', 0xff, 'e', 0xff, 'f'}},
		"all invalid":               {8, []byte{0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe, 0xff, 0xfe}},
		"one invalid at the edge":   {4, []byte{'a', 'b', 'c', 0xff}},
		"valid multi-byte runes":    {9, []byte("日本語")},
		"valid ascii":               {5, []byte("hello")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := &boundedBuffer{limit: test.limit}
			if _, err := b.Write(test.raw); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			if int64(len(out)) > test.limit {
				t.Fatalf("returned %d bytes for a %d-byte budget", len(out), test.limit)
			}
			if !utf8.ValidString(out) {
				t.Fatalf("returned invalid UTF-8: %q", out)
			}
		})
	}
}

// TestTerminationAttributesTheRealCause covers the window where a process that
// had already failed on its own was reported as ended by its caller. The
// context alone cannot tell the two apart: it says only that cancellation
// happened, not that it caused anything.
func TestTerminationAttributesTheRealCause(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "be useful")
	workspace, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	failing := testManifest("/bin/sh", "")
	failing.Command = []string{"/bin/sh", "-c", "exit 3"}
	failing.Acceptance = TaskAcceptance{ExitCodes: []int{0}}
	failing.Timeout = Duration{Duration: 30 * time.Second}
	runner := Runner{Workspace: workspace}

	// Sweep the cancellation across the whole tail of the run so it lands
	// before, during and after the child's own exit.
	const attempts = 300
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		delay := time.Duration(500+(i%300)*10) * time.Microsecond
		go func() { time.Sleep(delay); cancel() }()
		result, _ := runner.Run(ctx, failing)
		cancel()
		if result.ExitCode == 3 && result.Cancelled {
			t.Fatalf("a process that exited 3 on its own was attributed to the caller (attempt %d, cancel after %v)", i, delay)
		}
	}

	// The two real terminations must still be told apart from each other.
	blocking := failing
	blocking.Command = []string{"/bin/sh", "-c", "sleep 30"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	cancelled, _ := runner.Run(ctx, blocking)
	cancel()
	if !cancelled.Cancelled || cancelled.TimedOut {
		t.Errorf("a caller cancellation reported cancelled=%v timed_out=%v", cancelled.Cancelled, cancelled.TimedOut)
	}
	blocking.Timeout = Duration{Duration: 150 * time.Millisecond}
	timedOut, _ := runner.Run(context.Background(), blocking)
	if !timedOut.TimedOut || timedOut.Cancelled {
		t.Errorf("a manifest timeout reported cancelled=%v timed_out=%v", timedOut.Cancelled, timedOut.TimedOut)
	}
}

// TestTerminationOwnsTheProcessTree covers descendants outliving the terminal
// result. A Task that backgrounded work kept touching the workspace after the
// Runner had returned a timeout and observability had recorded the run as over.
func TestTerminationOwnsTheProcessTree(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("process-group ownership is implemented for Linux and macOS, not %s", runtime.GOOS)
	}
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "be useful")
	workspace, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "descendant-was-here")
	manifest := testManifest("/bin/sh", "")
	manifest.Command = []string{"/bin/sh", "-c", "(sleep 3; echo alive > '" + marker + "') >/dev/null 2>&1 & sleep 30"}
	manifest.Acceptance = TaskAcceptance{ExitCodes: []int{0}}
	manifest.Timeout = Duration{Duration: 300 * time.Millisecond}

	started := time.Now()
	result, _ := Runner{Workspace: workspace}.Run(context.Background(), manifest)
	elapsed := time.Since(started)
	if !result.TimedOut {
		t.Fatalf("the run did not time out: %#v", result)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the descendant had already written before the terminal result; the case proves nothing")
	}
	// The bound is the timeout plus the termination grace, and owning the group
	// means the pipes close at once rather than being held for the full grace.
	if elapsed > manifest.Timeout.Duration+terminationGrace {
		t.Errorf("returned after %v, beyond the %v ceiling", elapsed, manifest.Timeout.Duration+terminationGrace)
	}
	time.Sleep(4 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a descendant wrote into the workspace after the terminal result")
	}
}
