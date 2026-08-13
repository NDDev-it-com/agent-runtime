// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"context"
	"fmt"
	"io"
	"os"
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
