// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

func TestTaskCLIEndToEnd(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("instruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version":"v1alpha1","id":"cli-test","instructions":["AGENTS.md"],"command":["cat"],"acceptance":{"exit_codes":[0],"output_contains":["instruction"]},"env":["PATH"]}`
	path := filepath.Join(root, "task.json")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"task", "validate", "--manifest", path, "--workspace", root}, &stdout, &stderr); err != nil {
		t.Fatalf("validate: %v stderr=%s", err, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"task", "run", "--manifest", path, "--workspace", root}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"agent_id":"cli-test"`) || !strings.Contains(stdout.String(), "instruction") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestGoalCLIRestartAndCompletionGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goal.json")
	var out, stderr bytes.Buffer
	args := []string{"goal", "init", "--journal", path, "--id", "cli-goal", "--intent", "prove durable workflow", "--acceptance", "done=all phases pass"}
	if err := run(args, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	var created goalpkg.Journal
	if err := json.Unmarshal(out.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"goal", "status", "--journal", path}, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	var restored goalpkg.Journal
	if err := json.Unmarshal(out.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Revision != created.Revision || restored.Goal.ID != "cli-goal" {
		t.Fatalf("restored=%#v", restored)
	}
	out.Reset()
	err := run([]string{"goal", "advance", "--journal", path, "--revision", "1", "--phase", "closure", "--summary", "shortcut", "--evidence-type", "test", "--evidence-ref", "one check", "--evidence-result", "passed", "--outcome", "done", "--cleanup", "none", "--no-remaining", "--next-type", "file", "--next-ref", "ROADMAP.md", "--next-result", "tracked"}, &out, &stderr)
	if !goalpkg.IsCode(err, goalpkg.CodeInvalidTransition) {
		t.Fatalf("shortcut error=%v", err)
	}
}
