// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
)

func cancellationManifest(t *testing.T) (agentruntime.Workspace, agentruntime.TaskManifest) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "instructions.md"), []byte("context\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := agentruntime.OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	return workspace, agentruntime.TaskManifest{
		SchemaVersion: agentruntime.TaskSchemaVersion, ID: "task-1",
		Instructions: []string{"instructions.md"},
		Command:      []string{"sh", "-c", "cat >/dev/null; sleep 60"},
		Acceptance:   agentruntime.TaskAcceptance{ExitCodes: []int{0}},
		Timeout:      agentruntime.Duration{Duration: time.Hour},
		MaxOutput:    1024, MaxContext: 1024,
	}
}

// A cancelled run is the case where the terminal observation matters most, so it
// must be delivered rather than dropped along with the context that cancelled it.
func TestTerminalTaskEventSurvivesCallerCancellation(t *testing.T) {
	workspace, manifest := cancellationManifest(t)
	sink, err := NewMemorySink("memory", 16)
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{sink}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	run := TaskRunner{Runner: agentruntime.Runner{Workspace: workspace}, Emitter: emitter, Context: lifecycleContext()}.Run(ctx, manifest)

	if !run.Result.Cancelled || run.Result.TimedOut {
		t.Fatalf("result did not attribute the termination to the caller: %#v", run.Result)
	}
	if len(run.Events) != 3 {
		t.Fatalf("events=%d, want validated, started and a terminal event", len(run.Events))
	}
	terminal := run.Events[len(run.Events)-1]
	if terminal.Kind() != TaskFailed {
		t.Fatalf("terminal kind=%s", terminal.Kind())
	}
	report := run.Delivery[len(run.Delivery)-1]
	if !report.Succeeded() {
		t.Fatalf("terminal observation was dropped with the cancelled context: %#v", report)
	}
	if len(sink.Snapshot()) != 3 {
		t.Fatalf("sink recorded %d events", len(sink.Snapshot()))
	}
}

func TestCancelledTaskCarriesCancellationErrorEvidence(t *testing.T) {
	workspace, manifest := cancellationManifest(t)
	sink, err := NewMemorySink("memory", 16)
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{sink}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	run := TaskRunner{Runner: agentruntime.Runner{Workspace: workspace}, Emitter: emitter, Context: lifecycleContext()}.Run(ctx, manifest)

	terminal := run.Events[len(run.Events)-1]
	data, err := terminal.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"code":"cancelled"`, `"class":"cancellation"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("terminal event lacks %s: %s", want, data)
		}
	}
}
