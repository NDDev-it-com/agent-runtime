// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

type failedSink struct{}

func (f failedSink) Name() string { return "failed" }
func (f failedSink) Write(context.Context, Envelope) (WriteResult, error) {
	return WriteResult{}, &SinkError{Code: SinkUnavailable, Retryable: true}
}
func (f failedSink) Flush(context.Context) error { return nil }
func (f failedSink) Close(context.Context) error { return nil }

func TestTaskRunnerPreservesExecutionAndReportsTelemetryFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "instructions.md"), []byte("context"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := agentruntime.OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := agentruntime.TaskManifest{SchemaVersion: agentruntime.TaskSchemaVersion, ID: "task-1", Instructions: []string{"instructions.md"}, Command: []string{"sh", "-c", "cat >/dev/null; printf accepted"}, Acceptance: agentruntime.TaskAcceptance{ExitCodes: []int{0}, OutputContains: []string{"accepted"}}, Timeout: agentruntime.Duration{Duration: time.Second}, MaxOutput: 1024, MaxContext: 1024}
	emitter, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{failedSink{}}, Options{MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	runner := TaskRunner{Runner: agentruntime.Runner{Workspace: workspace}, Emitter: emitter, Context: lifecycleContext()}
	run := runner.Run(context.Background(), manifest)
	if run.ExecutionError != nil || !run.Result.Accepted {
		t.Fatalf("run=%#v", run)
	}
	if len(run.Events) != 3 || len(run.Delivery) != 3 {
		t.Fatalf("events=%d delivery=%d", len(run.Events), len(run.Delivery))
	}
	for _, report := range run.Delivery {
		if report.Succeeded() || report.Sinks[0].Attempts != 2 {
			t.Fatalf("report=%#v", report)
		}
	}
}

func TestGoalStorePersistsBeforeSinkFailureAndLinksRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goal.json")
	journal, err := goalpkg.New("goal-1", "intent", []goalpkg.ChecklistItem{{ID: "done", Acceptance: "done"}}, nil, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{failedSink{}}, Options{MaxAttempts: 1, Clock: func() time.Time { return fixedTime }})
	if err != nil {
		t.Fatal(err)
	}
	store := GoalStore{Store: goalpkg.Store{Path: path}, Emitter: emitter, Context: lifecycleContext()}
	created, err := store.Create(context.Background(), journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Events) != 1 || created.Delivery[0].Succeeded() {
		t.Fatalf("created=%#v", created)
	}
	mutation, err := store.Update(context.Background(), journal.Revision, func(j *goalpkg.Journal) error {
		return j.CompleteItem("done", []goalpkg.Evidence{{Type: goalpkg.EvidenceTest, Reference: "test", Result: "passed"}}, fixedTime)
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := (goalpkg.Store{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != mutation.Journal.Revision || loaded.Goal.Acceptance[0].Status != goalpkg.ItemComplete {
		t.Fatalf("loaded=%#v", loaded)
	}
	if len(mutation.Events) != 1 || mutation.Events[0].Subject().Revision != loaded.Revision || mutation.Delivery[0].Succeeded() {
		t.Fatalf("mutation=%#v", mutation)
	}
}

func TestAdaptersWithoutEmitterPreserveExistingBehavior(t *testing.T) {
	journal, err := goalpkg.New("goal-1", "intent", []goalpkg.ChecklistItem{{ID: "done", Acceptance: "done"}}, nil, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "goal.json")
	store := GoalStore{Store: goalpkg.Store{Path: path}}
	created, err := store.Create(context.Background(), journal)
	if err != nil || len(created.Events) != 0 || len(created.Delivery) != 0 {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	_, err = store.Update(context.Background(), 999, func(*goalpkg.Journal) error { return nil })
	if err == nil {
		t.Fatal("revision guard weakened")
	}
	var conflict *goalpkg.Error
	if !errors.As(err, &conflict) || conflict.Code != goalpkg.CodeConflict {
		t.Fatalf("error=%v", err)
	}
}

func TestGoalStoreObservationConfigurationCannotTurnPersistedSuccessIntoError(t *testing.T) {
	journal, err := goalpkg.New("goal-1", "intent", []goalpkg.ChecklistItem{{ID: "done", Acceptance: "done"}}, nil, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	memory, _ := NewMemorySink("memory", 10)
	emitter := testEmitter(t, memory)
	store := GoalStore{Store: goalpkg.Store{Path: filepath.Join(t.TempDir(), "goal.json")}, Emitter: emitter, Context: Context{CorrelationID: "invalid correlation with spaces"}}
	mutation, err := store.Create(context.Background(), journal)
	if err != nil {
		t.Fatalf("authoritative create was converted to error: %v", err)
	}
	if len(mutation.Delivery) != 1 || mutation.Delivery[0].Sinks[0].ErrorCode != SinkCorruptData {
		t.Fatalf("mutation=%#v", mutation)
	}
}

func TestTaskRunnerValidationFailureEmitsTypedFailureWithoutStarting(t *testing.T) {
	memory, _ := NewMemorySink("memory", 10)
	emitter := testEmitter(t, memory)
	run := TaskRunner{Emitter: emitter, Context: lifecycleContext()}.Run(context.Background(), agentruntime.TaskManifest{SchemaVersion: agentruntime.TaskSchemaVersion, ID: "task-1"})
	if run.ExecutionError == nil || len(run.Events) != 1 || run.Events[0].Kind() != TaskFailed {
		t.Fatalf("run=%#v", run)
	}
	encoded, _ := run.Events[0].CanonicalJSON()
	if !strings.Contains(string(encoded), string(ErrorValidation)) {
		t.Fatalf("event=%s", encoded)
	}
}
