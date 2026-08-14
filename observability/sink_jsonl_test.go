// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONLRestartReplayDeduplicationAndSequenceSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := OpenJSONLSink(path, JSONLOptions{Name: "file", SyncEveryWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	emitter := testEmitter(t, sink)
	first, report, err := emitter.Emit(context.Background(), testDraft())
	if err != nil || !report.Succeeded() {
		t.Fatalf("err=%v report=%#v", err, report)
	}
	secondDraft := acceptedTaskDraft()
	second, _, err := emitter.Emit(context.Background(), secondDraft)
	if err != nil {
		t.Fatal(err)
	}
	if results := emitter.Close(context.Background()); !results[0].Delivered {
		t.Fatalf("close=%#v", results)
	}
	events, sequences, err := ReplayJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventID() != first.EventID() || events[1].EventID() != second.EventID() || sequences["task:task-1"] != 2 {
		t.Fatalf("events=%#v sequences=%#v", events, sequences)
	}
	reopened, err := OpenJSONLSink(path, JSONLOptions{Name: "file", SyncEveryWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	replayEmitter, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{reopened}, Options{InitialSequences: sequences, Clock: func() time.Time { return fixedTime }})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := replayEmitter.Replay(context.Background(), first)
	if !duplicate.Succeeded() || !duplicate.Sinks[0].Duplicate {
		t.Fatalf("duplicate=%#v", duplicate)
	}
	third, _, err := replayEmitter.Emit(context.Background(), testDraft())
	if err != nil {
		t.Fatal(err)
	}
	if third.Sequence() != 3 {
		t.Fatalf("sequence=%d", third.Sequence())
	}
	_ = replayEmitter.Close(context.Background())
}

func TestJSONLRejectsPartialCorruptAndOutOfOrderReplay(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	partial := filepath.Join(dir, "partial.jsonl")
	if err := os.WriteFile(partial, []byte(`{"schema_version":"v1alpha1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONLSink(partial, JSONLOptions{Name: "file"}); !sinkCode(err, SinkPartialWrite) {
		t.Fatalf("partial error=%v", err)
	}
	corrupt := filepath.Join(dir, "corrupt.jsonl")
	if err := os.WriteFile(corrupt, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONLSink(corrupt, JSONLOptions{Name: "file"}); !sinkCode(err, SinkCorruptData) {
		t.Fatalf("corrupt error=%v", err)
	}
	first, second := twoEvents(t)
	one, _ := first.CanonicalJSON()
	two, _ := second.CanonicalJSON()
	reversed := filepath.Join(dir, "reversed.jsonl")
	data := append(append(append([]byte{}, two...), '\n'), one...)
	data = append(data, '\n')
	if err := os.WriteFile(reversed, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReplayJSONL(reversed); !sinkCode(err, SinkCorruptData) {
		t.Fatalf("order error=%v", err)
	}
}

func TestSinksAndReplayRejectInvalidCompletedTaskPayloads(t *testing.T) {
	valid, _ := emitDraft(t, acceptedTaskDraft())
	invalid := []struct {
		name   string
		mutate func(*envelopeWire)
	}{
		{name: "missing accepted", mutate: func(w *envelopeWire) { w.Payload.Accepted = nil }},
		{name: "accepted false", mutate: func(w *envelopeWire) { accepted := false; w.Payload.Accepted = &accepted }},
		{name: "inconsistent error", mutate: func(w *envelopeWire) {
			w.Payload.Error = &ErrorEvidence{Code: ErrorExecution, Class: ErrorClassExecution}
		}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			wire := valid.wire
			test.mutate(&wire)
			wire.EventID = makeEventID(wire)
			event := Envelope{wire: wire}
			if err := event.Validate(); err == nil {
				t.Fatal("invalid envelope passed validator")
			}
			memory, _ := NewMemorySink("memory", 1)
			if _, err := memory.Write(context.Background(), event); !sinkCode(err, SinkCorruptData) {
				t.Fatalf("memory sink error=%v", err)
			}
			path := filepath.Join(t.TempDir(), "invalid.jsonl")
			data, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReplayJSONL(path); !sinkCode(err, SinkCorruptData) {
				t.Fatalf("replay error=%v", err)
			}
		})
	}

	t.Run("wrong payload type", func(t *testing.T) {
		data, err := valid.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		raw["payload"] = "wrong"
		data, err = json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "wrong-payload.jsonl")
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReplayJSONL(path); !sinkCode(err, SinkCorruptData) {
			t.Fatalf("replay error=%v", err)
		}
	})
}

func TestSinksAndReplayRejectContradictoryCompletedGoal(t *testing.T) {
	valid := completedGoalEvent(t)
	tests := []struct {
		name       string
		mutate     func(*envelopeWire)
		replayCode SinkErrorCode
	}{
		{name: "wrong version", mutate: func(w *envelopeWire) { w.SchemaVersion = "v2" }, replayCode: SinkUnsupportedVersion},
		{name: "inconsistent identity revision", mutate: func(w *envelopeWire) { w.Subject.Revision++ }, replayCode: SinkCorruptData},
		{name: "malformed causation", mutate: func(w *envelopeWire) { w.CausationID = "goal-1" }, replayCode: SinkCorruptData},
		{name: "terminal state contradiction", mutate: func(w *envelopeWire) { w.Payload.State = "active" }, replayCode: SinkCorruptData},
		{name: "terminal outcome contradiction", mutate: func(w *envelopeWire) { w.Outcome = OutcomeBlocked }, replayCode: SinkCorruptData},
		{name: "terminal blocking contradiction", mutate: func(w *envelopeWire) { w.Payload.Blocking = &BlockingEvidence{Code: BlockExternalState} }, replayCode: SinkCorruptData},
		{name: "missing attributes array", mutate: func(w *envelopeWire) { w.Attributes = nil }, replayCode: SinkCorruptData},
		{name: "missing redactions array", mutate: func(w *envelopeWire) { w.Redactions = nil }, replayCode: SinkCorruptData},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := valid.wire
			test.mutate(&wire)
			wire.EventID = makeEventID(wire)
			event := Envelope{wire: wire}
			if err := event.Validate(); err == nil {
				t.Fatal("contradictory Goal completion passed validator")
			}
			memory, _ := NewMemorySink("memory", 1)
			if _, err := memory.Write(context.Background(), event); !sinkCode(err, SinkCorruptData) {
				t.Fatalf("memory sink error=%v", err)
			}
			file := &shortFile{}
			jsonl, err := newJSONLSinkWriter("file", file, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := jsonl.Write(context.Background(), event); !sinkCode(err, SinkCorruptData) {
				t.Fatalf("JSONL sink error=%v", err)
			}
			data, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "invalid-goal.jsonl")
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReplayJSONL(path); !sinkCode(err, test.replayCode) {
				t.Fatalf("replay error=%v", err)
			}
		})
	}
}

func completedGoalEvent(t *testing.T) Envelope {
	t.Helper()
	for _, draft := range completeGoalLifecycleDrafts(t, lifecycleContext()) {
		if draft.Kind == GoalCompleted {
			event, _ := emitDraft(t, draft)
			return event
		}
	}
	t.Fatal("canonical Goal completion fixture omitted goal.completed")
	return Envelope{}
}

func TestJSONLPermissionsSymlinkVersionAndFileBound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	insecure := filepath.Join(dir, "insecure.jsonl")
	if err := os.WriteFile(insecure, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the process umask, so the mode under test must be set
	// explicitly or a restrictive umask silently makes the fixture private and
	// this assertion tests nothing.
	if err := os.Chmod(insecure, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONLSink(insecure, JSONLOptions{Name: "file"}); !sinkCode(err, SinkFailure) {
		t.Fatalf("permissions error=%v", err)
	}
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONLSink(link, JSONLOptions{Name: "file"}); !sinkCode(err, SinkFailure) {
		t.Fatalf("symlink error=%v", err)
	}
	event, _ := oneEvent(t)
	data, _ := event.CanonicalJSON()
	unsupported := bytes.Replace(data, []byte(`"schema_version":"v1alpha1"`), []byte(`"schema_version":"v2"`), 1)
	unsupported = append(unsupported, '\n')
	versionPath := filepath.Join(dir, "version.jsonl")
	if err := os.WriteFile(versionPath, unsupported, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONLSink(versionPath, JSONLOptions{Name: "file"}); !sinkCode(err, SinkUnsupportedVersion) {
		t.Fatalf("version error=%v", err)
	}
	bounded := filepath.Join(dir, "bounded.jsonl")
	sink, err := OpenJSONLSink(bounded, JSONLOptions{Name: "file", MaxFileBytes: MaxEnvelopeBytes})
	if err != nil {
		t.Fatal(err)
	}
	var final error
	for i := 0; i < 1000; i++ {
		draft := testDraft()
		draft.Subject.ID = fmt.Sprintf("task-%d", i)
		memory, _ := NewMemorySink("source", 1)
		generated, _, emitErr := testEmitter(t, memory).Emit(context.Background(), draft)
		if emitErr != nil {
			t.Fatal(emitErr)
		}
		_, final = sink.Write(context.Background(), generated)
		if final != nil {
			break
		}
	}
	if !sinkCode(final, SinkBackpressure) {
		t.Fatalf("bound error=%v", final)
	}
}

type shortFile struct {
	bytes.Buffer
	short   bool
	syncErr bool
	closed  bool
}

func (f *shortFile) Write(p []byte) (int, error) {
	if f.short && len(p) > 1 {
		return f.Buffer.Write(p[:len(p)/2])
	}
	return f.Buffer.Write(p)
}
func (f *shortFile) Sync() error {
	if f.syncErr {
		return errors.New("disk secret detail")
	}
	return nil
}
func (f *shortFile) Close() error { f.closed = true; return nil }
func TestJSONLPartialWritePoisonsSinkAndHidesRawErrors(t *testing.T) {
	event, _ := oneEvent(t)
	file := &shortFile{short: true}
	sink, err := newJSONLSinkWriter("file", file, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write(context.Background(), event); !sinkCode(err, SinkPartialWrite) {
		t.Fatalf("write error=%v", err)
	}
	file.short = false
	if _, err := sink.Write(context.Background(), event); !sinkCode(err, SinkPartialWrite) {
		t.Fatalf("poison error=%v", err)
	}
	if err := sink.Flush(context.Background()); !sinkCode(err, SinkPartialWrite) {
		t.Fatalf("flush error=%v", err)
	}
	file = &shortFile{syncErr: true}
	sink, _ = newJSONLSinkWriter("file", file, true)
	if _, err := sink.Write(context.Background(), event); !sinkCode(err, SinkPartialWrite) || strings.Contains(err.Error(), "disk secret") {
		t.Fatalf("sync error=%v", err)
	}
}

func oneEvent(t *testing.T) (Envelope, DeliveryReport) {
	t.Helper()
	memory, _ := NewMemorySink("memory", 10)
	event, report, err := testEmitter(t, memory).Emit(context.Background(), testDraft())
	if err != nil {
		t.Fatal(err)
	}
	return event, report
}

func emitDraft(t *testing.T, draft Draft) (Envelope, DeliveryReport) {
	t.Helper()
	memory, _ := NewMemorySink("memory", 10)
	event, report, err := testEmitter(t, memory).Emit(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	return event, report
}
func twoEvents(t *testing.T) (Envelope, Envelope) {
	t.Helper()
	memory, _ := NewMemorySink("memory", 10)
	emitter := testEmitter(t, memory)
	first, _, _ := emitter.Emit(context.Background(), testDraft())
	draft := acceptedTaskDraft()
	second, _, _ := emitter.Emit(context.Background(), draft)
	return first, second
}
func sinkCode(err error, code SinkErrorCode) bool {
	var typed *SinkError
	return errors.As(err, &typed) && typed.Code == code
}

// TestJSONLAppendsToTheFileItRead pins the guarantee that the recovered history
// and the appends describe one object: replace the path after opening and the
// sink keeps extending the file it recovered, leaving the impostor untouched.
//
// It does not reproduce the defect it accompanies. That was a window inside
// OpenJSONLSink — the path was opened once to scan, closed, and opened again to
// append, so a rename in between left duplicate-identity and size state
// describing the first file while writes went to the second. The window is
// closed by construction, by holding a single descriptor for the life of the
// sink, and hitting it from outside would require a hook that exists only to be
// hooked. What this test can do is fail if that construction is ever undone.
func TestJSONLAppendsToTheFileItRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	sink, err := OpenJSONLSink(path, JSONLOptions{Name: "file", SyncEveryWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	emitter := testEmitter(t, sink)
	if _, report, err := emitter.Emit(context.Background(), testDraft()); err != nil || !report.Succeeded() {
		t.Fatalf("err=%v report=%#v", err, report)
	}

	// The name now resolves to a different, empty file.
	held := filepath.Join(dir, "held.jsonl")
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := emitter.Emit(context.Background(), acceptedTaskDraft()); err != nil {
		t.Fatal(err)
	}
	if results := emitter.Close(context.Background()); !results[0].Delivered {
		t.Fatalf("close=%#v", results)
	}

	impostor, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(impostor) != 0 {
		t.Fatalf("the sink wrote into the file that took over the path: %q", impostor)
	}
	events, _, err := ReplayJSONL(held)
	if err != nil {
		t.Fatalf("the file the sink actually held is unreadable: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("the held file has %d events, want both writes", len(events))
	}
}

// TestJSONLRefusesAPathThatResolvedElsewhere covers the other direction: a name
// that no longer refers to the object just opened is a configuration the caller
// did not make, so it is refused rather than followed.
func TestJSONLRefusesAPathThatResolvedElsewhere(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenJSONLSink(link, JSONLOptions{Name: "file"}); err == nil {
		t.Fatal("a symlinked destination was accepted")
	}
}
