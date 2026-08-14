// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
)

var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func testDraft() Draft {
	return Draft{Kind: TaskStarted, Subject: Subject{Kind: SubjectTask, ID: "task-1"}, CorrelationID: "corr-1", Actor: Actor{Kind: ActorWorker, ID: "worker-1"}, Attempt: AttemptInitial, Outcome: OutcomeStarted, Timestamp: fixedTime, Attributes: []InputAttribute{{Name: "safe.count", Sensitivity: SensitivityPublic, Value: 1}}}
}

// acceptedTaskDraft is the single canonical fixture for a successful
// task.completed event. It deliberately delegates payload construction to the
// production lifecycle builder so fixtures cannot invent another result shape.
func acceptedTaskDraft() Draft {
	draft := TaskResultDraft(agentruntime.Result{AgentID: "task-1", Accepted: true}, nil, lifecycleContext())
	draft.Timestamp = fixedTime
	return draft
}
func testEmitter(t *testing.T, sinks ...Sink) *Emitter {
	t.Helper()
	emitter, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, sinks, Options{Clock: func() time.Time { return fixedTime }, MaxAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	return emitter
}

func TestEnvelopeCanonicalAndImmutable(t *testing.T) {
	t.Parallel()
	memory, _ := NewMemorySink("memory", 10)
	draft := testDraft()
	source := map[string]any{"safe": "before"}
	draft.Attributes = append(draft.Attributes, InputAttribute{Name: "safe.map", Sensitivity: SensitivityInternal, Value: source})
	event, report, err := testEmitter(t, memory).Emit(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	source["safe"] = "after"
	if !report.Succeeded() {
		t.Fatalf("report=%#v", report)
	}
	first, _ := event.CanonicalJSON()
	second, _ := event.CanonicalJSON()
	if string(first) != string(second) {
		t.Fatal("canonical bytes changed")
	}
	if containsAny(first, "after") {
		t.Fatalf("input mutation leaked: %s", first)
	}
	var restored Envelope
	if err := json.Unmarshal(first, &restored); err != nil {
		t.Fatal(err)
	}
	again, _ := restored.CanonicalJSON()
	if string(first) != string(again) {
		t.Fatalf("round trip changed\n%s\n%s", first, again)
	}
}

func TestConcurrentEmissionOrdersEachSubject(t *testing.T) {
	memory, _ := NewMemorySink("memory", 200)
	emitter := testEmitter(t, memory)
	const count = 100
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			if _, report, err := emitter.Emit(context.Background(), testDraft()); err != nil || !report.Succeeded() {
				t.Errorf("emit err=%v report=%#v", err, report)
			}
		}()
	}
	wg.Wait()
	events := memory.Snapshot()
	if len(events) != count {
		t.Fatalf("events=%d", len(events))
	}
	ids := map[string]bool{}
	for i, event := range events {
		if event.Sequence() != uint64(i+1) {
			t.Fatalf("sequence[%d]=%d", i, event.Sequence())
		}
		if ids[event.EventID()] {
			t.Fatal("duplicate event id")
		}
		ids[event.EventID()] = true
	}
}

type retrySink struct {
	mu    sync.Mutex
	calls int
	seen  []string
	raw   error
}

func (s *retrySink) Name() string { return "retry" }
func (s *retrySink) Write(_ context.Context, e Envelope) (WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.seen = append(s.seen, e.EventID())
	if s.calls < 3 {
		return WriteResult{}, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	return WriteResult{}, s.raw
}
func (s *retrySink) Flush(context.Context) error { return nil }
func (s *retrySink) Close(context.Context) error { return nil }
func TestRetryReusesEnvelopeAndRawSinkErrorNeverEscapes(t *testing.T) {
	sink := &retrySink{}
	event, report, err := testEmitter(t, sink).Emit(context.Background(), testDraft())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Succeeded() || report.Sinks[0].Attempts != 3 {
		t.Fatalf("report=%#v", report)
	}
	for _, id := range sink.seen {
		if id != event.EventID() {
			t.Fatalf("retry id=%s", id)
		}
	}
	sink = &retrySink{raw: errors.New("token=live-secret")}
	_, report, err = testEmitter(t, sink).Emit(context.Background(), testDraft())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(report)
	if containsAny(encoded, "live-secret", "token=") {
		t.Fatalf("raw sink error escaped: %s", encoded)
	}
	if report.Sinks[0].ErrorCode != SinkFailure {
		t.Fatalf("report=%#v", report)
	}
}

func TestMemoryBackpressureDuplicateAndClose(t *testing.T) {
	memory, _ := NewMemorySink("memory", 1)
	emitter := testEmitter(t, memory)
	event, report, err := emitter.Emit(context.Background(), testDraft())
	if err != nil || !report.Succeeded() {
		t.Fatal(err)
	}
	replay := emitter.Replay(context.Background(), event)
	if !replay.Succeeded() || !replay.Sinks[0].Duplicate {
		t.Fatalf("replay=%#v", replay)
	}
	draft := testDraft()
	draft.Subject.ID = "task-2"
	_, report, err = emitter.Emit(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	if report.Sinks[0].ErrorCode != SinkBackpressure || report.Sinks[0].Attempts != 3 {
		t.Fatalf("report=%#v", report)
	}
	closed := emitter.Close(context.Background())
	if !closed[0].Delivered {
		t.Fatalf("close=%#v", closed)
	}
	_, _, err = emitter.Emit(context.Background(), draft)
	if err == nil {
		t.Fatal("emit after close succeeded")
	}
}

func TestCausationLinksImmutableEvent(t *testing.T) {
	memory, _ := NewMemorySink("memory", 10)
	emitter := testEmitter(t, memory)
	first, _, _ := emitter.Emit(context.Background(), testDraft())
	secondDraft := acceptedTaskDraft()
	secondDraft.CausationID = first.EventID()
	second, _, err := emitter.Emit(context.Background(), secondDraft)
	if err != nil {
		t.Fatal(err)
	}
	if second.CausationID() != first.EventID() {
		t.Fatal("causation link lost")
	}
}

func TestEmitterRejectsUnboundedStreamCardinality(t *testing.T) {
	initial := make(map[string]uint64, MaxStreams+1)
	for i := 0; i < MaxStreams+1; i++ {
		initial[fmt.Sprintf("task:%d", i)] = 1
	}
	memory, _ := NewMemorySink("memory", 1)
	if _, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{memory}, Options{InitialSequences: initial}); err == nil {
		t.Fatal("unbounded streams accepted")
	}
}

func TestMalformedIdentityAndZeroGoalRevisionAreRejected(t *testing.T) {
	memory, _ := NewMemorySink("memory", 1)
	for _, id := range []string{"", "runtime 1", "runtime/1", "-runtime", strings.Repeat("r", 129)} {
		if _, err := NewEmitter(Runtime{ID: id, Version: "0.1.0"}, []Sink{memory}, Options{}); err == nil {
			t.Fatalf("malformed runtime identity %q accepted", id)
		}
	}
	draft := testDraft()
	draft.Subject = Subject{Kind: SubjectGoal, ID: "goal-1"}
	if _, _, err := testEmitter(t, memory).Emit(context.Background(), draft); err == nil {
		t.Fatal("Goal revision zero accepted")
	}
}

func TestEventKindCannotForkOutcomeOrRequiredEvidence(t *testing.T) {
	memory, _ := NewMemorySink("memory", 4)
	emitter := testEmitter(t, memory)
	draft := testDraft()
	draft.Outcome = OutcomeSucceeded
	if _, _, err := emitter.Emit(context.Background(), draft); err == nil {
		t.Fatal("Task started with succeeded outcome accepted")
	}
	draft = TaskBlockedDraft("task-1", BlockEvidenceMissing, []string{"test"}, lifecycleContext())
	draft.Payload.Blocking = nil
	if _, _, err := emitter.Emit(context.Background(), draft); err == nil {
		t.Fatal("blocked Task without blocking evidence accepted")
	}
}

func TestCompletedTaskFailsClosedWithoutCanonicalAcceptedResult(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Draft)
	}{
		{name: "missing accepted", mutate: func(d *Draft) { d.Payload.Accepted = nil }},
		{name: "accepted false", mutate: func(d *Draft) { accepted := false; d.Payload.Accepted = &accepted }},
		{name: "error on success", mutate: func(d *Draft) { d.Payload.Error = &ErrorEvidence{Code: ErrorExecution, Class: ErrorClassExecution} }},
		{name: "blocking on success", mutate: func(d *Draft) { d.Payload.Blocking = &BlockingEvidence{Code: BlockEvidenceMissing} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := acceptedTaskDraft()
			test.mutate(&draft)
			memory, _ := NewMemorySink("memory", 1)
			if _, _, err := testEmitter(t, memory).Emit(context.Background(), draft); err == nil {
				t.Fatal("semantically inconsistent task.completed accepted")
			}
		})
	}
}

func containsAny(data []byte, values ...string) bool {
	for _, value := range values {
		if strings.Contains(string(data), value) {
			return true
		}
	}
	return false
}
