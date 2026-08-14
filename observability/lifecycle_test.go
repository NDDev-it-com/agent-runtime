// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

func lifecycleContext() Context {
	return Context{CorrelationID: "corr-lifecycle", Actor: Actor{Kind: ActorOrchestrator, ID: "orchestrator-1"}, Attempt: AttemptInitial}
}

type goalLifecycleFixture struct {
	id                string
	intent            string
	nextWorkReference string
	nextWorkResult    string
}

func newGoalLifecycleFixture() goalLifecycleFixture {
	return goalLifecycleFixture{
		id:                "goal-1",
		intent:            "verify every lifecycle transition",
		nextWorkReference: "ROADMAP.md",
		nextWorkResult:    "canonical follow-up queue",
	}
}

func (f goalLifecycleFixture) nextWork() []goalpkg.Evidence {
	return []goalpkg.Evidence{{Type: goalpkg.EvidenceFile, Reference: f.nextWorkReference, Result: f.nextWorkResult}}
}

func (f goalLifecycleFixture) closureReceipt(summary, outcome, cleanup string, remaining []goalpkg.RemainingWork, evidence []goalpkg.Evidence) goalpkg.Receipt {
	remainingCopy := make([]goalpkg.RemainingWork, len(remaining))
	copy(remainingCopy, remaining)
	evidenceCopy := make([]goalpkg.Evidence, len(evidence))
	copy(evidenceCopy, evidence)
	return goalpkg.Receipt{
		Phase:    goalpkg.PhaseClosure,
		Summary:  summary,
		Evidence: evidenceCopy,
		Closure: &goalpkg.ClosureDetails{
			AchievedOutcome: outcome,
			Cleanup:         cleanup,
			Remaining:       remainingCopy,
			NextWork:        f.nextWork(),
		},
	}
}
func TestTaskLifecycleNeverIncludesOutput(t *testing.T) {
	t.Parallel()
	result := agentruntime.Result{AgentID: "task-1", ExitCode: 7, Output: "token=live-secret", Accepted: false, Truncated: true}
	draft := TaskResultDraft(result, &ErrorEvidence{Code: ErrorExecution, Class: ErrorClassExecution, Retryable: false}, lifecycleContext())
	memory, _ := NewMemorySink("memory", 10)
	event, _, err := testEmitter(t, memory).Emit(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := event.CanonicalJSON()
	if strings.Contains(string(encoded), "live-secret") {
		t.Fatalf("output leaked: %s", encoded)
	}
	if event.Kind() != TaskFailed {
		t.Fatalf("kind=%s", event.Kind())
	}
}

func TestGoalLifecycleDerivesExistingStateMachineChanges(t *testing.T) {
	t.Parallel()
	now := fixedTime
	fixture := newGoalLifecycleFixture()
	j, err := goalpkg.New(fixture.id, fixture.intent, []goalpkg.ChecklistItem{{ID: "done", Acceptance: "done"}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	created, err := GoalCreatedDraft(j, lifecycleContext())
	if err != nil || created.Kind != GoalCreated {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	before := cloneJournal(t, j)
	if err := j.CompleteItem("done", []goalpkg.Evidence{{Type: goalpkg.EvidenceTest, Reference: "test", Result: "passed"}}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err := GoalTransitionDrafts(before, j, lifecycleContext())
	if err != nil {
		t.Fatal(err)
	}
	assertKinds(t, events, GoalChecklistCompleted)
	before = cloneJournal(t, j)
	if err := j.Advance(goalpkg.Receipt{Phase: goalpkg.PhaseOrient, Summary: "oriented", Evidence: []goalpkg.Evidence{{Type: goalpkg.EvidenceFile, Reference: "README.md", Result: "read"}}}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err = GoalTransitionDrafts(before, j, lifecycleContext())
	if err != nil {
		t.Fatal(err)
	}
	assertKinds(t, events, GoalReceiptEvidenceAdded, GoalPhaseTransitioned)
	before = cloneJournal(t, j)
	if err := j.AddReceiptEvidence(goalpkg.PhaseOrient, goalpkg.Evidence{Type: goalpkg.EvidenceLink, Reference: "https://example.test/evidence", Result: "observed"}, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err = GoalTransitionDrafts(before, j, lifecycleContext())
	if err != nil {
		t.Fatal(err)
	}
	assertKinds(t, events, GoalReceiptEvidenceAdded)
}

func TestGoalCompletionCarriesTypedDebtWithoutSummary(t *testing.T) {
	now := fixedTime
	fixture := newGoalLifecycleFixture()
	j, err := goalpkg.New(fixture.id, fixture.intent, []goalpkg.ChecklistItem{{ID: "done", Acceptance: "done"}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteItem("done", []goalpkg.Evidence{{Type: goalpkg.EvidenceTest, Reference: "test", Result: "passed"}}, now); err != nil {
		t.Fatal(err)
	}
	evidence := []goalpkg.Evidence{{Type: goalpkg.EvidenceTest, Reference: "gate", Result: "passed"}}
	for _, phase := range goalpkg.Phases()[:len(goalpkg.Phases())-1] {
		if err := j.Advance(goalpkg.Receipt{Phase: phase, Summary: "complete", Evidence: evidence}, now); err != nil {
			t.Fatal(err)
		}
	}
	before := cloneJournal(t, j)
	receipt := fixture.closureReceipt("secret closure", "secret outcome text", "secret cleanup", []goalpkg.RemainingWork{{Kind: goalpkg.RemainingRisk, Summary: "secret risk detail"}}, evidence)
	if err := j.Advance(receipt, now); err != nil {
		t.Fatal(err)
	}
	events, err := GoalTransitionDrafts(before, j, lifecycleContext())
	if err != nil {
		t.Fatal(err)
	}
	assertKinds(t, events, GoalReceiptEvidenceAdded, GoalCompleted)
	encoded, _ := json.Marshal(events)
	for _, secret := range []string{"secret outcome", "secret cleanup", "secret risk", "secret closure"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("journal prose leaked: %s", encoded)
		}
	}
}

func TestGoalLifecycleFixturePreservesPresenceAndDoesNotAlias(t *testing.T) {
	fixture := newGoalLifecycleFixture()
	evidence := []goalpkg.Evidence{{Type: goalpkg.EvidenceTest, Reference: "test", Result: "passed"}}
	empty := fixture.closureReceipt("complete", "complete", "clean", []goalpkg.RemainingWork{}, evidence)
	if empty.Closure.Remaining == nil || len(empty.Closure.Remaining) != 0 || len(empty.Closure.NextWork) != 1 {
		t.Fatalf("presence collapsed: %#v", empty.Closure)
	}
	remaining := []goalpkg.RemainingWork{{Kind: goalpkg.RemainingRisk, Summary: "bounded risk"}}
	receipt := fixture.closureReceipt("complete", "complete", "clean", remaining, evidence)
	remaining[0].Summary = "mutated input"
	evidence[0].Result = "mutated input"
	if receipt.Closure.Remaining[0].Summary != "bounded risk" || receipt.Evidence[0].Result == "mutated input" {
		t.Fatalf("fixture output aliases input: %#v", receipt)
	}
	receipt.Closure.NextWork[0].Result = "mutated output"
	if next := fixture.nextWork(); next[0].Result != fixture.nextWorkResult {
		t.Fatalf("NextWork helper retained mutation: %#v", next)
	}
}

func TestHandoffVocabulary(t *testing.T) {
	t.Parallel()
	draft, err := HandoffDraft("handoff-1", ActorDispatcher, ActorWorker, HandoffStageBlocked, nil, &BlockingEvidence{Code: BlockApprovalRequired, RequiredEvidenceTypes: []string{"issue"}}, lifecycleContext())
	if err != nil {
		t.Fatal(err)
	}
	if draft.Kind != HandoffBlocked || draft.Outcome != OutcomeBlocked {
		t.Fatalf("draft=%#v", draft)
	}
	if _, err := HandoffDraft("handoff-1", ActorDispatcher, ActorWorker, "unknown", nil, nil, lifecycleContext()); err == nil {
		t.Fatal("unknown stage accepted")
	}
}

func TestEveryLifecycleKindHasValidSubjectOutcomeAndPayload(t *testing.T) {
	t.Parallel()
	memory, _ := NewMemorySink("memory", 100)
	emitter := testEmitter(t, memory)
	ctx := lifecycleContext()
	drafts := []Draft{TaskValidatedDraft("task-1", ctx), TaskStartedDraft("task-2", ctx), TaskResultDraft(agentruntime.Result{AgentID: "task-3", Accepted: true}, nil, ctx), TaskResultDraft(agentruntime.Result{AgentID: "task-4", Accepted: false}, &ErrorEvidence{Code: ErrorExecution, Class: ErrorClassExecution}, ctx), TaskBlockedDraft("task-5", BlockEvidenceMissing, []string{"test"}, ctx), TaskResultDraft(agentruntime.Result{AgentID: "task-6", Cancelled: true}, &ErrorEvidence{Code: ErrorCancelled, Class: ErrorClassCancellation}, ctx)}
	drafts = append(drafts, completeGoalLifecycleDrafts(t, ctx)...)
	for _, stage := range []HandoffStage{HandoffStageDispatched, HandoffStageAccepted, HandoffStageCompleted, HandoffStageFailed, HandoffStageBlocked} {
		var errorEvidence *ErrorEvidence
		var blocking *BlockingEvidence
		if stage == HandoffStageFailed {
			errorEvidence = &ErrorEvidence{Code: ErrorExecution, Class: ErrorClassExecution}
		}
		if stage == HandoffStageBlocked {
			blocking = &BlockingEvidence{Code: BlockApprovalRequired, RequiredEvidenceTypes: []string{"issue"}}
		}
		draft, err := HandoffDraft("handoff-"+string(stage), ActorDispatcher, ActorWorker, stage, errorEvidence, blocking, ctx)
		if err != nil {
			t.Fatal(err)
		}
		drafts = append(drafts, draft)
	}
	seen := map[EventKind]bool{}
	for _, draft := range drafts {
		event, _, err := emitter.Emit(context.Background(), draft)
		if err != nil {
			t.Fatalf("%s: %v", draft.Kind, err)
		}
		seen[event.Kind()] = true
	}
	for kind := range eventKinds {
		if !seen[kind] {
			t.Errorf("lifecycle kind omitted: %s", kind)
		}
	}
}

func completeGoalLifecycleDrafts(t *testing.T, ctx Context) []Draft {
	t.Helper()
	fixture := newGoalLifecycleFixture()
	journal, err := goalpkg.New(fixture.id, fixture.intent, []goalpkg.ChecklistItem{{ID: "done", Acceptance: "done"}}, nil, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	created, err := GoalCreatedDraft(journal, ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := GoalBlockedDraft(journal, BlockAuthorityRequired, []string{"issue"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	drafts := []Draft{created, blocked}
	mutate := func(change func(*goalpkg.Journal) error) {
		before := cloneJournal(t, journal)
		if err := change(&journal); err != nil {
			t.Fatal(err)
		}
		derived, err := GoalTransitionDrafts(before, journal, ctx)
		if err != nil {
			t.Fatal(err)
		}
		drafts = append(drafts, derived...)
	}
	evidence := []goalpkg.Evidence{{Type: goalpkg.EvidenceTest, Reference: "test", Result: "passed"}}
	mutate(func(j *goalpkg.Journal) error {
		return j.AddChecklistItem(goalpkg.ChecklistItem{ID: "extra", Acceptance: "extra"}, fixedTime.Add(time.Second))
	})
	mutate(func(j *goalpkg.Journal) error { return j.CompleteItem("done", evidence, fixedTime.Add(2*time.Second)) })
	mutate(func(j *goalpkg.Journal) error { return j.CompleteItem("extra", evidence, fixedTime.Add(3*time.Second)) })
	for index, phase := range goalpkg.Phases()[:len(goalpkg.Phases())-1] {
		phase := phase
		mutate(func(j *goalpkg.Journal) error {
			return j.Advance(goalpkg.Receipt{Phase: phase, Summary: "complete", Evidence: evidence}, fixedTime.Add(time.Duration(index+4)*time.Second))
		})
	}
	mutate(func(j *goalpkg.Journal) error {
		return j.Advance(fixture.closureReceipt("complete", "all lifecycle events observed", "fixture state finalized", []goalpkg.RemainingWork{}, evidence), fixedTime.Add(20*time.Second))
	})
	return drafts
}

func cloneJournal(t *testing.T, j goalpkg.Journal) goalpkg.Journal {
	t.Helper()
	data, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var out goalpkg.Journal
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func assertKinds(t *testing.T, events []Draft, want ...EventKind) {
	t.Helper()
	got := make([]EventKind, len(events))
	for i, event := range events {
		got[i] = event.Kind
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kinds=%v want=%v", got, want)
	}
}

// TestCancelledTaskRequiresCancellationEvidence keeps the cancelled outcome
// tied to the evidence that justifies it: a caller cannot claim a Task was
// stopped without the unaccepted result and the cancellation error that make it
// true, and cannot claim it while also reporting the Task as blocked.
func TestCancelledTaskRequiresCancellationEvidence(t *testing.T) {
	t.Parallel()
	memory, _ := NewMemorySink("memory", 100)
	emitter := testEmitter(t, memory)
	ctx := lifecycleContext()
	cancellation := &ErrorEvidence{Code: ErrorCancelled, Class: ErrorClassCancellation}

	valid := TaskResultDraft(agentruntime.Result{AgentID: "task-cancelled", Cancelled: true}, cancellation, ctx)
	if valid.Kind != TaskCancelled || valid.Outcome != OutcomeCancelled {
		t.Fatalf("cancelled result drafted kind=%s outcome=%s", valid.Kind, valid.Outcome)
	}
	if _, _, err := emitter.Emit(context.Background(), valid); err != nil {
		t.Fatalf("well-evidenced cancellation rejected: %v", err)
	}

	accepted := true
	for name, mutate := range map[string]func(*Draft){
		"no error evidence": func(d *Draft) { d.Payload.Error = nil },
		"wrong error class": func(d *Draft) { d.Payload.Error = &ErrorEvidence{Code: ErrorExecution, Class: ErrorClassExecution} },
		"accepted result":   func(d *Draft) { d.Payload.Accepted = &accepted },
		"also blocked": func(d *Draft) {
			d.Payload.Blocking = &BlockingEvidence{Code: BlockEvidenceMissing, RequiredEvidenceTypes: []string{"test"}}
		},
		"outcome disagreement": func(d *Draft) { d.Outcome = OutcomeFailed },
	} {
		t.Run(name, func(t *testing.T) {
			draft := TaskResultDraft(agentruntime.Result{AgentID: "task-cancelled", Cancelled: true}, cancellation, ctx)
			mutate(&draft)
			if _, _, err := emitter.Emit(context.Background(), draft); err == nil {
				t.Fatal("emitter accepted a cancelled Task without its evidence")
			}
		})
	}
}

// TestTimedOutTaskIsNotReportedAsCancelled keeps the two terminal states apart:
// exceeding the Task's own timeout is the Task failing its contract, not the
// caller stopping it.
func TestTimedOutTaskIsNotReportedAsCancelled(t *testing.T) {
	t.Parallel()
	ctx := lifecycleContext()
	draft := TaskResultDraft(
		agentruntime.Result{AgentID: "task-timeout", TimedOut: true},
		&ErrorEvidence{Code: ErrorTimeout, Class: ErrorClassTimeout},
		ctx,
	)
	if draft.Kind != TaskFailed || draft.Outcome != OutcomeFailed {
		t.Fatalf("timed-out result drafted kind=%s outcome=%s, want a failed Task", draft.Kind, draft.Outcome)
	}
}
