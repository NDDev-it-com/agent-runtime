// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

// Every identifier the Task manifest contract accepts must be observable. The
// redaction word list applies to attribute values, not to identities, and
// applying it to identities silently discarded whole observations.
func TestEveryValidTaskIdentityIsObservable(t *testing.T) {
	t.Parallel()
	identities := []string{"run-command", "fetch-url", "provider-sync", "raw-dump", "curl", "env-check", "secret-scan", "token.refresh", "a"}
	for _, id := range identities {
		manifest := agentruntime.TaskManifest{
			SchemaVersion: agentruntime.TaskSchemaVersion, ID: id,
			Instructions: []string{"AGENTS.md"}, Command: []string{"true"},
			Acceptance: agentruntime.TaskAcceptance{ExitCodes: []int{0}},
		}
		if _, err := manifest.Prepare(); err != nil {
			t.Fatalf("fixture %q is not a valid Task identity: %v", id, err)
		}
		memory, err := NewMemorySink("memory", 4)
		if err != nil {
			t.Fatal(err)
		}
		emitter := testEmitter(t, memory)
		if _, _, err := emitter.Emit(context.Background(), TaskStartedDraft(id, lifecycleContext())); err != nil {
			t.Fatalf("valid Task identity %q could not be observed: %v", id, err)
		}
	}
}

// A closure carrying both a debt and a risk builds its kinds from a Go map, whose
// iteration order is deliberately randomised. Canonicalisation must therefore
// happen before validation, or a durably completed Goal loses its terminal event.
func TestMixedDebtAndRiskAlwaysEmitsGoalCompleted(t *testing.T) {
	t.Parallel()
	const runs = 200
	for run := 0; run < runs; run++ {
		before, after := completedGoalPair(t)
		drafts, err := GoalTransitionDrafts(before, after, lifecycleContext())
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		memory, err := NewMemorySink("memory", 16)
		if err != nil {
			t.Fatal(err)
		}
		emitter := testEmitter(t, memory)
		emitted := false
		for _, draft := range drafts {
			event, _, err := emitter.Emit(context.Background(), draft)
			if err != nil {
				t.Fatalf("run %d: %s draft rejected: %v", run, draft.Kind, err)
			}
			if event.Kind() == GoalCompleted {
				emitted = true
			}
		}
		if !emitted {
			t.Fatalf("run %d: a durably completed Goal produced no goal.completed event", run)
		}
	}
}

func completedGoalPair(t *testing.T) (goalpkg.Journal, goalpkg.Journal) {
	t.Helper()
	store := goalpkg.Store{Path: filepath.Join(t.TempDir(), "goal.json")}
	evidence := []goalpkg.Evidence{{Type: goalpkg.EvidenceCommand, Reference: "go test ./...", Result: "passed"}}
	journal, err := goalpkg.New("mixed", "intent", []goalpkg.ChecklistItem{{ID: "done", Acceptance: "criterion"}}, nil, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(journal); err != nil {
		t.Fatal(err)
	}
	revision := journal.Revision
	step := func(mutate func(*goalpkg.Journal) error) goalpkg.Journal {
		t.Helper()
		updated, err := store.Update(revision, mutate)
		if err != nil {
			t.Fatal(err)
		}
		revision = updated.Revision
		return updated
	}
	current := step(func(j *goalpkg.Journal) error { return j.CompleteItem("done", evidence, fixedTime) })
	// Advance to closure without naming the phase order, so this fixture stays
	// correct whatever the canonical enumeration is.
	for current.Goal.CurrentPhase != goalpkg.PhaseClosure {
		phase := current.Goal.CurrentPhase
		current = step(func(j *goalpkg.Journal) error {
			return j.Advance(goalpkg.Receipt{Phase: phase, Summary: "complete", Evidence: evidence}, fixedTime)
		})
	}
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	after := step(func(j *goalpkg.Journal) error {
		return j.Advance(goalpkg.Receipt{Phase: goalpkg.PhaseClosure, Summary: "closed", Evidence: evidence, Closure: &goalpkg.ClosureDetails{
			AchievedOutcome: "shipped", Cleanup: "none",
			Remaining: []goalpkg.RemainingWork{{Kind: goalpkg.RemainingDebt, Summary: "debt"}, {Kind: goalpkg.RemainingRisk, Summary: "risk"}},
			NextWork:  []goalpkg.Evidence{{Type: goalpkg.EvidenceFile, Reference: "ROADMAP.md", Result: "queued"}},
		}}, fixedTime)
	})
	if after.Goal.State != goalpkg.StateCompleted {
		t.Fatalf("state=%s", after.Goal.State)
	}
	return before, after
}

// A history the sink is willing to append to must also be replayable. The two
// used to disagree about per-stream sequence order.
func TestAppendAndReplayShareOneHistoryContract(t *testing.T) {
	t.Parallel()
	first, second := twoEvents(t)
	one, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	two, err := second.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	reversed := filepath.Join(t.TempDir(), "reversed.jsonl")
	data := append(append(append([]byte{}, two...), '\n'), one...)
	if err := os.WriteFile(reversed, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	sink, openErr := OpenJSONLSink(reversed, JSONLOptions{Name: "file"})
	if sink != nil {
		_ = sink.Close(context.Background())
	}
	if !sinkCode(openErr, SinkCorruptData) {
		t.Fatalf("sink opened a history replay rejects: %v", openErr)
	}
	if _, _, err := ReplayJSONL(reversed); !sinkCode(err, SinkCorruptData) {
		t.Fatalf("replay error=%v", err)
	}
	ordered := filepath.Join(t.TempDir(), "ordered.jsonl")
	inOrder := append(append(append([]byte{}, one...), '\n'), two...)
	if err := os.WriteFile(ordered, append(inOrder, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	sink, err = OpenJSONLSink(ordered, JSONLOptions{Name: "file"})
	if err != nil {
		t.Fatalf("ordered history rejected: %v", err)
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, sequences, err := ReplayJSONL(ordered)
	if err != nil || len(events) != 2 {
		t.Fatalf("replay events=%d err=%v", len(events), err)
	}
	if sequences[streamKey(second.Subject())] != second.Sequence() {
		t.Fatalf("sequences=%v", sequences)
	}
}

// A policy that cannot produce a valid envelope must fail at construction rather
// than discard every observation that carries such an attribute.
func TestEmitterRejectsUnpublishableSensitivity(t *testing.T) {
	t.Parallel()
	memory, err := NewMemorySink("memory", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitivity := range []Sensitivity{SensitivityConfidential, SensitivitySecret, Sensitivity("unknown")} {
		if _, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{memory}, Options{Policy: Policy{MaxSensitivity: sensitivity}}); err == nil {
			t.Fatalf("policy %q accepted", sensitivity)
		}
	}
	for _, sensitivity := range []Sensitivity{SensitivityPublic, SensitivityInternal} {
		if _, err := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{memory}, Options{Policy: Policy{MaxSensitivity: sensitivity}}); err != nil {
			t.Fatalf("policy %q rejected: %v", sensitivity, err)
		}
	}
}
