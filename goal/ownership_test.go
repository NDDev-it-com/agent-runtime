// SPDX-License-Identifier: AGPL-3.0-only

package goal

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	store := Store{Path: filepath.Join(t.TempDir(), "goal.json")}
	if err := store.Create(newTestJournal(t)); err != nil {
		t.Fatal(err)
	}
	return store
}

// orientedStore returns a store whose Goal has one sealed orient receipt.
func orientedStore(t *testing.T) (Store, Journal) {
	t.Helper()
	store := newTestStore(t)
	j, err := store.Update(1, func(j *Journal) error {
		return j.Advance(Receipt{Phase: PhaseOrient, Summary: "sealed orient summary", Evidence: newTestEvidence()}, testNow)
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, j
}

func TestCompletedGoalRejectsEveryMutator(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	advanceThrough(t, &j, PhaseOmissionAudit)
	if err := j.Advance(Receipt{Phase: PhaseVerify, Summary: "verified", Evidence: newTestEvidence()}, testNow); err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteItem("release-ready", newTestEvidence(), testNow); err != nil {
		t.Fatal(err)
	}
	if err := j.Advance(closureReceipt(), testNow); err != nil {
		t.Fatal(err)
	}
	if j.Goal.State != StateCompleted {
		t.Fatalf("state=%s", j.Goal.State)
	}
	sealed := j.Clone()

	mutations := map[string]func() error{
		"complete item": func() error {
			return j.CompleteItem("release-ready", []Evidence{{Type: EvidenceLink, Reference: "late", Result: "found"}}, testNow)
		},
		"add checklist item": func() error {
			return j.AddChecklistItem(ChecklistItem{ID: "extra", Acceptance: "another criterion"}, testNow)
		},
		"add receipt evidence": func() error {
			return j.AddReceiptEvidence(PhaseVerify, Evidence{Type: EvidenceLink, Reference: "late", Result: "found"}, testNow)
		},
		"advance": func() error {
			return j.Advance(Receipt{Phase: PhaseClosure, Summary: "again", Evidence: newTestEvidence()}, testNow)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); !IsCode(err, CodeInvalidTransition) {
				t.Fatalf("completed goal accepted %s: %v", name, err)
			}
		})
	}
	if j.Revision != sealed.Revision || len(j.Goal.Receipts[PhaseVerify].Evidence) != len(sealed.Goal.Receipts[PhaseVerify].Evidence) {
		t.Fatal("a rejected mutation still changed the completed journal")
	}
}

func TestUpdateRejectsHistoricalRewrite(t *testing.T) {
	t.Parallel()
	rewrites := map[string]func(*Journal){
		"intent":              func(j *Journal) { j.Goal.Intent = "fabricated intent" },
		"created at":          func(j *Journal) { j.Goal.CreatedAt = testNow.Add(-time.Hour) },
		"identity":            func(j *Journal) { j.Goal.ID = "other" },
		"non-goals":           func(j *Journal) { j.Goal.NonGoals = nil },
		"updated at":          func(j *Journal) { j.Goal.UpdatedAt = testNow.Add(-time.Hour) },
		"receipt summary":     func(j *Journal) { rewriteOrient(j, func(r *Receipt) { r.Summary = "fabricated summary" }) },
		"receipt recorded at": func(j *Journal) { rewriteOrient(j, func(r *Receipt) { r.RecordedAt = time.Unix(0, 0).UTC() }) },
		"receipt evidence": func(j *Journal) {
			rewriteOrient(j, func(r *Receipt) {
				r.Evidence = []Evidence{{Type: EvidenceCommand, Reference: "never ran", Result: "fabricated"}}
			})
		},
		"receipt removal":      func(j *Journal) { delete(j.Goal.Receipts, PhaseOrient) },
		"acceptance criterion": func(j *Journal) { j.Goal.Acceptance[0].Acceptance = "fabricated criterion" },
		"acceptance removal":   func(j *Journal) { j.Goal.Acceptance = nil },
		"phase skip": func(j *Journal) {
			for _, phase := range []Phase{PhaseGapPlan, PhaseExecute} {
				j.Goal.Receipts[phase] = Receipt{Phase: phase, Summary: "fabricated " + string(phase), Evidence: newTestEvidence(), RecordedAt: testNow}
			}
			j.Goal.CurrentPhase = PhaseReconcile
		},
	}
	for name, rewrite := range rewrites {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, current := orientedStore(t)
			sealed, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Update(current.Revision, func(j *Journal) error {
				j.Revision++
				j.Goal.UpdatedAt = testNow.Add(time.Hour)
				rewrite(j)
				return nil
			}); err == nil {
				t.Fatal("historical rewrite was accepted")
			}
			after, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if after.Revision != sealed.Revision || after.Goal.Intent != sealed.Goal.Intent {
				t.Fatalf("rejected rewrite still reached the journal: %#v", after.Goal)
			}
		})
	}
}

func rewriteOrient(j *Journal, mutate func(*Receipt)) {
	receipt := j.Goal.Receipts[PhaseOrient]
	mutate(&receipt)
	j.Goal.Receipts[PhaseOrient] = receipt
}

func TestUpdateAcceptsDocumentedTransitions(t *testing.T) {
	t.Parallel()
	store, current := orientedStore(t)
	next, err := store.Update(current.Revision, func(j *Journal) error {
		return j.Advance(Receipt{Phase: PhaseGapPlan, Summary: "planned", Evidence: newTestEvidence()}, testNow.Add(time.Minute))
	})
	if err != nil {
		t.Fatalf("documented advance rejected: %v", err)
	}
	if next.Goal.CurrentPhase != PhaseExecute {
		t.Fatalf("phase=%s", next.Goal.CurrentPhase)
	}
	appended, err := store.Update(next.Revision, func(j *Journal) error {
		return j.AddReceiptEvidence(PhaseOrient, Evidence{Type: EvidenceLink, Reference: "issue-1", Result: "later finding"}, testNow.Add(2*time.Minute))
	})
	if err != nil {
		t.Fatalf("documented evidence append rejected: %v", err)
	}
	if len(appended.Goal.Receipts[PhaseOrient].Evidence) != 2 {
		t.Fatalf("evidence=%d", len(appended.Goal.Receipts[PhaseOrient].Evidence))
	}
	if _, err := store.Update(appended.Revision, func(j *Journal) error {
		return j.AddChecklistItem(ChecklistItem{ID: "extra", Acceptance: "another criterion"}, testNow.Add(3*time.Minute))
	}); err != nil {
		t.Fatalf("documented checklist append rejected: %v", err)
	}
}

func TestCreateRequiresGenesisState(t *testing.T) {
	t.Parallel()
	fabricated := newTestJournal(t)
	fabricated.Revision = 99
	fabricated.Goal.CurrentPhase = PhaseVerify
	fabricated.Goal.Acceptance[0].Status = ItemComplete
	fabricated.Goal.Acceptance[0].Evidence = newTestEvidence()
	for _, phase := range Phases()[:6] {
		fabricated.Goal.Receipts[phase] = Receipt{Phase: phase, Summary: "fabricated " + string(phase), Evidence: newTestEvidence(), RecordedAt: testNow}
	}
	if err := fabricated.Validate(); err != nil {
		t.Fatalf("fixture must be structurally valid to prove the point: %v", err)
	}
	store := Store{Path: filepath.Join(t.TempDir(), "goal.json")}
	if err := store.Create(fabricated); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("fabricated history was created: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("rejected journal was still written")
	}
	if err := store.Create(newTestJournal(t)); err != nil {
		t.Fatalf("genesis journal rejected: %v", err)
	}
}

func TestCloneIsolatesMutableHistory(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if err := j.Advance(Receipt{Phase: PhaseOrient, Summary: "oriented", Evidence: newTestEvidence()}, testNow); err != nil {
		t.Fatal(err)
	}
	snapshot := j.Clone()
	if err := j.Advance(Receipt{Phase: PhaseGapPlan, Summary: "planned", Evidence: newTestEvidence()}, testNow); err != nil {
		t.Fatal(err)
	}
	if err := j.AddReceiptEvidence(PhaseOrient, Evidence{Type: EvidenceLink, Reference: "issue-1", Result: "later"}, testNow); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Goal.Receipts) != 1 || len(snapshot.Goal.Receipts[PhaseOrient].Evidence) != 1 {
		t.Fatalf("snapshot followed later mutations: receipts=%d evidence=%d", len(snapshot.Goal.Receipts), len(snapshot.Goal.Receipts[PhaseOrient].Evidence))
	}
	snapshot.Goal.Receipts[PhaseOrient] = Receipt{Phase: PhaseOrient, Summary: "tampered"}
	snapshot.Goal.Acceptance[0].Acceptance = "tampered"
	if j.Goal.Receipts[PhaseOrient].Summary != "oriented" || j.Goal.Acceptance[0].Acceptance != "all gates pass" {
		t.Fatal("mutating a clone reached the original")
	}
}

func TestChecklistEvidenceIsAppendOnly(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if err := j.CompleteItem("release-ready", newTestEvidence(), testNow); err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteItem("release-ready", []Evidence{{Type: EvidenceLink, Reference: "issue-1", Result: "later"}}, testNow); err != nil {
		t.Fatal(err)
	}
	if got := j.Goal.Acceptance[0].Evidence; len(got) != 2 || got[0] != newTestEvidence()[0] {
		t.Fatalf("evidence was replaced instead of appended: %#v", got)
	}
	if err := j.CompleteItem("release-ready", newTestEvidence(), testNow); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("duplicate evidence identity accepted: %v", err)
	}
}

func TestPhasesAccessorReturnsACopy(t *testing.T) {
	t.Parallel()
	first := Phases()
	first[0], first[1] = first[1], first[0]
	if second := Phases(); second[0] != PhaseOrient || second[1] != PhaseGapPlan {
		t.Fatalf("mutating the returned order changed the state machine: %v", second)
	}
	j := newTestJournal(t)
	if j.Goal.CurrentPhase != PhaseOrient {
		t.Fatalf("phase=%s", j.Goal.CurrentPhase)
	}
}
