// SPDX-License-Identifier: AGPL-3.0-only

package goal

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
var testEvidence = []Evidence{{Type: EvidenceTest, Reference: "go test ./...", Result: "passed"}}

func TestGoalRequiresExplicitAcceptance(t *testing.T) {
	t.Parallel()
	if _, err := New("release", "ship it", nil, nil, testNow); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("error=%v", err)
	}
}

func TestGoalCannotCompleteAfterImplementationOnly(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	advanceThrough(t, &j, PhaseExecute)
	if j.Goal.State == StateCompleted {
		t.Fatal("implementation incorrectly completed goal")
	}
	if err := j.Advance(closureReceipt(), testNow); !IsCode(err, CodeInvalidTransition) {
		t.Fatalf("error=%v", err)
	}
}

func TestGoalCannotCompleteWithOnlyVerifyReceipt(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	j.Goal.CurrentPhase = PhaseClosure
	j.Goal.Receipts[PhaseVerify] = Receipt{Phase: PhaseVerify, Summary: "one check passed", Evidence: testEvidence, RecordedAt: testNow}
	j.Goal.Acceptance[0].Status = ItemComplete
	j.Goal.Acceptance[0].Evidence = testEvidence
	if err := j.Advance(closureReceipt(), testNow); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("error=%v", err)
	}
	if j.Goal.State == StateCompleted {
		t.Fatal("single check incorrectly completed goal")
	}
}

func TestGoalCompletesOnlyWithChecklistAndAllReceipts(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	for _, phase := range Phases[:len(Phases)-1] {
		if err := j.Advance(Receipt{Phase: phase, Summary: "phase complete", Evidence: testEvidence}, testNow); err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
	}
	if err := j.CompleteItem("release-ready", testEvidence, testNow); err != nil {
		t.Fatal(err)
	}
	if err := j.Advance(closureReceipt(), testNow); err != nil {
		t.Fatal(err)
	}
	if j.Goal.State != StateCompleted {
		t.Fatalf("state=%s", j.Goal.State)
	}
	if err := j.CompleteItem("release-ready", testEvidence, testNow); !IsCode(err, CodeInvalidTransition) {
		t.Fatalf("completed goal mutation error=%v", err)
	}
}

func TestAdvanceIsOrderedAndRequiresEvidence(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if err := j.Advance(Receipt{Phase: PhaseExecute, Summary: "implemented", Evidence: testEvidence}, testNow); !IsCode(err, CodeInvalidTransition) {
		t.Fatalf("out of order error=%v", err)
	}
	if err := j.Advance(Receipt{Phase: PhaseOrient, Summary: "inspected"}, testNow); !IsCode(err, CodeMissingReceipt) {
		t.Fatalf("missing evidence error=%v", err)
	}
}

func TestLivingChecklistCanGrowAndRequiresUniqueIDs(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if err := j.AddChecklistItem(ChecklistItem{ID: "new-risk", Acceptance: "newly discovered risk is resolved"}, testNow); err != nil {
		t.Fatal(err)
	}
	if len(j.Goal.Acceptance) != 2 || j.Goal.Acceptance[1].Status != ItemPending {
		t.Fatalf("checklist=%#v", j.Goal.Acceptance)
	}
	if err := j.AddChecklistItem(ChecklistItem{ID: "new-risk", Acceptance: "duplicate"}, testNow); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("error=%v", err)
	}
}

func TestReceiptEvidenceIsAppendOnly(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if err := j.Advance(Receipt{Phase: PhaseOrient, Summary: "observed", Evidence: testEvidence}, testNow); err != nil {
		t.Fatal(err)
	}
	extra := Evidence{Type: EvidenceLink, Reference: "https://example.test/run", Result: "failed"}
	if err := j.AddReceiptEvidence(PhaseOrient, extra, testNow); err != nil {
		t.Fatal(err)
	}
	if got := j.Goal.Receipts[PhaseOrient].Evidence; len(got) != 2 || got[1] != extra {
		t.Fatalf("evidence=%#v", got)
	}
	if err := j.AddReceiptEvidence(PhaseOrient, extra, testNow); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("duplicate error=%v", err)
	}
}

func newTestJournal(t *testing.T) Journal {
	t.Helper()
	j, err := New("release", "ship release", []ChecklistItem{{ID: "release-ready", Acceptance: "all gates pass"}}, []string{"remote orchestration"}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func advanceThrough(t *testing.T, j *Journal, last Phase) {
	t.Helper()
	for _, phase := range Phases {
		if err := j.Advance(Receipt{Phase: phase, Summary: "complete", Evidence: testEvidence}, testNow); err != nil {
			t.Fatal(err)
		}
		if phase == last {
			return
		}
	}
}

func closureReceipt() Receipt {
	return Receipt{Phase: PhaseClosure, Summary: "closure recorded", Evidence: testEvidence, Closure: &ClosureDetails{AchievedOutcome: "release ready", Cleanup: "temporary artifacts removed", Remaining: []RemainingWork{}, NextWork: []Evidence{{Type: EvidenceFile, Reference: "ROADMAP.md", Result: "canonical follow-up queue"}}}}
}
