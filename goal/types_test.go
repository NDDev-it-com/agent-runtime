// SPDX-License-Identifier: AGPL-3.0-only

package goal

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func newTestEvidence() []Evidence {
	return []Evidence{{Type: EvidenceTest, Reference: "go test ./...", Result: "passed"}}
}

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
	j.Goal.Receipts[PhaseVerify] = Receipt{Phase: PhaseVerify, Summary: "one check passed", Evidence: newTestEvidence(), RecordedAt: testNow}
	j.Goal.Acceptance[0].Status = ItemComplete
	j.Goal.Acceptance[0].Evidence = newTestEvidence()
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
	for _, phase := range Phases()[:len(Phases())-1] {
		if err := j.Advance(Receipt{Phase: phase, Summary: "phase complete", Evidence: newTestEvidence()}, testNow); err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
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
	if err := j.CompleteItem("release-ready", newTestEvidence(), testNow); !IsCode(err, CodeInvalidTransition) {
		t.Fatalf("completed goal mutation error=%v", err)
	}
}

func TestAdvanceIsOrderedAndRequiresEvidence(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if err := j.Advance(Receipt{Phase: PhaseExecute, Summary: "implemented", Evidence: newTestEvidence()}, testNow); !IsCode(err, CodeInvalidTransition) {
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
	if err := j.Advance(Receipt{Phase: PhaseOrient, Summary: "observed", Evidence: newTestEvidence()}, testNow); err != nil {
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
	conflict := extra
	conflict.Result = "different"
	if err := j.AddReceiptEvidence(PhaseOrient, conflict, testNow); !IsCode(err, CodeInvalidGoal) {
		t.Fatalf("conflicting evidence error=%v", err)
	}
}

func TestClosureRejectsInvalidNextWork(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ClosureDetails)
	}{
		{name: "missing", mutate: func(c *ClosureDetails) { c.NextWork = nil }},
		{name: "empty", mutate: func(c *ClosureDetails) { c.NextWork = []Evidence{} }},
		{name: "whitespace reference", mutate: func(c *ClosureDetails) { c.NextWork[0].Reference = " \t" }},
		{name: "whitespace result", mutate: func(c *ClosureDetails) { c.NextWork[0].Result = " \n" }},
		{name: "wrong type", mutate: func(c *ClosureDetails) { c.NextWork[0].Type = "provider" }},
		{name: "oversized reference", mutate: func(c *ClosureDetails) { c.NextWork[0].Reference = strings.Repeat("x", MaxEvidenceFieldBytes+1) }},
		{name: "oversized result", mutate: func(c *ClosureDetails) { c.NextWork[0].Result = strings.Repeat("x", MaxEvidenceFieldBytes+1) }},
		{name: "duplicate", mutate: func(c *ClosureDetails) { c.NextWork = append(c.NextWork, c.NextWork[0]) }},
		{name: "conflicting duplicate", mutate: func(c *ClosureDetails) {
			duplicate := c.NextWork[0]
			duplicate.Result = "different"
			c.NextWork = append(c.NextWork, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := closureReceipt()
			test.mutate(receipt.Closure)
			if err := validateClosure(receipt); err == nil {
				t.Fatal("invalid NextWork accepted")
			}
		})
	}
}

func TestClosureJSONPresenceRoundTrip(t *testing.T) {
	t.Parallel()
	validEvidence := `[{"type":"file","reference":"ROADMAP.md","result":"canonical follow-up queue"}]`
	tests := []struct {
		name      string
		remaining string
		nextWork  string
		valid     bool
	}{
		{name: "absent remaining", nextWork: `,"next_work":` + validEvidence},
		{name: "null remaining", remaining: `,"remaining":null`, nextWork: `,"next_work":` + validEvidence},
		{name: "explicit empty remaining", remaining: `,"remaining":[]`, nextWork: `,"next_work":` + validEvidence, valid: true},
		{name: "nonempty remaining", remaining: `,"remaining":[{"kind":"risk","summary":"tracked"}]`, nextWork: `,"next_work":` + validEvidence, valid: true},
		{name: "absent next work", remaining: `,"remaining":[]`},
		{name: "null next work", remaining: `,"remaining":[]`, nextWork: `,"next_work":null`},
		{name: "empty next work", remaining: `,"remaining":[]`, nextWork: `,"next_work":[]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(`{"achieved_outcome":"complete","cleanup":"clean"` + test.remaining + test.nextWork + `}`)
			var closure ClosureDetails
			if err := json.Unmarshal(data, &closure); err != nil {
				t.Fatal(err)
			}
			receipt := Receipt{Phase: PhaseClosure, Summary: "complete", Evidence: newTestEvidence(), Closure: &closure}
			err := validateClosure(receipt)
			if test.valid != (err == nil) {
				t.Fatalf("valid=%v error=%v closure=%#v", test.valid, err, closure)
			}
			if test.valid {
				roundTrip, err := json.Marshal(closure)
				if err != nil {
					t.Fatal(err)
				}
				if test.name == "explicit empty remaining" && !strings.Contains(string(roundTrip), `"remaining":[]`) {
					t.Fatalf("explicit empty presence lost: %s", roundTrip)
				}
			}
		})
	}
	for _, malformed := range []string{
		`{"achieved_outcome":"complete","cleanup":"clean","remaining":{},"next_work":` + validEvidence + `}`,
		`{"achieved_outcome":"complete","cleanup":"clean","remaining":[],"next_work":{}}`,
	} {
		var closure ClosureDetails
		if err := json.Unmarshal([]byte(malformed), &closure); err == nil {
			t.Fatalf("wrong container type accepted: %s", malformed)
		}
	}
}

func TestGoalRequiredMapPresenceRoundTrip(t *testing.T) {
	t.Parallel()
	j := newTestJournal(t)
	if j.Goal.Receipts == nil || len(j.Goal.Receipts) != 0 {
		t.Fatalf("initial receipts presence=%#v", j.Goal.Receipts)
	}
	data, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"receipts":{}`) {
		t.Fatalf("empty receipts object lost: %s", data)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		value  any
		delete bool
	}{
		{name: "absent", delete: true},
		{name: "null", value: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := make(map[string]any, len(raw))
			for key, value := range raw {
				candidate[key] = value
			}
			goal := candidate["goal"].(map[string]any)
			goalCopy := make(map[string]any, len(goal))
			for key, value := range goal {
				goalCopy[key] = value
			}
			candidate["goal"] = goalCopy
			if test.delete {
				delete(goalCopy, "receipts")
			} else {
				goalCopy["receipts"] = test.value
			}
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var restored Journal
			if err := json.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			if err := restored.Validate(); err == nil {
				t.Fatal("missing receipts object accepted")
			}
		})
	}
}

func TestGoalBuildersPreservePresenceAndDoNotAlias(t *testing.T) {
	t.Parallel()
	acceptance := []ChecklistItem{{ID: "release-ready", Acceptance: "all gates pass"}}
	nonGoals := []string{"remote orchestration"}
	j, err := New("release", "ship release", acceptance, nonGoals, testNow)
	if err != nil {
		t.Fatal(err)
	}
	acceptance[0].Acceptance = "mutated"
	nonGoals[0] = "mutated"
	if j.Goal.Acceptance[0].Acceptance != "all gates pass" || j.Goal.NonGoals[0] != "remote orchestration" || j.Goal.Receipts == nil {
		t.Fatalf("New retained caller aliases: %#v", j.Goal)
	}
	for _, phase := range Phases()[:len(Phases())-1] {
		if err := j.Advance(Receipt{Phase: phase, Summary: "complete", Evidence: newTestEvidence()}, testNow); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.CompleteItem("release-ready", newTestEvidence(), testNow); err != nil {
		t.Fatal(err)
	}
	receipt := closureReceipt()
	if err := j.Advance(receipt, testNow); err != nil {
		t.Fatal(err)
	}
	receipt.Evidence[0].Result = "mutated"
	receipt.Closure.Remaining = nil
	receipt.Closure.NextWork[0].Result = "mutated"
	stored := j.Goal.Receipts[PhaseClosure]
	if stored.Evidence[0].Result != "passed" || stored.Closure.Remaining == nil || stored.Closure.NextWork[0].Result != "canonical follow-up queue" {
		t.Fatalf("Advance retained caller aliases: %#v", stored)
	}
}

func TestGoalTestFixturesAreDeeplyIndependent(t *testing.T) {
	t.Parallel()
	first := closureReceipt()
	second := closureReceipt()

	if first.Closure == second.Closure {
		t.Fatal("closure fixture pointers alias")
	}
	first.Evidence[0].Result = "first-only"
	first.Closure.NextWork[0].Result = "first-only"
	first.Closure.Remaining = append(first.Closure.Remaining, RemainingWork{Kind: "risk", Summary: "first-only"})
	if second.Evidence[0].Result != "passed" || second.Closure.NextWork[0].Result != "canonical follow-up queue" {
		t.Fatalf("fixture mutation escaped ownership: %#v", second)
	}
	if second.Closure.Remaining == nil || len(second.Closure.Remaining) != 0 {
		t.Fatalf("explicit-empty Remaining presence changed: %#v", second.Closure.Remaining)
	}

	firstEvidence := newTestEvidence()
	secondEvidence := newTestEvidence()
	firstEvidence[0].Reference = "first-only"
	if secondEvidence[0].Reference != "go test ./..." {
		t.Fatalf("evidence fixtures alias: %#v", secondEvidence)
	}
}

func TestGoalTestFixturesSupportConcurrentIndependentMutation(t *testing.T) {
	t.Parallel()
	const fixtureCount = 32
	fixtures := make([]Receipt, fixtureCount)
	for index := range fixtures {
		fixtures[index] = closureReceipt()
	}

	var workers sync.WaitGroup
	workers.Add(len(fixtures))
	for index := range fixtures {
		go func(index int) {
			defer workers.Done()
			fixtures[index].Evidence[0].Result = "mutated"
			fixtures[index].Closure.NextWork[0].Result = "mutated"
			fixtures[index].Closure.Remaining = append(fixtures[index].Closure.Remaining, RemainingWork{Kind: "risk", Summary: "mutated"})
		}(index)
	}
	workers.Wait()

	for index, fixture := range fixtures {
		if fixture.Evidence[0].Result != "mutated" || fixture.Closure.NextWork[0].Result != "mutated" || len(fixture.Closure.Remaining) != 1 {
			t.Fatalf("fixture %d lost its independent mutation: %#v", index, fixture)
		}
	}
	canonical := closureReceipt()
	if canonical.Evidence[0].Result != "passed" || canonical.Closure.NextWork[0].Result != "canonical follow-up queue" || canonical.Closure.Remaining == nil || len(canonical.Closure.Remaining) != 0 {
		t.Fatalf("canonical fixture was mutated: %#v", canonical)
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
	for _, phase := range Phases() {
		if err := j.Advance(Receipt{Phase: phase, Summary: "complete", Evidence: newTestEvidence()}, testNow); err != nil {
			t.Fatal(err)
		}
		if phase == last {
			return
		}
	}
}

func closureReceipt() Receipt {
	return Receipt{Phase: PhaseClosure, Summary: "closure recorded", Evidence: newTestEvidence(), Closure: &ClosureDetails{AchievedOutcome: "release ready", Cleanup: "temporary artifacts removed", Remaining: make([]RemainingWork, 0), NextWork: []Evidence{{Type: EvidenceFile, Reference: "ROADMAP.md", Result: "canonical follow-up queue"}}}}
}

// TestPendingEvidenceCannotPoisonAnItem covers a state a journal could reach
// and never leave. Validate checked evidence only on completed items, but
// acceptance evidence is append-only for every item, so a malformed record
// staged on a pending one could never be removed and CompleteItem — which
// validates the combined set — refused forever. The journal stayed valid to
// Load and became impossible to finish without editing the file outside the
// contract.
func TestPendingEvidenceCannotPoisonAnItem(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	journal, err := New("probe", "probe intent", []ChecklistItem{{ID: "a1", Acceptance: "must hold"}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Evidence{
		"no result":       {Type: EvidenceTest, Reference: "ref"},
		"no reference":    {Type: EvidenceTest, Result: "passed"},
		"unknown type":    {Type: "rumour", Reference: "ref", Result: "passed"},
		"blank reference": {Type: EvidenceTest, Reference: "   ", Result: "passed"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := journal.Clone()
			candidate.Goal.Acceptance[0].Evidence = []Evidence{bad}
			if err := candidate.Validate(); err == nil {
				t.Fatal("a pending item accepted evidence that could never be completed")
			}
		})
	}

	// Staging well-formed evidence on a pending item stays legitimate, and the
	// item must still complete afterwards.
	staged := journal.Clone()
	staged.Goal.Acceptance[0].Evidence = []Evidence{{Type: EvidenceTest, Reference: "ref", Result: "passed"}}
	if err := staged.Validate(); err != nil {
		t.Fatalf("valid staged evidence rejected: %v", err)
	}
	if err := staged.CompleteItem("a1", []Evidence{{Type: EvidenceFile, Reference: "f", Result: "ok"}}, now); err != nil {
		t.Fatalf("a staged item could not be completed: %v", err)
	}
	if staged.Goal.Acceptance[0].Status != ItemComplete || len(staged.Goal.Acceptance[0].Evidence) != 2 {
		t.Fatalf("completion did not append: %#v", staged.Goal.Acceptance[0])
	}
}
