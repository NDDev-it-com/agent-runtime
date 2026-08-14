// SPDX-License-Identifier: AGPL-3.0-only

// Package goal implements the durable Goal journal and phase state machine.
package goal

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

const SchemaVersion = "v1alpha1"

const (
	MaxEvidenceRecords    = 64
	MaxEvidenceFieldBytes = 2048
)

type State string

const (
	StateActive    State = "active"
	StateCompleted State = "completed"
)

type Phase string

const (
	PhaseOrient        Phase = "orient"
	PhaseGapPlan       Phase = "gap_plan"
	PhaseExecute       Phase = "execute"
	PhaseReconcile     Phase = "reconcile"
	PhaseSelfReview    Phase = "self_review"
	PhaseOmissionAudit Phase = "completeness_omission_audit"
	PhaseVerify        Phase = "verify"
	PhaseClosure       Phase = "closure"
)

// phases is the canonical ordered phase enumeration. It is unexported so that no
// caller can reorder the state machine for the whole process.
var phases = [8]Phase{PhaseOrient, PhaseGapPlan, PhaseExecute, PhaseReconcile, PhaseSelfReview, PhaseOmissionAudit, PhaseVerify, PhaseClosure}

// Phases returns the canonical phase order. The result is a copy, so mutating it
// cannot change the state machine.
func Phases() []Phase { return append([]Phase(nil), phases[:]...) }

type ErrorCode string

const (
	CodeInvalidGoal         ErrorCode = "invalid_goal"
	CodeInvalidTransition   ErrorCode = "invalid_transition"
	CodeIncompleteChecklist ErrorCode = "incomplete_checklist"
	CodeMissingReceipt      ErrorCode = "missing_receipt"
	CodeConflict            ErrorCode = "conflict"
	CodeJournalIO           ErrorCode = "journal_io"
)

type Error struct {
	Code    ErrorCode
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}
func (e *Error) Unwrap() error { return e.Cause }
func IsCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code == code
}

type EvidenceType string

const (
	EvidenceCommand EvidenceType = "command"
	EvidenceFile    EvidenceType = "file"
	EvidenceLink    EvidenceType = "link"
	EvidenceCommit  EvidenceType = "commit"
	EvidenceTest    EvidenceType = "test"
	EvidenceIssue   EvidenceType = "issue"
)

type Evidence struct {
	Type      EvidenceType `json:"type"`
	Reference string       `json:"reference"`
	Result    string       `json:"result"`
}

type Receipt struct {
	Phase      Phase           `json:"phase"`
	Summary    string          `json:"summary"`
	Evidence   []Evidence      `json:"evidence"`
	RecordedAt time.Time       `json:"recorded_at"`
	Closure    *ClosureDetails `json:"closure,omitempty"`
}

type RemainingKind string

const (
	RemainingDebt RemainingKind = "debt"
	RemainingRisk RemainingKind = "risk"
)

type RemainingWork struct {
	Kind    RemainingKind `json:"kind"`
	Summary string        `json:"summary"`
}
type ClosureDetails struct {
	AchievedOutcome string          `json:"achieved_outcome"`
	Cleanup         string          `json:"cleanup"`
	Remaining       []RemainingWork `json:"remaining"`
	NextWork        []Evidence      `json:"next_work"`
}

type ItemStatus string

const (
	ItemPending  ItemStatus = "pending"
	ItemComplete ItemStatus = "complete"
)

type ChecklistItem struct {
	ID         string     `json:"id"`
	Acceptance string     `json:"acceptance"`
	Status     ItemStatus `json:"status"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

type Goal struct {
	ID           string            `json:"id"`
	Intent       string            `json:"intent"`
	Acceptance   []ChecklistItem   `json:"acceptance"`
	NonGoals     []string          `json:"non_goals,omitempty"`
	State        State             `json:"state"`
	CurrentPhase Phase             `json:"current_phase"`
	Receipts     map[Phase]Receipt `json:"receipts"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

type Journal struct {
	SchemaVersion string `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Goal          Goal   `json:"goal"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

func New(id, intent string, acceptance []ChecklistItem, nonGoals []string, now time.Time) (Journal, error) {
	items := make([]ChecklistItem, len(acceptance))
	for i := range acceptance {
		items[i] = acceptance[i]
		items[i].Status = ItemPending
		items[i].Evidence = nil
	}
	j := Journal{SchemaVersion: SchemaVersion, Revision: 1, Goal: Goal{ID: id, Intent: strings.TrimSpace(intent), Acceptance: items, NonGoals: cloneStrings(nonGoals), State: StateActive, CurrentPhase: PhaseOrient, Receipts: map[Phase]Receipt{}, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}}
	if err := j.Validate(); err != nil {
		return Journal{}, err
	}
	return j, nil
}

func (j Journal) Validate() error {
	if j.SchemaVersion != SchemaVersion {
		return invalid("schema_version must be " + SchemaVersion)
	}
	if j.Revision == 0 {
		return invalid("revision must be positive")
	}
	if !idPattern.MatchString(j.Goal.ID) {
		return invalid("goal id has invalid format")
	}
	if strings.TrimSpace(j.Goal.Intent) == "" {
		return invalid("goal intent is required")
	}
	if len(j.Goal.Acceptance) == 0 {
		return invalid("goal acceptance checklist is required")
	}
	seen := map[string]bool{}
	for _, item := range j.Goal.Acceptance {
		if !idPattern.MatchString(item.ID) || strings.TrimSpace(item.Acceptance) == "" {
			return invalid("checklist item id and acceptance are required")
		}
		if seen[item.ID] {
			return invalid("duplicate checklist item: " + item.ID)
		}
		seen[item.ID] = true
		if item.Status != ItemPending && item.Status != ItemComplete {
			return invalid("invalid checklist status for " + item.ID)
		}
		// A completed item must carry evidence. A pending one need not, but any
		// evidence it does carry must already be valid, because acceptance
		// evidence is append-only: a malformed record accepted here can never be
		// removed, and CompleteItem validates the combined set, so the item
		// becomes permanently uncompletable. Validating only completed items
		// left that state reachable through any generic mutation.
		switch {
		case item.Status == ItemComplete:
			if validateEvidence(item.Evidence) != nil {
				return invalid("completed checklist item lacks valid evidence: " + item.ID)
			}
		case len(item.Evidence) > 0:
			if validateEvidence(item.Evidence) != nil {
				return invalid("pending checklist item carries evidence that could never be completed: " + item.ID)
			}
		}
	}
	if phaseIndex(j.Goal.CurrentPhase) < 0 {
		return invalid("invalid current_phase")
	}
	if j.Goal.State != StateActive && j.Goal.State != StateCompleted {
		return invalid("invalid goal state")
	}
	if j.Goal.Receipts == nil {
		return invalid("receipts must be an object")
	}
	if j.Goal.CreatedAt.IsZero() || j.Goal.UpdatedAt.Before(j.Goal.CreatedAt) {
		return invalid("goal timestamps are invalid")
	}
	for _, value := range j.Goal.NonGoals {
		if strings.TrimSpace(value) == "" {
			return invalid("non-goals must not be empty")
		}
	}
	for phase, receipt := range j.Goal.Receipts {
		if phaseIndex(phase) < 0 || receipt.Phase != phase || strings.TrimSpace(receipt.Summary) == "" || validateEvidence(receipt.Evidence) != nil || receipt.RecordedAt.IsZero() || validateClosure(receipt) != nil {
			return invalid("invalid receipt for phase " + string(phase))
		}
	}
	current := phaseIndex(j.Goal.CurrentPhase)
	if j.Goal.State == StateActive {
		for i, phase := range phases {
			_, exists := j.Goal.Receipts[phase]
			if exists != (i < current) {
				return invalid("receipts do not match current phase")
			}
		}
	}
	if j.Goal.State == StateCompleted {
		if j.Goal.CurrentPhase != PhaseClosure {
			return invalid("completed goal must be at closure")
		}
		if err := j.completionPrerequisites(); err != nil {
			return invalid("completed goal violates prerequisites: " + err.Error())
		}
	}
	return nil
}

// Clone returns a deep copy. A Journal value holds a receipts map and evidence
// slices, so plain assignment shares mutable state with the original and a
// "before" snapshot taken that way silently reflects later mutations. Callers
// that compare two points of one Goal's history must Clone.
func (j Journal) Clone() Journal {
	out := j
	out.Goal.NonGoals = cloneStrings(j.Goal.NonGoals)
	if j.Goal.Acceptance != nil {
		items := make([]ChecklistItem, len(j.Goal.Acceptance))
		for index, item := range j.Goal.Acceptance {
			item.Evidence = cloneEvidence(item.Evidence)
			items[index] = item
		}
		out.Goal.Acceptance = items
	}
	if j.Goal.Receipts != nil {
		receipts := make(map[Phase]Receipt, len(j.Goal.Receipts))
		for phase, receipt := range j.Goal.Receipts {
			receipts[phase] = cloneReceipt(receipt)
		}
		out.Goal.Receipts = receipts
	}
	return out
}

// IsGenesis reports whether j is an unstarted Goal: revision one, the first
// phase, no receipts, and no recorded acceptance evidence. Only a genesis
// journal may be created; every later state must be reached through a
// validated transition.
func (j Journal) IsGenesis() bool {
	if j.Revision != 1 || j.Goal.State != StateActive || j.Goal.CurrentPhase != phases[0] || len(j.Goal.Receipts) != 0 {
		return false
	}
	for _, item := range j.Goal.Acceptance {
		if item.Status != ItemPending || len(item.Evidence) != 0 {
			return false
		}
	}
	return true
}

// ValidateTransitionFrom reports whether j is a legitimate successor of before.
// Structural validity alone is not enough for a durable journal: identity,
// sealed receipts and recorded acceptance history must survive every mutation.
// Store applies this to the result of a caller-supplied mutation, so a generic
// callback cannot persist a structurally valid but historically false journal.
func (j Journal) ValidateTransitionFrom(before Journal) error {
	if before.Goal.State != StateActive {
		return transition("completed goals are immutable")
	}
	if j.Revision <= before.Revision {
		return invalid("mutation did not advance revision")
	}
	if j.SchemaVersion != before.SchemaVersion || j.Goal.ID != before.Goal.ID || j.Goal.Intent != before.Goal.Intent || !j.Goal.CreatedAt.Equal(before.Goal.CreatedAt) {
		return invalid("goal identity is immutable")
	}
	if !slices.Equal(j.Goal.NonGoals, before.Goal.NonGoals) {
		return invalid("goal non-goals are immutable")
	}
	if j.Goal.UpdatedAt.Before(before.Goal.UpdatedAt) {
		return invalid("goal updated_at moved backwards")
	}
	from, to := phaseIndex(before.Goal.CurrentPhase), phaseIndex(j.Goal.CurrentPhase)
	if from < 0 || to < from || to > from+1 {
		return transition("phase may only advance by one")
	}
	if err := validateReceiptSuccession(before.Goal.Receipts, j.Goal.Receipts); err != nil {
		return err
	}
	return validateAcceptanceSuccession(before.Goal.Acceptance, j.Goal.Acceptance)
}

func validateReceiptSuccession(before, after map[Phase]Receipt) error {
	for phase, sealed := range before {
		current, exists := after[phase]
		if !exists {
			return invalid("receipt was removed for phase " + string(phase))
		}
		if current.Phase != sealed.Phase || current.Summary != sealed.Summary || !current.RecordedAt.Equal(sealed.RecordedAt) {
			return invalid("sealed receipt was rewritten for phase " + string(phase))
		}
		if !equalClosure(current.Closure, sealed.Closure) {
			return invalid("sealed closure was rewritten for phase " + string(phase))
		}
		if !isEvidencePrefix(sealed.Evidence, current.Evidence) {
			return invalid("receipt evidence is append-only for phase " + string(phase))
		}
	}
	return nil
}

func validateAcceptanceSuccession(before, after []ChecklistItem) error {
	if len(after) < len(before) {
		return invalid("acceptance checklist items cannot be removed")
	}
	for index, sealed := range before {
		current := after[index]
		if current.ID != sealed.ID || current.Acceptance != sealed.Acceptance {
			return invalid("acceptance criterion is immutable: " + sealed.ID)
		}
		if sealed.Status == ItemComplete && current.Status != ItemComplete {
			return invalid("completed acceptance item cannot revert: " + sealed.ID)
		}
		if !isEvidencePrefix(sealed.Evidence, current.Evidence) {
			return invalid("acceptance evidence is append-only: " + sealed.ID)
		}
	}
	return nil
}

func isEvidencePrefix(sealed, current []Evidence) bool {
	return len(current) >= len(sealed) && slices.Equal(sealed, current[:len(sealed)])
}

func equalClosure(a, b *ClosureDetails) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.AchievedOutcome == b.AchievedOutcome && a.Cleanup == b.Cleanup && slices.Equal(a.Remaining, b.Remaining) && slices.Equal(a.NextWork, b.NextWork)
}

func (j *Journal) CompleteItem(id string, evidence []Evidence, now time.Time) error {
	if err := j.Validate(); err != nil {
		return err
	}
	if j.Goal.State != StateActive {
		return transition("completed goals are immutable")
	}
	if err := validateEvidence(evidence); err != nil {
		return err
	}
	for i := range j.Goal.Acceptance {
		if j.Goal.Acceptance[i].ID != id {
			continue
		}
		combined := append(cloneEvidence(j.Goal.Acceptance[i].Evidence), evidence...)
		if err := validateEvidence(combined); err != nil {
			return err
		}
		j.Goal.Acceptance[i].Status = ItemComplete
		j.Goal.Acceptance[i].Evidence = combined
		j.touch(now)
		return nil
	}
	return invalid("unknown checklist item: " + id)
}

func (j *Journal) AddChecklistItem(item ChecklistItem, now time.Time) error {
	if err := j.Validate(); err != nil {
		return err
	}
	if j.Goal.State != StateActive {
		return transition("completed goals are immutable")
	}
	if !idPattern.MatchString(item.ID) || strings.TrimSpace(item.Acceptance) == "" {
		return invalid("checklist item id and acceptance are required")
	}
	for _, existing := range j.Goal.Acceptance {
		if existing.ID == item.ID {
			return invalid("duplicate checklist item: " + item.ID)
		}
	}
	item.Status = ItemPending
	item.Evidence = nil
	j.Goal.Acceptance = append(j.Goal.Acceptance, item)
	j.touch(now)
	return nil
}

// AddReceiptEvidence appends immutable evidence discovered after a phase
// transition. It cannot alter the receipt summary or remove prior evidence.
func (j *Journal) AddReceiptEvidence(phase Phase, evidence Evidence, now time.Time) error {
	if err := j.Validate(); err != nil {
		return err
	}
	if j.Goal.State != StateActive {
		return transition("completed goals are immutable")
	}
	if err := validateEvidence([]Evidence{evidence}); err != nil {
		return err
	}
	receipt, ok := j.Goal.Receipts[phase]
	if !ok {
		return invalid("phase has no receipt: " + string(phase))
	}
	for _, existing := range receipt.Evidence {
		if existing == evidence {
			return invalid("duplicate receipt evidence")
		}
	}
	combined := cloneEvidence(receipt.Evidence)
	combined = append(combined, evidence)
	if err := validateEvidence(combined); err != nil {
		return err
	}
	receipt.Evidence = combined
	j.Goal.Receipts[phase] = receipt
	j.touch(now)
	return nil
}

func (j *Journal) Advance(receipt Receipt, now time.Time) error {
	if err := j.Validate(); err != nil {
		return err
	}
	if j.Goal.State != StateActive {
		return transition("completed goals are immutable")
	}
	if receipt.Phase != j.Goal.CurrentPhase {
		return transition(fmt.Sprintf("expected phase %s, got %s", j.Goal.CurrentPhase, receipt.Phase))
	}
	if strings.TrimSpace(receipt.Summary) == "" {
		return &Error{Code: CodeMissingReceipt, Message: "receipt summary is required"}
	}
	if err := validateEvidence(receipt.Evidence); err != nil {
		return err
	}
	if err := validateClosure(receipt); err != nil {
		return err
	}
	if _, exists := j.Goal.Receipts[receipt.Phase]; exists {
		return transition("phase already has a receipt")
	}
	receipt = cloneReceipt(receipt)
	receipt.RecordedAt = now.UTC()
	j.Goal.Receipts[receipt.Phase] = receipt
	index := phaseIndex(receipt.Phase)
	if receipt.Phase == PhaseClosure {
		if err := j.completionPrerequisites(); err != nil {
			delete(j.Goal.Receipts, receipt.Phase)
			return err
		}
		j.Goal.State = StateCompleted
	} else {
		j.Goal.CurrentPhase = phases[index+1]
	}
	j.touch(now)
	return nil
}

func (j Journal) completionPrerequisites() error {
	for _, item := range j.Goal.Acceptance {
		if item.Status != ItemComplete {
			return &Error{Code: CodeIncompleteChecklist, Message: "checklist item is not complete: " + item.ID}
		}
	}
	for _, phase := range phases {
		if _, ok := j.Goal.Receipts[phase]; !ok {
			return &Error{Code: CodeMissingReceipt, Message: "missing phase receipt: " + string(phase)}
		}
	}
	return nil
}

func (j *Journal) touch(now time.Time) { j.Revision++; j.Goal.UpdatedAt = now.UTC() }
func phaseIndex(phase Phase) int {
	for i, candidate := range phases {
		if candidate == phase {
			return i
		}
	}
	return -1
}
func validateEvidence(items []Evidence) error {
	if len(items) == 0 {
		return &Error{Code: CodeMissingReceipt, Message: "at least one evidence record is required"}
	}
	if len(items) > MaxEvidenceRecords {
		return &Error{Code: CodeInvalidGoal, Message: "evidence record limit exceeded"}
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		validType := item.Type == EvidenceCommand || item.Type == EvidenceFile || item.Type == EvidenceLink || item.Type == EvidenceCommit || item.Type == EvidenceTest || item.Type == EvidenceIssue
		reference, result := strings.TrimSpace(item.Reference), strings.TrimSpace(item.Result)
		if !validType || reference == "" || result == "" || len(item.Reference) > MaxEvidenceFieldBytes || len(item.Result) > MaxEvidenceFieldBytes {
			return &Error{Code: CodeMissingReceipt, Message: "evidence type, reference, and result are required"}
		}
		key := string(item.Type) + "\x00" + reference
		if seen[key] {
			return &Error{Code: CodeInvalidGoal, Message: "duplicate or conflicting evidence identity"}
		}
		seen[key] = true
	}
	return nil
}

func cloneStrings(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	copy(out, items)
	return out
}

func cloneEvidence(items []Evidence) []Evidence {
	if items == nil {
		return nil
	}
	out := make([]Evidence, len(items))
	copy(out, items)
	return out
}

func cloneRemaining(items []RemainingWork) []RemainingWork {
	if items == nil {
		return nil
	}
	out := make([]RemainingWork, len(items))
	copy(out, items)
	return out
}

func cloneReceipt(receipt Receipt) Receipt {
	receipt.Evidence = cloneEvidence(receipt.Evidence)
	if receipt.Closure != nil {
		closure := *receipt.Closure
		closure.Remaining = cloneRemaining(receipt.Closure.Remaining)
		closure.NextWork = cloneEvidence(receipt.Closure.NextWork)
		receipt.Closure = &closure
	}
	return receipt
}
func validateClosure(receipt Receipt) error {
	if receipt.Phase != PhaseClosure {
		if receipt.Closure != nil {
			return &Error{Code: CodeInvalidGoal, Message: "closure details are only valid for closure phase"}
		}
		return nil
	}
	if receipt.Closure == nil {
		return &Error{Code: CodeMissingReceipt, Message: "closure details are required"}
	}
	c := receipt.Closure
	if strings.TrimSpace(c.AchievedOutcome) == "" || strings.TrimSpace(c.Cleanup) == "" || c.Remaining == nil || c.NextWork == nil {
		return &Error{Code: CodeMissingReceipt, Message: "closure requires achieved_outcome, cleanup, explicit remaining list, and explicit next_work list"}
	}
	for _, item := range c.Remaining {
		if (item.Kind != RemainingDebt && item.Kind != RemainingRisk) || strings.TrimSpace(item.Summary) == "" {
			return &Error{Code: CodeInvalidGoal, Message: "remaining work requires debt/risk kind and summary"}
		}
	}
	if len(c.NextWork) == 0 {
		return &Error{Code: CodeMissingReceipt, Message: "closure requires canonical next_work evidence"}
	}
	if err := validateEvidence(c.NextWork); err != nil {
		return err
	}
	return nil
}
func invalid(message string) error    { return &Error{Code: CodeInvalidGoal, Message: message} }
func transition(message string) error { return &Error{Code: CodeInvalidTransition, Message: message} }
