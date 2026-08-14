// SPDX-License-Identifier: AGPL-3.0-only

// Package observability provides provider-neutral lifecycle events and sinks.
// Events are derived observations; Task results and Goal journals remain the
// authoritative state.
package observability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion       = "v1alpha1"
	MaxEnvelopeBytes    = 64 << 10
	MaxAttributes       = 32
	MaxStringBytes      = 2048
	MaxCollectionItems  = 32
	MaxDepth            = 6
	DefaultMaxFileBytes = int64(64 << 20)
	MaximumMaxFileBytes = int64(1 << 30)
	MaxReplayEvents     = 100000
	MaxStreams          = 4096
)

type EventKind string

const (
	TaskValidated            EventKind = "task.validated"
	TaskStarted              EventKind = "task.started"
	TaskCompleted            EventKind = "task.completed"
	TaskFailed               EventKind = "task.failed"
	TaskBlocked              EventKind = "task.blocked"
	TaskCancelled            EventKind = "task.cancelled"
	GoalCreated              EventKind = "goal.created"
	GoalChecklistAdded       EventKind = "goal.checklist_added"
	GoalChecklistCompleted   EventKind = "goal.checklist_completed"
	GoalReceiptEvidenceAdded EventKind = "goal.receipt_evidence_added"
	GoalPhaseTransitioned    EventKind = "goal.phase_transitioned"
	GoalCompleted            EventKind = "goal.completed"
	GoalBlocked              EventKind = "goal.blocked"
	HandoffDispatched        EventKind = "handoff.dispatched"
	HandoffAccepted          EventKind = "handoff.accepted"
	HandoffCompleted         EventKind = "handoff.completed"
	HandoffFailed            EventKind = "handoff.failed"
	HandoffBlocked           EventKind = "handoff.blocked"
)

var eventKinds = map[EventKind]bool{TaskValidated: true, TaskStarted: true, TaskCompleted: true, TaskFailed: true, TaskBlocked: true, TaskCancelled: true, GoalCreated: true, GoalChecklistAdded: true, GoalChecklistCompleted: true, GoalReceiptEvidenceAdded: true, GoalPhaseTransitioned: true, GoalCompleted: true, GoalBlocked: true, HandoffDispatched: true, HandoffAccepted: true, HandoffCompleted: true, HandoffFailed: true, HandoffBlocked: true}

type SubjectKind string

const (
	SubjectTask    SubjectKind = "task"
	SubjectGoal    SubjectKind = "goal"
	SubjectHandoff SubjectKind = "handoff"
)

type Subject struct {
	Kind     SubjectKind `json:"kind"`
	ID       string      `json:"id"`
	Revision uint64      `json:"revision,omitempty"`
}

type ActorKind string

const (
	ActorBrain        ActorKind = "brain"
	ActorOrchestrator ActorKind = "orchestrator"
	ActorDispatcher   ActorKind = "dispatcher"
	ActorWorker       ActorKind = "worker"
	ActorRuntime      ActorKind = "runtime"
)

type Actor struct {
	Kind ActorKind `json:"kind"`
	ID   string    `json:"id"`
}
type Runtime struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Attempt string

const (
	AttemptInitial  Attempt = "initial"
	AttemptRetry    Attempt = "retry"
	AttemptRecovery Attempt = "recovery"
	AttemptReplay   Attempt = "replay"
)

type Outcome string

const (
	OutcomeObserved  Outcome = "observed"
	OutcomeStarted   Outcome = "started"
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeBlocked   Outcome = "blocked"
	OutcomeCancelled Outcome = "cancelled"
)

type ErrorCode string

const (
	ErrorValidation      ErrorCode = "validation_failed"
	ErrorExecution       ErrorCode = "execution_failed"
	ErrorTimeout         ErrorCode = "timeout"
	ErrorCancelled       ErrorCode = "cancelled"
	ErrorJournalConflict ErrorCode = "journal_conflict"
	ErrorJournalIO       ErrorCode = "journal_io"
	ErrorSinkDelivery    ErrorCode = "sink_delivery_failed"
)

type ErrorClass string

const (
	ErrorClassValidation   ErrorClass = "validation"
	ErrorClassExecution    ErrorClass = "execution"
	ErrorClassTimeout      ErrorClass = "timeout"
	ErrorClassCancellation ErrorClass = "cancellation"
	ErrorClassConcurrency  ErrorClass = "concurrency"
	ErrorClassStorage      ErrorClass = "storage"
	ErrorClassDelivery     ErrorClass = "delivery"
)

type BlockCode string

const (
	BlockApprovalRequired      BlockCode = "approval_required"
	BlockDependencyUnavailable BlockCode = "dependency_unavailable"
	BlockEvidenceMissing       BlockCode = "evidence_missing"
	BlockAuthorityRequired     BlockCode = "authority_required"
	BlockExternalState         BlockCode = "external_state"
)

type ErrorEvidence struct {
	Code      ErrorCode  `json:"code"`
	Class     ErrorClass `json:"class"`
	Retryable bool       `json:"retryable"`
}
type BlockingEvidence struct {
	Code                  BlockCode `json:"code"`
	RequiredEvidenceTypes []string  `json:"required_evidence_types,omitempty"`
}
type HandoffEvidence struct {
	From ActorKind `json:"from"`
	To   ActorKind `json:"to"`
}
type Payload struct {
	PreviousState    string            `json:"previous_state,omitempty"`
	State            string            `json:"state,omitempty"`
	PreviousPhase    string            `json:"previous_phase,omitempty"`
	Phase            string            `json:"phase,omitempty"`
	PreviousRevision uint64            `json:"previous_revision,omitempty"`
	Revision         uint64            `json:"revision,omitempty"`
	ChecklistChanges uint32            `json:"checklist_changes,omitempty"`
	EvidenceCount    uint32            `json:"evidence_count,omitempty"`
	EvidenceTypes    []string          `json:"evidence_types,omitempty"`
	DebtCount        uint32            `json:"debt_count,omitempty"`
	DebtKinds        []string          `json:"debt_kinds,omitempty"`
	Accepted         *bool             `json:"accepted,omitempty"`
	ExitCode         *int              `json:"exit_code,omitempty"`
	TimedOut         *bool             `json:"timed_out,omitempty"`
	Truncated        *bool             `json:"truncated,omitempty"`
	Error            *ErrorEvidence    `json:"error,omitempty"`
	Blocking         *BlockingEvidence `json:"blocking,omitempty"`
	Handoff          *HandoffEvidence  `json:"handoff,omitempty"`
}

type Sensitivity string

const (
	SensitivityPublic       Sensitivity = "public"
	SensitivityInternal     Sensitivity = "internal"
	SensitivityConfidential Sensitivity = "confidential"
	SensitivitySecret       Sensitivity = "secret"
)

type InputAttribute struct {
	Name        string
	Sensitivity Sensitivity
	Value       any
}

type Attribute struct {
	Name        string          `json:"name"`
	Sensitivity Sensitivity     `json:"sensitivity"`
	Value       json.RawMessage `json:"value"`
}

func (a Attribute) ValueJSON() []byte { return append([]byte(nil), a.Value...) }

type RedactionReason string

const (
	ReasonSensitivity    RedactionReason = "sensitivity"
	ReasonUnsafeName     RedactionReason = "unsafe_name"
	ReasonUnsupported    RedactionReason = "unsupported_type"
	ReasonBinary         RedactionReason = "binary"
	ReasonCycle          RedactionReason = "cycle"
	ReasonDepth          RedactionReason = "depth"
	ReasonCollection     RedactionReason = "collection_limit"
	ReasonString         RedactionReason = "string_limit"
	ReasonInvalidUTF8    RedactionReason = "invalid_utf8"
	ReasonAttributeLimit RedactionReason = "attribute_limit"
	ReasonUnsafeValue    RedactionReason = "unsafe_value"
)

type RedactionDecision struct {
	Reason RedactionReason `json:"reason"`
	Count  uint32          `json:"count"`
}

type Draft struct {
	Kind          EventKind
	Subject       Subject
	CorrelationID string
	CausationID   string
	Actor         Actor
	Attempt       Attempt
	Outcome       Outcome
	Payload       Payload
	Attributes    []InputAttribute
	Timestamp     time.Time
}

type envelopeWire struct {
	SchemaVersion string              `json:"schema_version"`
	EventID       string              `json:"event_id"`
	Kind          EventKind           `json:"kind"`
	Subject       Subject             `json:"subject"`
	CorrelationID string              `json:"correlation_id"`
	CausationID   string              `json:"causation_id,omitempty"`
	Sequence      uint64              `json:"sequence"`
	Timestamp     time.Time           `json:"timestamp"`
	Actor         Actor               `json:"actor"`
	Runtime       Runtime             `json:"runtime"`
	Attempt       Attempt             `json:"attempt"`
	Outcome       Outcome             `json:"outcome"`
	Payload       Payload             `json:"payload"`
	Attributes    []Attribute         `json:"attributes"`
	Redactions    []RedactionDecision `json:"redactions"`
}
type Envelope struct{ wire envelopeWire }

func (e Envelope) EventID() string              { return e.wire.EventID }
func (e Envelope) Kind() EventKind              { return e.wire.Kind }
func (e Envelope) Subject() Subject             { return e.wire.Subject }
func (e Envelope) Sequence() uint64             { return e.wire.Sequence }
func (e Envelope) Timestamp() time.Time         { return e.wire.Timestamp }
func (e Envelope) CorrelationID() string        { return e.wire.CorrelationID }
func (e Envelope) CausationID() string          { return e.wire.CausationID }
func (e Envelope) MarshalJSON() ([]byte, error) { return json.Marshal(e.wire) }
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var wire envelopeWire
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	if err := validateEnvelopeJSONShape(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("event must contain one JSON value")
	}
	candidate := Envelope{wire: wire}
	if err := candidate.Validate(); err != nil {
		return err
	}
	*e = candidate
	return nil
}

func validateEnvelopeJSONShape(data []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return errors.New("event must be a JSON object")
	}
	for _, name := range []string{"subject", "actor", "runtime", "payload"} {
		value, ok := object[name]
		value = bytes.TrimSpace(value)
		if !ok || len(value) == 0 || value[0] != '{' {
			return fmt.Errorf("event %s must be a present object", name)
		}
	}
	for _, name := range []string{"attributes", "redactions"} {
		value, ok := object[name]
		value = bytes.TrimSpace(value)
		if !ok || len(value) == 0 || value[0] != '[' {
			return fmt.Errorf("event %s must be a present array", name)
		}
	}
	return nil
}
func (e Envelope) CanonicalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(e.wire)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope exceeds %d bytes", MaxEnvelopeBytes)
	}
	return data, nil
}

var stableID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var eventID = regexp.MustCompile(`^evt_[0-9a-f]{32}$`)

func (e Envelope) Validate() error {
	w := e.wire
	if w.SchemaVersion != SchemaVersion {
		return errors.New("unsupported event schema_version")
	}
	if !eventID.MatchString(w.EventID) {
		return errors.New("invalid event_id")
	}
	if makeEventID(w) != w.EventID {
		return errors.New("event_id does not match canonical envelope")
	}
	if !eventKinds[w.Kind] {
		return errors.New("invalid event kind")
	}
	if !validSubject(w.Subject) {
		return errors.New("invalid subject")
	}
	if !safeID(w.CorrelationID) || (w.CausationID != "" && !eventID.MatchString(w.CausationID)) {
		return errors.New("invalid correlation or causation identity")
	}
	if w.Sequence == 0 || !validActor(w.Actor) || !safeID(w.Runtime.ID) || !safeID(w.Runtime.Version) {
		return errors.New("invalid sequence, actor, or runtime")
	}
	if w.Timestamp.IsZero() || w.Timestamp.Location() != time.UTC {
		return errors.New("timestamp must be UTC")
	}
	if !validAttempt(w.Attempt) || !validOutcome(w.Outcome) {
		return errors.New("invalid attempt or outcome")
	}
	if w.Attributes == nil || w.Redactions == nil {
		return errors.New("attributes and redactions must be present arrays")
	}
	if len(w.Attributes) > MaxAttributes {
		return errors.New("too many attributes")
	}
	if !sort.SliceIsSorted(w.Attributes, func(i, j int) bool { return w.Attributes[i].Name < w.Attributes[j].Name }) {
		return errors.New("attributes are not canonical")
	}
	for i, attribute := range w.Attributes {
		if !validAttributeName(attribute.Name) || unsafeName(attribute.Name) || (attribute.Sensitivity != SensitivityPublic && attribute.Sensitivity != SensitivityInternal) || !json.Valid(attribute.Value) {
			return errors.New("invalid safe attribute")
		}
		if i > 0 && w.Attributes[i-1].Name == attribute.Name {
			return errors.New("duplicate safe attribute")
		}
		if err := validateSafeJSON(attribute.Value); err != nil {
			return err
		}
		var value any
		decoder := json.NewDecoder(strings.NewReader(string(attribute.Value)))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid safe attribute JSON")
		}
		canonical, err := json.Marshal(value)
		if err != nil || string(canonical) != string(attribute.Value) {
			return errors.New("safe attribute JSON is not canonical")
		}
	}
	if !sort.SliceIsSorted(w.Redactions, func(i, j int) bool { return w.Redactions[i].Reason < w.Redactions[j].Reason }) {
		return errors.New("redactions are not canonical")
	}
	for i, decision := range w.Redactions {
		if decision.Count == 0 || !validReason(decision.Reason) || (i > 0 && w.Redactions[i-1].Reason == decision.Reason) {
			return errors.New("invalid redaction decision")
		}
	}
	if err := validatePayload(w.Payload); err != nil {
		return err
	}
	if expected := subjectForKind(w.Kind); expected != w.Subject.Kind {
		return errors.New("event kind and subject mismatch")
	}
	if err := validateEventSemantics(w.Kind, w.Subject, w.Outcome, w.Payload); err != nil {
		return err
	}
	return nil
}
func validSubject(s Subject) bool {
	if !safeID(s.ID) {
		return false
	}
	if s.Kind == SubjectGoal {
		return s.Revision > 0
	}
	return (s.Kind == SubjectTask || s.Kind == SubjectHandoff) && s.Revision == 0
}
func validActor(a Actor) bool {
	return (a.Kind == ActorBrain || a.Kind == ActorOrchestrator || a.Kind == ActorDispatcher || a.Kind == ActorWorker || a.Kind == ActorRuntime) && safeID(a.ID)
}

// safeID validates an identity: a runtime, sink, correlation, subject or actor
// name. It deliberately does not apply the redaction word list, which exists to
// keep secret-looking attribute *values* out of a sink. An identifier carries no
// value, and filtering it there rejected Task identities the manifest contract
// accepts — "run-command" or "fetch-url", and "curl" for containing "url".
func safeID(value string) bool { return stableID.MatchString(value) }
func validAttempt(a Attempt) bool {
	return a == AttemptInitial || a == AttemptRetry || a == AttemptRecovery || a == AttemptReplay
}
func validOutcome(o Outcome) bool {
	return o == OutcomeObserved || o == OutcomeStarted || o == OutcomeSucceeded || o == OutcomeFailed || o == OutcomeBlocked || o == OutcomeCancelled
}
func makeEventID(w envelopeWire) string {
	w.EventID = ""
	data, _ := json.Marshal(w)
	sum := sha256.Sum256(data)
	return "evt_" + hex.EncodeToString(sum[:16])
}
func canonicalStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func subjectForKind(kind EventKind) SubjectKind {
	switch {
	case strings.HasPrefix(string(kind), "task."):
		return SubjectTask
	case strings.HasPrefix(string(kind), "goal."):
		return SubjectGoal
	default:
		return SubjectHandoff
	}
}
func validReason(reason RedactionReason) bool {
	switch reason {
	case ReasonSensitivity, ReasonUnsafeName, ReasonUnsupported, ReasonBinary, ReasonCycle, ReasonDepth, ReasonCollection, ReasonString, ReasonInvalidUTF8, ReasonAttributeLimit, ReasonUnsafeValue:
		return true
	}
	return false
}
func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorValidation, ErrorExecution, ErrorTimeout, ErrorCancelled, ErrorJournalConflict, ErrorJournalIO, ErrorSinkDelivery:
		return true
	}
	return false
}
func validErrorClass(class ErrorClass) bool {
	switch class {
	case ErrorClassValidation, ErrorClassExecution, ErrorClassTimeout, ErrorClassCancellation, ErrorClassConcurrency, ErrorClassStorage, ErrorClassDelivery:
		return true
	}
	return false
}
func validBlockCode(code BlockCode) bool {
	switch code {
	case BlockApprovalRequired, BlockDependencyUnavailable, BlockEvidenceMissing, BlockAuthorityRequired, BlockExternalState:
		return true
	}
	return false
}
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if seen[key] {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("JSON contains trailing value")
	}
	return nil
}
func validateSafeJSON(raw []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("invalid attribute JSON")
	}
	return validateSafeValue(value, 0)
}
func validateSafeValue(value any, depth int) error {
	if depth > MaxDepth {
		return errors.New("attribute exceeds depth limit")
	}
	switch typed := value.(type) {
	case nil, bool, json.Number:
		return nil
	case string:
		if len(typed) > MaxStringBytes || !utf8.ValidString(typed) {
			return errors.New("invalid safe string")
		}
		return nil
	case []any:
		if len(typed) > MaxCollectionItems {
			return errors.New("attribute collection exceeds limit")
		}
		for _, item := range typed {
			if err := validateSafeValue(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if len(typed) > MaxCollectionItems {
			return errors.New("attribute map exceeds limit")
		}
		for key, item := range typed {
			if !validNestedName(key) || unsafeName(key) {
				return errors.New("unsafe nested attribute key")
			}
			if err := validateSafeValue(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unsupported safe JSON value")
	}
}
