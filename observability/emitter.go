// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"errors"
	"sync"
	"time"
)

type SinkErrorCode string

const (
	SinkUnavailable        SinkErrorCode = "unavailable"
	SinkBackpressure       SinkErrorCode = "backpressure"
	SinkClosed             SinkErrorCode = "closed"
	SinkPartialWrite       SinkErrorCode = "partial_write"
	SinkCorruptData        SinkErrorCode = "corrupt_data"
	SinkUnsupportedVersion SinkErrorCode = "unsupported_version"
	SinkContext            SinkErrorCode = "context"
	SinkFailure            SinkErrorCode = "failure"
)

type SinkError struct {
	Code      SinkErrorCode
	Retryable bool
}

func (e *SinkError) Error() string { return "observability sink " + string(e.Code) }

type WriteResult struct{ Duplicate bool }
type Sink interface {
	Name() string
	Write(context.Context, Envelope) (WriteResult, error)
	Flush(context.Context) error
	Close(context.Context) error
}

type SinkDelivery struct {
	Name      string        `json:"name"`
	Attempts  uint32        `json:"attempts"`
	Delivered bool          `json:"delivered"`
	Duplicate bool          `json:"duplicate"`
	ErrorCode SinkErrorCode `json:"error_code,omitempty"`
	Retryable bool          `json:"retryable,omitempty"`
}
type DeliveryReport struct {
	EventID string         `json:"event_id"`
	Sinks   []SinkDelivery `json:"sinks"`
}

func (r DeliveryReport) Succeeded() bool {
	if len(r.Sinks) == 0 {
		return false
	}
	for _, sink := range r.Sinks {
		if !sink.Delivered {
			return false
		}
	}
	return true
}

type Options struct {
	Policy           Policy
	Clock            func() time.Time
	InitialSequences map[string]uint64
	MaxAttempts      uint32
}
type Emitter struct {
	mu          sync.Mutex
	runtime     Runtime
	policy      Policy
	clock       func() time.Time
	sequences   map[string]uint64
	sinks       []Sink
	maxAttempts uint32
	closed      bool
}

func NewEmitter(runtime Runtime, sinks []Sink, options Options) (*Emitter, error) {
	if !safeID(runtime.ID) || !safeID(runtime.Version) {
		return nil, errors.New("invalid runtime identity")
	}
	if len(sinks) == 0 {
		return nil, errors.New("at least one sink is required")
	}
	names := map[string]bool{}
	copied := append([]Sink(nil), sinks...)
	for _, sink := range copied {
		if sink == nil || !safeID(sink.Name()) || names[sink.Name()] {
			return nil, errors.New("sinks require unique stable names")
		}
		names[sink.Name()] = true
	}
	policy := options.Policy
	if policy.MaxSensitivity == "" {
		policy = DefaultPolicy()
	}
	// An envelope may only carry public or internal attributes, so a higher
	// maximum would let Redact pass an attribute that envelope validation then
	// rejects, discarding the whole observation. Refuse it at construction.
	if policy.MaxSensitivity != SensitivityPublic && policy.MaxSensitivity != SensitivityInternal {
		return nil, errors.New("maximum sensitivity must be public or internal")
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	attempts := options.MaxAttempts
	if attempts == 0 {
		attempts = 1
	}
	if attempts > 5 {
		return nil, errors.New("max attempts exceeds 5")
	}
	sequences := map[string]uint64{}
	for key, value := range options.InitialSequences {
		if key == "" {
			return nil, errors.New("invalid initial sequence key")
		}
		sequences[key] = value
	}
	if len(sequences) > MaxStreams {
		return nil, errors.New("initial sequence streams exceed limit")
	}
	return &Emitter{runtime: runtime, policy: policy, clock: clock, sequences: sequences, sinks: copied, maxAttempts: attempts}, nil
}

func (e *Emitter) Emit(ctx context.Context, draft Draft) (Envelope, DeliveryReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return Envelope{}, DeliveryReport{}, errors.New("emitter is closed")
	}
	// Canonicalize before validating. The validator requires canonical collection
	// order, so a draft whose collections were built from a Go map would otherwise
	// be rejected for an ordering the emitter is about to impose anyway.
	draft.Payload = canonicalPayload(draft.Payload)
	if err := validateDraft(draft); err != nil {
		return Envelope{}, DeliveryReport{}, err
	}
	key := streamKey(draft.Subject)
	if _, exists := e.sequences[key]; !exists && len(e.sequences) >= MaxStreams {
		return Envelope{}, DeliveryReport{}, errors.New("event stream limit exceeded")
	}
	sequence := e.sequences[key] + 1
	timestamp := draft.Timestamp
	if timestamp.IsZero() {
		timestamp = e.clock()
	}
	timestamp = timestamp.UTC()
	attributes, redactions, err := e.policy.Redact(draft.Attributes)
	if err != nil {
		return Envelope{}, DeliveryReport{}, err
	}
	wire := envelopeWire{SchemaVersion: SchemaVersion, Kind: draft.Kind, Subject: draft.Subject, CorrelationID: draft.CorrelationID, CausationID: draft.CausationID, Sequence: sequence, Timestamp: timestamp, Actor: draft.Actor, Runtime: e.runtime, Attempt: draft.Attempt, Outcome: draft.Outcome, Payload: draft.Payload, Attributes: attributes, Redactions: redactions}
	wire.EventID = makeEventID(wire)
	envelope := Envelope{wire: wire}
	if _, err := envelope.CanonicalJSON(); err != nil {
		return Envelope{}, DeliveryReport{}, err
	}
	e.sequences[key] = sequence
	report := e.deliverLocked(ctx, envelope)
	return envelope, report, nil
}

func (e *Emitter) Replay(ctx context.Context, envelope Envelope) DeliveryReport {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return failedReport(envelope.EventID(), e.sinks, SinkClosed, false)
	}
	if err := envelope.Validate(); err != nil {
		return failedReport(envelope.EventID(), e.sinks, SinkCorruptData, false)
	}
	return e.deliverLocked(ctx, envelope)
}
func (e *Emitter) deliverLocked(ctx context.Context, envelope Envelope) DeliveryReport {
	report := DeliveryReport{EventID: envelope.EventID(), Sinks: make([]SinkDelivery, 0, len(e.sinks))}
	for _, sink := range e.sinks {
		delivery := SinkDelivery{Name: sink.Name()}
		for attempt := uint32(1); attempt <= e.maxAttempts; attempt++ {
			delivery.Attempts = attempt
			if err := ctx.Err(); err != nil {
				delivery.ErrorCode = SinkContext
				break
			}
			result, err := sink.Write(ctx, envelope)
			if err == nil {
				delivery.Delivered = true
				delivery.Duplicate = result.Duplicate
				delivery.ErrorCode = ""
				break
			}
			code, retryable := classifySinkError(err)
			delivery.ErrorCode = code
			delivery.Retryable = retryable
			if !retryable {
				break
			}
		}
		report.Sinks = append(report.Sinks, delivery)
	}
	return report
}

func (e *Emitter) Flush(ctx context.Context) []SinkDelivery {
	e.mu.Lock()
	defer e.mu.Unlock()
	return operate(ctx, e.sinks, func(s Sink) error { return s.Flush(ctx) })
}
func (e *Emitter) Close(ctx context.Context) []SinkDelivery {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return operateClosed(e.sinks)
	}
	results := operate(ctx, e.sinks, func(s Sink) error { return s.Close(ctx) })
	e.closed = true
	return results
}
func operate(ctx context.Context, sinks []Sink, call func(Sink) error) []SinkDelivery {
	out := make([]SinkDelivery, 0, len(sinks))
	for _, sink := range sinks {
		d := SinkDelivery{Name: sink.Name(), Attempts: 1}
		if err := ctx.Err(); err != nil {
			d.ErrorCode = SinkContext
		} else if err := call(sink); err != nil {
			d.ErrorCode, d.Retryable = classifySinkError(err)
		} else {
			d.Delivered = true
		}
		out = append(out, d)
	}
	return out
}
func operateClosed(sinks []Sink) []SinkDelivery {
	return failedReport("", sinks, SinkClosed, false).Sinks
}
func failedReport(id string, sinks []Sink, code SinkErrorCode, retryable bool) DeliveryReport {
	report := DeliveryReport{EventID: id}
	for _, sink := range sinks {
		report.Sinks = append(report.Sinks, SinkDelivery{Name: sink.Name(), ErrorCode: code, Retryable: retryable})
	}
	return report
}
func classifySinkError(err error) (SinkErrorCode, bool) {
	var typed *SinkError
	if errors.As(err, &typed) {
		return typed.Code, typed.Retryable
	}
	return SinkFailure, false
}
func streamKey(subject Subject) string { return string(subject.Kind) + ":" + subject.ID }

func validateDraft(d Draft) error {
	if !eventKinds[d.Kind] || !validSubject(d.Subject) || !safeID(d.CorrelationID) || (d.CausationID != "" && !eventID.MatchString(d.CausationID)) || !validActor(d.Actor) || !validAttempt(d.Attempt) || !validOutcome(d.Outcome) {
		return errors.New("invalid event draft identity or vocabulary")
	}
	if !d.Timestamp.IsZero() && d.Timestamp.Location() != time.UTC {
		return errors.New("explicit timestamp must be UTC")
	}
	if err := validatePayload(d.Payload); err != nil {
		return err
	}
	if subjectForKind(d.Kind) != d.Subject.Kind {
		return errors.New("event kind and subject mismatch")
	}
	return validateEventSemantics(d.Kind, d.Subject, d.Outcome, d.Payload)
}

func validateEventSemantics(kind EventKind, subject Subject, outcome Outcome, p Payload) error {
	wantOutcome := map[EventKind]Outcome{
		TaskValidated: OutcomeObserved, TaskStarted: OutcomeStarted, TaskCompleted: OutcomeSucceeded,
		TaskFailed: OutcomeFailed, TaskBlocked: OutcomeBlocked, TaskCancelled: OutcomeCancelled,
		GoalCreated:        OutcomeObserved,
		GoalChecklistAdded: OutcomeObserved, GoalChecklistCompleted: OutcomeObserved,
		GoalReceiptEvidenceAdded: OutcomeObserved, GoalPhaseTransitioned: OutcomeObserved,
		GoalCompleted: OutcomeSucceeded, GoalBlocked: OutcomeBlocked,
		HandoffDispatched: OutcomeStarted, HandoffAccepted: OutcomeObserved,
		HandoffCompleted: OutcomeSucceeded, HandoffFailed: OutcomeFailed, HandoffBlocked: OutcomeBlocked,
	}[kind]
	if outcome != wantOutcome {
		return errors.New("event kind and outcome mismatch")
	}
	if kind == TaskCompleted && (p.Accepted == nil || !*p.Accepted || p.Error != nil || p.Blocking != nil) {
		return errors.New("invalid completed Task evidence")
	}
	if kind == TaskFailed && (p.Accepted == nil || *p.Accepted || p.Error == nil || p.Blocking != nil) {
		return errors.New("invalid failed Task evidence")
	}
	if kind == TaskBlocked && p.Blocking == nil {
		return errors.New("blocked Task requires blocking evidence")
	}
	if kind == TaskCancelled && (p.Accepted == nil || *p.Accepted || p.Error == nil || p.Error.Class != ErrorClassCancellation || p.Blocking != nil) {
		return errors.New("invalid cancelled Task evidence")
	}
	if subject.Kind == SubjectGoal {
		if p.Revision != subject.Revision {
			return errors.New("Goal payload revision must match subject revision")
		}
		if kind == GoalCompleted && (p.State != "completed" || p.Phase != "closure" || p.Error != nil || p.Blocking != nil) {
			return errors.New("completed Goal requires canonical terminal evidence")
		}
		if kind == GoalBlocked && p.Blocking == nil {
			return errors.New("blocked Goal requires blocking evidence")
		}
	}
	if subject.Kind == SubjectHandoff {
		if p.Handoff == nil {
			return errors.New("handoff event requires handoff evidence")
		}
		if kind == HandoffFailed && p.Error == nil {
			return errors.New("failed handoff requires error evidence")
		}
		if kind == HandoffBlocked && p.Blocking == nil {
			return errors.New("blocked handoff requires blocking evidence")
		}
	}
	return nil
}
func validatePayload(p Payload) error {
	if p.Error != nil {
		if !validErrorCode(p.Error.Code) || !validErrorClass(p.Error.Class) {
			return errors.New("invalid typed error evidence")
		}
	}
	if p.Blocking != nil {
		if !validBlockCode(p.Blocking.Code) {
			return errors.New("invalid blocking evidence")
		}
		for _, kind := range p.Blocking.RequiredEvidenceTypes {
			if !validEvidenceType(kind) {
				return errors.New("invalid required evidence type")
			}
		}
		if !canonicalUniqueStrings(p.Blocking.RequiredEvidenceTypes) {
			return errors.New("required evidence types are not canonical")
		}
	}
	if p.Handoff != nil {
		if !validActor(Actor{Kind: p.Handoff.From, ID: "role"}) || !validActor(Actor{Kind: p.Handoff.To, ID: "role"}) {
			return errors.New("invalid handoff roles")
		}
	}
	if len(p.EvidenceTypes) > MaxCollectionItems || len(p.DebtKinds) > MaxCollectionItems {
		return errors.New("payload collection exceeds limit")
	}
	if !canonicalUniqueStrings(p.EvidenceTypes) || !canonicalUniqueStrings(p.DebtKinds) {
		return errors.New("payload collections are not canonical")
	}
	for _, kind := range p.EvidenceTypes {
		if !validEvidenceType(kind) {
			return errors.New("invalid evidence type")
		}
	}
	for _, kind := range p.DebtKinds {
		if kind != "debt" && kind != "risk" {
			return errors.New("invalid debt kind")
		}
	}
	for _, phase := range []string{p.PreviousPhase, p.Phase} {
		if phase != "" && !validPhase(phase) {
			return errors.New("invalid Goal phase")
		}
	}
	for _, state := range []string{p.PreviousState, p.State} {
		if state != "" && state != "active" && state != "completed" {
			return errors.New("invalid Goal state")
		}
	}
	return nil
}
func canonicalUniqueStrings(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}
func canonicalPayload(p Payload) Payload {
	p.EvidenceTypes = canonicalStrings(p.EvidenceTypes)
	p.DebtKinds = canonicalStrings(p.DebtKinds)
	if p.Blocking != nil {
		copy := *p.Blocking
		copy.RequiredEvidenceTypes = canonicalStrings(copy.RequiredEvidenceTypes)
		p.Blocking = &copy
	}
	return p
}
func validEvidenceType(kind string) bool {
	switch kind {
	case "command", "file", "link", "commit", "test", "issue":
		return true
	}
	return false
}
func validPhase(phase string) bool {
	switch phase {
	case "orient", "gap_plan", "execute", "reconcile", "self_review", "completeness_omission_audit", "verify", "closure":
		return true
	}
	return false
}
