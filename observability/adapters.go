// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"errors"
	"time"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

// terminalDeliveryTimeout bounds delivery of a terminal Task observation on a
// context detached from the caller's, so cancelling the work cannot also cancel
// the record of it.
const terminalDeliveryTimeout = 5 * time.Second

type TaskRunner struct {
	Runner  agentruntime.Runner
	Emitter *Emitter
	Context Context
}
type TaskRun struct {
	Result         agentruntime.Result
	ExecutionError error
	Events         []Envelope
	Delivery       []DeliveryReport
}

func (r TaskRunner) Run(ctx context.Context, manifest agentruntime.TaskManifest) TaskRun {
	run := TaskRun{}
	if r.Emitter == nil {
		run.Result, run.ExecutionError = r.Runner.Run(ctx, manifest)
		return run
	}
	prepared, validationErr := manifest.Prepare()
	if validationErr != nil {
		run.ExecutionError = validationErr
		observed := agentruntime.Result{AgentID: manifest.ID, ExitCode: -1}
		r.emit(ctx, TaskResultDraft(observed, &ErrorEvidence{Code: ErrorValidation, Class: ErrorClassValidation}, r.Context), &run)
		return run
	}
	manifest = prepared
	r.emit(ctx, TaskValidatedDraft(manifest.ID, r.Context), &run)
	r.emit(ctx, TaskStartedDraft(manifest.ID, r.Context), &run)
	result, executionErr := r.Runner.Run(ctx, manifest)
	run.Result, run.ExecutionError = result, executionErr
	var evidence *ErrorEvidence
	if executionErr != nil {
		code, class := ErrorExecution, ErrorClassExecution
		switch {
		case result.TimedOut:
			code, class = ErrorTimeout, ErrorClassTimeout
		case result.Cancelled:
			code, class = ErrorCancelled, ErrorClassCancellation
		}
		evidence = &ErrorEvidence{Code: code, Class: class}
	}
	terminal, stopTerminal := context.WithTimeout(context.WithoutCancel(ctx), terminalDeliveryTimeout)
	defer stopTerminal()
	r.emit(terminal, TaskResultDraft(result, evidence, r.Context), &run)
	return run
}
func (r TaskRunner) emit(ctx context.Context, draft Draft, run *TaskRun) {
	event, report, err := r.Emitter.Emit(ctx, draft)
	if err != nil {
		run.Delivery = append(run.Delivery, invalidDraftReport())
		return
	}
	run.Events = append(run.Events, event)
	run.Delivery = append(run.Delivery, report)
}

type GoalStore struct {
	Store   goalpkg.Store
	Emitter *Emitter
	Context Context
}
type GoalMutation struct {
	Journal  goalpkg.Journal
	Events   []Envelope
	Delivery []DeliveryReport
}

func (s GoalStore) Create(ctx context.Context, j goalpkg.Journal) (GoalMutation, error) {
	if err := s.Store.Create(j); err != nil {
		return GoalMutation{}, err
	}
	mutation := GoalMutation{Journal: j}
	if s.Emitter != nil {
		draft, err := GoalCreatedDraft(j, s.Context)
		if err != nil {
			mutation.Delivery = append(mutation.Delivery, DeliveryReport{Sinks: []SinkDelivery{{Name: "emitter", ErrorCode: SinkCorruptData}}})
			return mutation, nil
		}
		s.emit(ctx, draft, &mutation)
	}
	return mutation, nil
}
func (s GoalStore) Update(ctx context.Context, expectedRevision uint64, mutate func(*goalpkg.Journal) error) (GoalMutation, error) {
	before, err := s.Store.Load()
	if err != nil {
		return GoalMutation{}, err
	}
	if before.Revision != expectedRevision {
		return GoalMutation{}, &goalpkg.Error{Code: goalpkg.CodeConflict, Message: "revision conflict before observed update"}
	}
	after, err := s.Store.Update(expectedRevision, mutate)
	if err != nil {
		return GoalMutation{}, err
	}
	result := GoalMutation{Journal: after}
	if s.Emitter == nil {
		return result, nil
	}
	drafts, err := GoalTransitionDrafts(before, after, s.Context)
	if err != nil {
		result.Delivery = append(result.Delivery, DeliveryReport{Sinks: []SinkDelivery{{Name: "emitter", ErrorCode: SinkCorruptData}}})
		return result, nil
	}
	for _, draft := range drafts {
		s.emit(ctx, draft, &result)
	}
	return result, nil
}
func (s GoalStore) emit(ctx context.Context, draft Draft, result *GoalMutation) {
	event, report, err := s.Emitter.Emit(ctx, draft)
	if err != nil {
		result.Delivery = append(result.Delivery, invalidDraftReport())
		return
	}
	result.Events = append(result.Events, event)
	result.Delivery = append(result.Delivery, report)
}

func invalidDraftReport() DeliveryReport {
	return DeliveryReport{Sinks: []SinkDelivery{{Name: "emitter", ErrorCode: SinkCorruptData}}}
}

type HandoffEmitter struct {
	Emitter *Emitter
	Context Context
}

func (h HandoffEmitter) Emit(ctx context.Context, id string, from, to ActorKind, stage HandoffStage, errorEvidence *ErrorEvidence, blocking *BlockingEvidence) (Envelope, DeliveryReport, error) {
	if h.Emitter == nil {
		return Envelope{}, DeliveryReport{}, errors.New("emitter is required")
	}
	draft, err := HandoffDraft(id, from, to, stage, errorEvidence, blocking, h.Context)
	if err != nil {
		return Envelope{}, DeliveryReport{}, err
	}
	return h.Emitter.Emit(ctx, draft)
}
