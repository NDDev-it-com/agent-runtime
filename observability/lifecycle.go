// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"errors"
	"sort"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

type Context struct {
	CorrelationID string
	CausationID   string
	Actor         Actor
	Attempt       Attempt
	Attributes    []InputAttribute
}

func (c Context) draft(kind EventKind, subject Subject, outcome Outcome, payload Payload) Draft {
	return Draft{Kind: kind, Subject: subject, CorrelationID: c.CorrelationID, CausationID: c.CausationID, Actor: c.Actor, Attempt: c.Attempt, Outcome: outcome, Payload: payload, Attributes: append([]InputAttribute(nil), c.Attributes...)}
}

func TaskValidatedDraft(id string, c Context) Draft {
	return c.draft(TaskValidated, Subject{Kind: SubjectTask, ID: id}, OutcomeObserved, Payload{})
}
func TaskStartedDraft(id string, c Context) Draft {
	return c.draft(TaskStarted, Subject{Kind: SubjectTask, ID: id}, OutcomeStarted, Payload{})
}
func TaskResultDraft(result agentruntime.Result, errorEvidence *ErrorEvidence, c Context) Draft {
	kind, outcome := TaskCompleted, OutcomeSucceeded
	if !result.Accepted {
		kind, outcome = TaskFailed, OutcomeFailed
	}
	accepted, exit, timedOut, truncated := result.Accepted, result.ExitCode, result.TimedOut, result.Truncated
	payload := Payload{Accepted: &accepted, ExitCode: &exit, TimedOut: &timedOut, Truncated: &truncated, Error: errorEvidence}
	return c.draft(kind, Subject{Kind: SubjectTask, ID: result.AgentID}, outcome, payload)
}
func TaskBlockedDraft(id string, code BlockCode, requiredEvidence []string, c Context) Draft {
	return c.draft(TaskBlocked, Subject{Kind: SubjectTask, ID: id}, OutcomeBlocked, Payload{Blocking: &BlockingEvidence{Code: code, RequiredEvidenceTypes: requiredEvidence}})
}

func GoalCreatedDraft(j goalpkg.Journal, c Context) (Draft, error) {
	if err := j.Validate(); err != nil {
		return Draft{}, err
	}
	return c.draft(GoalCreated, Subject{Kind: SubjectGoal, ID: j.Goal.ID, Revision: j.Revision}, OutcomeObserved, Payload{State: string(j.Goal.State), Phase: string(j.Goal.CurrentPhase), Revision: j.Revision}), nil
}

func GoalTransitionDrafts(before, after goalpkg.Journal, c Context) ([]Draft, error) {
	if err := before.Validate(); err != nil {
		return nil, err
	}
	if err := after.Validate(); err != nil {
		return nil, err
	}
	if before.Goal.ID != after.Goal.ID || after.Revision <= before.Revision {
		return nil, errors.New("Goal transition requires same identity and increasing revision")
	}
	subject := Subject{Kind: SubjectGoal, ID: after.Goal.ID, Revision: after.Revision}
	base := Payload{PreviousState: string(before.Goal.State), State: string(after.Goal.State), PreviousPhase: string(before.Goal.CurrentPhase), Phase: string(after.Goal.CurrentPhase), PreviousRevision: before.Revision, Revision: after.Revision}
	events := []Draft{}
	if added := len(after.Goal.Acceptance) - len(before.Goal.Acceptance); added > 0 {
		payload := base
		payload.ChecklistChanges = uint32(added)
		events = append(events, c.draft(GoalChecklistAdded, subject, OutcomeObserved, payload))
	}
	beforeItems := map[string]goalpkg.ItemStatus{}
	for _, item := range before.Goal.Acceptance {
		beforeItems[item.ID] = item.Status
	}
	completed := 0
	for _, item := range after.Goal.Acceptance {
		if item.Status == goalpkg.ItemComplete && beforeItems[item.ID] != goalpkg.ItemComplete {
			completed++
		}
	}
	if completed > 0 {
		payload := base
		payload.ChecklistChanges = uint32(completed)
		events = append(events, c.draft(GoalChecklistCompleted, subject, OutcomeObserved, payload))
	}
	evidenceCount := 0
	evidenceTypes := map[string]bool{}
	for phase, receipt := range after.Goal.Receipts {
		old := len(before.Goal.Receipts[phase].Evidence)
		if delta := len(receipt.Evidence) - old; delta > 0 {
			evidenceCount += delta
			for _, evidence := range receipt.Evidence[old:] {
				evidenceTypes[string(evidence.Type)] = true
			}
		}
	}
	if evidenceCount > 0 {
		types := make([]string, 0, len(evidenceTypes))
		for kind := range evidenceTypes {
			types = append(types, kind)
		}
		sort.Strings(types)
		payload := base
		payload.EvidenceCount = uint32(evidenceCount)
		payload.EvidenceTypes = types
		events = append(events, c.draft(GoalReceiptEvidenceAdded, subject, OutcomeObserved, payload))
	}
	if before.Goal.CurrentPhase != after.Goal.CurrentPhase {
		events = append(events, c.draft(GoalPhaseTransitioned, subject, OutcomeObserved, base))
	}
	if before.Goal.State != goalpkg.StateCompleted && after.Goal.State == goalpkg.StateCompleted {
		payload := base
		if closure, ok := after.Goal.Receipts[goalpkg.PhaseClosure]; ok && closure.Closure != nil {
			payload.DebtCount = uint32(len(closure.Closure.Remaining))
			kinds := map[string]bool{}
			for _, item := range closure.Closure.Remaining {
				kinds[string(item.Kind)] = true
			}
			for kind := range kinds {
				payload.DebtKinds = append(payload.DebtKinds, kind)
			}
			sort.Strings(payload.DebtKinds)
		}
		events = append(events, c.draft(GoalCompleted, subject, OutcomeSucceeded, payload))
	}
	if len(events) == 0 {
		return nil, errors.New("Goal revision changed without an observable lifecycle transition")
	}
	return events, nil
}

func GoalBlockedDraft(j goalpkg.Journal, code BlockCode, requiredEvidence []string, c Context) (Draft, error) {
	if err := j.Validate(); err != nil {
		return Draft{}, err
	}
	return c.draft(GoalBlocked, Subject{Kind: SubjectGoal, ID: j.Goal.ID, Revision: j.Revision}, OutcomeBlocked, Payload{State: string(j.Goal.State), Phase: string(j.Goal.CurrentPhase), Revision: j.Revision, Blocking: &BlockingEvidence{Code: code, RequiredEvidenceTypes: requiredEvidence}}), nil
}

type HandoffStage string

const (
	HandoffStageDispatched HandoffStage = "dispatched"
	HandoffStageAccepted   HandoffStage = "accepted"
	HandoffStageCompleted  HandoffStage = "completed"
	HandoffStageFailed     HandoffStage = "failed"
	HandoffStageBlocked    HandoffStage = "blocked"
)

func HandoffDraft(id string, from, to ActorKind, stage HandoffStage, errorEvidence *ErrorEvidence, blocking *BlockingEvidence, c Context) (Draft, error) {
	kinds := map[HandoffStage]struct {
		kind    EventKind
		outcome Outcome
	}{HandoffStageDispatched: {HandoffDispatched, OutcomeStarted}, HandoffStageAccepted: {HandoffAccepted, OutcomeObserved}, HandoffStageCompleted: {HandoffCompleted, OutcomeSucceeded}, HandoffStageFailed: {HandoffFailed, OutcomeFailed}, HandoffStageBlocked: {HandoffBlocked, OutcomeBlocked}}
	selected, ok := kinds[stage]
	if !ok {
		return Draft{}, errors.New("invalid handoff stage")
	}
	payload := Payload{Handoff: &HandoffEvidence{From: from, To: to}, Error: errorEvidence, Blocking: blocking}
	return c.draft(selected.kind, Subject{Kind: SubjectHandoff, ID: id}, selected.outcome, payload), nil
}
