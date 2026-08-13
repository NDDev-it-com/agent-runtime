// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestLifecycleSchemaVocabularyParity(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "schemas", "lifecycle-event-v1alpha1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["x-license"] != "AGPL-3.0-only" {
		t.Fatal("schema license drift")
	}
	properties := schema["properties"].(map[string]any)
	if properties["schema_version"].(map[string]any)["const"] != SchemaVersion {
		t.Fatal("schema version drift")
	}
	got := stringsFromSchema(properties["kind"].(map[string]any)["enum"])
	want := make([]string, 0, len(eventKinds))
	for kind := range eventKinds {
		want = append(want, string(kind))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event kinds got=%v want=%v", got, want)
	}
	defs := schema["$defs"].(map[string]any)
	gotReasons := stringsFromSchema(defs["redaction"].(map[string]any)["properties"].(map[string]any)["reason"].(map[string]any)["enum"])
	wantReasons := []string{string(ReasonSensitivity), string(ReasonUnsafeName), string(ReasonUnsupported), string(ReasonBinary), string(ReasonCycle), string(ReasonDepth), string(ReasonCollection), string(ReasonString), string(ReasonInvalidUTF8), string(ReasonAttributeLimit), string(ReasonUnsafeValue)}
	sort.Strings(gotReasons)
	sort.Strings(wantReasons)
	if !reflect.DeepEqual(gotReasons, wantReasons) {
		t.Fatalf("reasons got=%v want=%v", gotReasons, wantReasons)
	}
	gotErrors := stringsFromSchema(defs["typedError"].(map[string]any)["properties"].(map[string]any)["code"].(map[string]any)["enum"])
	wantErrors := []string{string(ErrorValidation), string(ErrorExecution), string(ErrorTimeout), string(ErrorCancelled), string(ErrorJournalConflict), string(ErrorJournalIO), string(ErrorSinkDelivery)}
	sort.Strings(gotErrors)
	sort.Strings(wantErrors)
	if !reflect.DeepEqual(gotErrors, wantErrors) {
		t.Fatalf("errors got=%v want=%v", gotErrors, wantErrors)
	}
	gotOutcomes := stringsFromSchema(properties["outcome"].(map[string]any)["enum"])
	wantOutcomes := []string{string(OutcomeObserved), string(OutcomeStarted), string(OutcomeSucceeded), string(OutcomeFailed), string(OutcomeBlocked), string(OutcomeCancelled)}
	sort.Strings(gotOutcomes)
	sort.Strings(wantOutcomes)
	if !reflect.DeepEqual(gotOutcomes, wantOutcomes) {
		t.Fatalf("outcomes got=%v want=%v", gotOutcomes, wantOutcomes)
	}
	for _, outcome := range wantOutcomes {
		if !validOutcome(Outcome(outcome)) {
			t.Fatalf("schema publishes outcome %q the validator rejects", outcome)
		}
	}
	gotAttempts := stringsFromSchema(properties["attempt"].(map[string]any)["enum"])
	wantAttempts := []string{string(AttemptInitial), string(AttemptRetry), string(AttemptRecovery), string(AttemptReplay)}
	sort.Strings(gotAttempts)
	sort.Strings(wantAttempts)
	if !reflect.DeepEqual(gotAttempts, wantAttempts) {
		t.Fatalf("attempts got=%v want=%v", gotAttempts, wantAttempts)
	}
	for _, attempt := range wantAttempts {
		if !validAttempt(Attempt(attempt)) {
			t.Fatalf("schema publishes attempt %q the validator rejects", attempt)
		}
	}
	gotSubjects := stringsFromSchema(defs["subject"].(map[string]any)["properties"].(map[string]any)["kind"].(map[string]any)["enum"])
	wantSubjects := []string{string(SubjectTask), string(SubjectGoal), string(SubjectHandoff)}
	sort.Strings(gotSubjects)
	sort.Strings(wantSubjects)
	if !reflect.DeepEqual(gotSubjects, wantSubjects) {
		t.Fatalf("subject kinds got=%v want=%v", gotSubjects, wantSubjects)
	}
	gotActors := stringsFromSchema(defs["actor"].(map[string]any)["properties"].(map[string]any)["kind"].(map[string]any)["enum"])
	wantActors := []string{string(ActorBrain), string(ActorOrchestrator), string(ActorDispatcher), string(ActorWorker), string(ActorRuntime)}
	sort.Strings(gotActors)
	sort.Strings(wantActors)
	if !reflect.DeepEqual(gotActors, wantActors) {
		t.Fatalf("actor kinds got=%v want=%v", gotActors, wantActors)
	}
	for _, actor := range wantActors {
		if !validActor(Actor{Kind: ActorKind(actor), ID: "role"}) {
			t.Fatalf("schema publishes actor kind %q the validator rejects", actor)
		}
	}
	gotHandoffRoles := stringsFromSchema(defs["handoff"].(map[string]any)["properties"].(map[string]any)["from"].(map[string]any)["enum"])
	sort.Strings(gotHandoffRoles)
	if !reflect.DeepEqual(gotHandoffRoles, wantActors) {
		t.Fatalf("handoff roles got=%v want=%v", gotHandoffRoles, wantActors)
	}
	gotBlocks := stringsFromSchema(defs["blocking"].(map[string]any)["properties"].(map[string]any)["code"].(map[string]any)["enum"])
	wantBlocks := []string{string(BlockApprovalRequired), string(BlockDependencyUnavailable), string(BlockEvidenceMissing), string(BlockAuthorityRequired), string(BlockExternalState)}
	sort.Strings(gotBlocks)
	sort.Strings(wantBlocks)
	if !reflect.DeepEqual(gotBlocks, wantBlocks) {
		t.Fatalf("blocks got=%v want=%v", gotBlocks, wantBlocks)
	}
}

func TestEnvelopeRejectsTamperingTrailingAndOversize(t *testing.T) {
	event, _ := oneEvent(t)
	data, _ := event.CanonicalJSON()
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	wire["sequence"] = float64(99)
	tampered, _ := json.Marshal(wire)
	var restored Envelope
	if err := json.Unmarshal(tampered, &restored); err == nil {
		t.Fatal("tampered content-derived ID accepted")
	}
	if err := json.Unmarshal(append(data, []byte(` {}`)...), &restored); err == nil {
		t.Fatal("trailing event accepted")
	}
	duplicate := bytes.Replace(data, []byte(`"schema_version":"v1alpha1"`), []byte(`"schema_version":"v1alpha1","schema_version":"v1alpha1"`), 1)
	if err := json.Unmarshal(duplicate, &restored); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	draft := testDraft()
	huge := map[string]any{}
	for i := 0; i < MaxCollectionItems; i++ {
		huge[fmt.Sprintf("value%02d", i)] = strings.Repeat("x", MaxStringBytes)
	}
	draft.Attributes = []InputAttribute{{Name: "safe.huge", Sensitivity: SensitivityPublic, Value: huge}}
	memory, _ := NewMemorySink("memory", 2)
	if _, _, err := testEmitter(t, memory).Emit(context.Background(), draft); err == nil {
		t.Fatal("oversize envelope accepted")
	}
}

func TestEnvelopeRejectsMissingNullAndWrongRequiredContainers(t *testing.T) {
	draft := testDraft()
	expectedAttributes, expectedRedactions, err := DefaultPolicy().Redact(draft.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	event, _ := emitDraft(t, draft)
	draft.Attributes[0].Name = "mutated.name"
	draft.Attributes[0].Value = 99
	data, err := event.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(data, &canonical); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		field  string
		value  any
		delete bool
	}{
		{name: "missing payload", field: "payload", delete: true},
		{name: "null payload", field: "payload", value: nil},
		{name: "wrong payload type", field: "payload", value: []any{}},
		{name: "null attributes", field: "attributes", value: nil},
		{name: "wrong attributes type", field: "attributes", value: map[string]any{}},
		{name: "null redactions", field: "redactions", value: nil},
		{name: "wrong redactions type", field: "redactions", value: map[string]any{}},
		{name: "null subject", field: "subject", value: nil},
		{name: "null actor", field: "actor", value: nil},
		{name: "null runtime", field: "runtime", value: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := make(map[string]any, len(canonical))
			for key, value := range canonical {
				candidate[key] = value
			}
			if test.delete {
				delete(candidate, test.field)
			} else {
				candidate[test.field] = test.value
			}
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var restored Envelope
			if err := json.Unmarshal(encoded, &restored); err == nil {
				t.Fatal("invalid required container accepted")
			}
		})
	}
	if !reflect.DeepEqual(event.wire.Attributes, expectedAttributes) || len(event.wire.Attributes) == 0 {
		t.Fatalf("canonical safe attributes changed: got=%#v want=%#v", event.wire.Attributes, expectedAttributes)
	}
	if !reflect.DeepEqual(event.wire.Redactions, expectedRedactions) || len(expectedRedactions) != 0 {
		t.Fatalf("canonical redactions changed: got=%#v want=%#v", event.wire.Redactions, expectedRedactions)
	}
	expectedAttributeJSON, err := json.Marshal(expectedAttributes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, append([]byte(`"attributes":`), expectedAttributeJSON...)) || !bytes.Contains(data, []byte(`"redactions":[]`)) || !bytes.Contains(data, []byte(`"payload":{}`)) || bytes.Contains(data, []byte("mutated")) || bytes.Contains(data, []byte(`"value":99`)) {
		t.Fatalf("canonical required containers or safe attributes changed: %s", data)
	}
}

func FuzzEnvelopeUnmarshal(f *testing.F) {
	memory, _ := NewMemorySink("memory", 2)
	emitter, _ := NewEmitter(Runtime{ID: "runtime-1", Version: "0.1.0"}, []Sink{memory}, Options{})
	event, _, err := emitter.Emit(context.Background(), testDraft())
	if err != nil {
		f.Fatal(err)
	}
	data, _ := event.CanonicalJSON()
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) { var event Envelope; _ = json.Unmarshal(data, &event) })
}

func stringsFromSchema(value any) []string {
	raw := value.([]any)
	out := make([]string, len(raw))
	for i, item := range raw {
		out[i] = item.(string)
	}
	return out
}
