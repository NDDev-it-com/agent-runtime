// SPDX-License-Identifier: AGPL-3.0-only

package observability_test

import (
	"context"
	"fmt"
	"time"

	"github.com/NDDev-it-com/agent-runtime/observability"
)

func ExampleEmitter() {
	sink, _ := observability.NewMemorySink("test", 10)
	emitter, _ := observability.NewEmitter(observability.Runtime{ID: "runtime-1", Version: "0.1.0"}, []observability.Sink{sink}, observability.Options{Clock: func() time.Time { return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC) }})
	draft := observability.TaskStartedDraft("task-1", observability.Context{CorrelationID: "request-1", Actor: observability.Actor{Kind: observability.ActorWorker, ID: "worker-1"}, Attempt: observability.AttemptInitial, Attributes: []observability.InputAttribute{{Name: "tenant.class", Sensitivity: observability.SensitivityInternal, Value: "standard"}, {Name: "auth.token", Sensitivity: observability.SensitivitySecret, Value: "never persisted"}}})
	event, report, _ := emitter.Emit(context.Background(), draft)
	fmt.Println(event.Kind(), event.Sequence(), report.Succeeded())
	data, _ := event.CanonicalJSON()
	fmt.Println(string(data) != "")
	// Output:
	// task.started 1 true
	// true
}
