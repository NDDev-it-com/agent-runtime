// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDecodeTaskManifestDefaults(t *testing.T) {
	t.Parallel()
	m, err := DecodeTaskManifest(strings.NewReader(`{"schema_version":"v1alpha1","id":"reviewer","instructions":["AGENTS.md"],"command":["review"],"acceptance":{"exit_codes":[0]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Workdir != "." || m.Timeout.Duration != DefaultTimeout || m.MaxOutput != DefaultMaxOutputBytes || m.MaxContext != DefaultMaxContextBytes {
		t.Fatalf("defaults not applied: %#v", m)
	}
}

func TestPrepareAppliesDefaultsWithoutMutatingCaller(t *testing.T) {
	t.Parallel()
	original := TaskManifest{SchemaVersion: TaskSchemaVersion, ID: "agent", Instructions: []string{"AGENTS.md"}, Command: []string{"agent"}, Acceptance: TaskAcceptance{ExitCodes: []int{0}}}
	prepared, err := original.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if original.Workdir != "" || prepared.Workdir != "." || prepared.Timeout.Duration != DefaultTimeout {
		t.Fatalf("original=%#v prepared=%#v", original, prepared)
	}
}

func TestDecodeTaskManifestRejectsUnknownAndTrailingData(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"schema_version":"v1alpha1","id":"a","instructions":["a"],"command":["a"],"acceptance":{"exit_codes":[0]},"surprise":true}`,
		`{"schema_version":"v1alpha1","id":"a","instructions":["a"],"command":["a"],"acceptance":{"exit_codes":[0]}} {}`,
	} {
		if _, err := DecodeTaskManifest(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestTaskManifestRequiredAndOptionalSlicePresence(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"schema_version":"v1alpha1","id":"a","command":["a"],"acceptance":{"exit_codes":[0]}}`,
		`{"schema_version":"v1alpha1","id":"a","instructions":null,"command":["a"],"acceptance":{"exit_codes":[0]}}`,
		`{"schema_version":"v1alpha1","id":"a","instructions":[],"command":["a"],"acceptance":{"exit_codes":[0]}}`,
		`{"schema_version":"v1alpha1","id":"a","instructions":["a"],"command":null,"acceptance":{"exit_codes":[0]}}`,
		`{"schema_version":"v1alpha1","id":"a","instructions":["a"],"command":["a"],"acceptance":{"exit_codes":null}}`,
	} {
		if _, err := DecodeTaskManifest(strings.NewReader(input)); err == nil {
			t.Fatalf("required slice absence accepted: %s", input)
		}
	}
	for _, optional := range []string{
		`"env":null,"acceptance":{"exit_codes":[0],"output_contains":null}`,
		`"env":[],"acceptance":{"exit_codes":[0],"output_contains":[]}`,
	} {
		input := `{"schema_version":"v1alpha1","id":"a","instructions":["a"],"command":["a"],` + optional + `}`
		if _, err := DecodeTaskManifest(strings.NewReader(input)); err != nil {
			t.Fatalf("optional empty slice rejected: %s: %v", input, err)
		}
	}
}

func TestDecodeTaskManifestRejectsOversizeInput(t *testing.T) {
	t.Parallel()
	if _, err := DecodeTaskManifest(bytes.NewReader(make([]byte, (1<<20)+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTaskManifestValidation(t *testing.T) {
	t.Parallel()
	m := TaskManifest{SchemaVersion: TaskSchemaVersion, ID: "Bad ID", Instructions: []string{"a", "a"}, Command: []string{""}, Acceptance: TaskAcceptance{ExitCodes: []int{999, 999}}, Env: []string{"A=B"}, Timeout: Duration{25 * time.Hour}, MaxOutput: 1, MaxContext: 1}
	err := m.Validate()
	for _, want := range []string{"id must match", "duplicate instruction", "command", "environment", "at most 24h"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func FuzzDecodeTaskManifest(f *testing.F) {
	f.Add([]byte(`{"schema_version":"v1alpha1","id":"agent","instructions":["AGENTS.md"],"command":["agent"],"acceptance":{"exit_codes":[0]}}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeTaskManifest(strings.NewReader(string(data))) })
}

// TestStatedBoundsAreNotWidened covers the fail-open path where a document that
// asked for no execution time, no output or no context was granted the default
// instead. Absence and an explicit zero decode identically in Go, so the
// distinction has to be drawn from the document. A negative value was already
// refused, which made zero the only way through.
func TestStatedBoundsAreNotWidened(t *testing.T) {
	t.Parallel()
	const base = `{"schema_version":"v1alpha1","id":"probe","instructions":["AGENTS.md"],` +
		`"command":["/bin/true"],"acceptance":{"exit_codes":[0]}`

	stated, err := DecodeTaskManifest(strings.NewReader(base + `}`))
	if err != nil {
		t.Fatalf("a manifest that states no bounds must still decode: %v", err)
	}
	if stated.Timeout.Duration != DefaultTimeout || stated.MaxOutput != DefaultMaxOutputBytes || stated.MaxContext != DefaultMaxContextBytes {
		t.Fatalf("silence must produce defaults, got timeout=%v out=%d ctx=%d", stated.Timeout.Duration, stated.MaxOutput, stated.MaxContext)
	}

	for name, document := range map[string]string{
		"zero timeout":     base + `,"timeout":"0s"}`,
		"zero output":      base + `,"max_output_bytes":0}`,
		"zero context":     base + `,"max_context_bytes":0}`,
		"negative output":  base + `,"max_output_bytes":-1}`,
		"negative context": base + `,"max_context_bytes":-1}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got, err := DecodeTaskManifest(strings.NewReader(document)); err == nil {
				t.Fatalf("a stated zero bound was widened to timeout=%v out=%d ctx=%d",
					got.Timeout.Duration, got.MaxOutput, got.MaxContext)
			}
		})
	}

	// A stated bound within its range must survive untouched.
	explicit, err := DecodeTaskManifest(strings.NewReader(base + `,"timeout":"7s","max_output_bytes":128,"max_context_bytes":256}`))
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Timeout.Duration != 7*time.Second || explicit.MaxOutput != 128 || explicit.MaxContext != 256 {
		t.Fatalf("stated bounds were rewritten: timeout=%v out=%d ctx=%d", explicit.Timeout.Duration, explicit.MaxOutput, explicit.MaxContext)
	}

	// Prepare reads a Go value, where a zero field is silence rather than a
	// stated bound, so it must still default.
	prepared, err := TaskManifest{
		SchemaVersion: TaskSchemaVersion, ID: "probe",
		Instructions: []string{"AGENTS.md"}, Command: []string{"/bin/true"},
		Acceptance: TaskAcceptance{ExitCodes: []int{0}},
	}.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if prepared.MaxOutput != DefaultMaxOutputBytes {
		t.Fatalf("a Go literal's zero field must still default, got %d", prepared.MaxOutput)
	}
}
