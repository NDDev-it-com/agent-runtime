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
