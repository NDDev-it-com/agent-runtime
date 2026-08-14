// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type panicStringer struct{ secret string }

func (p panicStringer) String() string { panic("String must never be called: " + p.secret) }

func TestRedactionPreventsNestedLeakageAndFormatterBypass(t *testing.T) {
	t.Parallel()
	cycle := map[string]any{}
	cycle["child"] = cycle
	inputs := []InputAttribute{
		{Name: "safe.public", Sensitivity: SensitivityPublic, Value: "visible"},
		{Name: "authToken", Sensitivity: SensitivityPublic, Value: "secret-token"},
		{Name: "safe.nested", Sensitivity: SensitivityInternal, Value: map[string]any{"ok": "yes", "password": "nested-password", "values": []any{"x", errors.New("error-secret"), panicStringer{secret: "formatter-secret"}}, "cycle": cycle}},
		{Name: "safe.binary", Sensitivity: SensitivityInternal, Value: []byte("binary-secret")},
		{Name: "safe.binary_array", Sensitivity: SensitivityInternal, Value: [12]byte{'a', 'r', 'r', 'a', 'y', '-', 's', 'e', 'c', 'r', 'e', 't'}},
		{Name: "safe.confidential", Sensitivity: SensitivityConfidential, Value: "confidential-secret"},
		{Name: "safe.link", Sensitivity: SensitivityPublic, Value: "https://user:secret@example.test/?token=secret"},
		{Name: "command", Sensitivity: SensitivityPublic, Value: []string{"tool", "--token", "command-secret"}},
		{Name: "environment", Sensitivity: SensitivityInternal, Value: map[string]any{"API_TOKEN": "env-secret"}},
		{Name: "provider.payload", Sensitivity: SensitivityPublic, Value: "provider-secret"},
	}
	attributes, decisions, err := DefaultPolicy().Redact(inputs)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(struct {
		Attributes []Attribute         `json:"attributes"`
		Decisions  []RedactionDecision `json:"decisions"`
	}{attributes, decisions})
	for _, secret := range []string{"secret-token", "nested-password", "error-secret", "formatter-secret", "binary-secret", "array-secret", "confidential-secret", "example.test", "command-secret", "env-secret", "provider-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("leaked %q in %s", secret, encoded)
		}
	}
	if !strings.Contains(string(encoded), "visible") || !strings.Contains(string(encoded), "yes") {
		t.Fatalf("safe values missing: %s", encoded)
	}
	for _, reason := range []string{"unsafe_name", "unsupported_type", "binary", "sensitivity", "cycle", "unsafe_value"} {
		if !strings.Contains(string(encoded), reason) {
			t.Fatalf("missing decision %s: %s", reason, encoded)
		}
	}
}

func TestRedactionBoundsUnicodeCollectionsAndAttributes(t *testing.T) {
	t.Parallel()
	invalid := string([]byte{'a', 0xff, 'b'})
	long := strings.Repeat("界", MaxStringBytes)
	many := make([]any, MaxCollectionItems+10)
	for i := range many {
		many[i] = i
	}
	inputs := make([]InputAttribute, 0, MaxAttributes+2)
	inputs = append(inputs, InputAttribute{Name: "a.invalid", Sensitivity: SensitivityPublic, Value: invalid}, InputAttribute{Name: "b.long", Sensitivity: SensitivityPublic, Value: long}, InputAttribute{Name: "c.many", Sensitivity: SensitivityPublic, Value: many})
	for i := 0; i < MaxAttributes; i++ {
		inputs = append(inputs, InputAttribute{Name: fmt.Sprintf("z.value-%02d", i), Sensitivity: SensitivityPublic, Value: i})
	}
	attributes, decisions, err := DefaultPolicy().Redact(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != MaxAttributes {
		t.Fatalf("attributes=%d", len(attributes))
	}
	encoded, _ := json.Marshal(decisions)
	for _, reason := range []string{"attribute_limit", "collection_limit", "invalid_utf8", "string_limit"} {
		if !strings.Contains(string(encoded), reason) {
			t.Fatalf("missing %s: %s", reason, encoded)
		}
	}
}

func TestRedactionRejectsDuplicateAndUnknownSensitivity(t *testing.T) {
	t.Parallel()
	if _, _, err := DefaultPolicy().Redact([]InputAttribute{{Name: "same", Sensitivity: SensitivityPublic, Value: 1}, {Name: "same", Sensitivity: SensitivityPublic, Value: 2}}); err == nil {
		t.Fatal("duplicate accepted")
	}
	attributes, decisions, err := DefaultPolicy().Redact([]InputAttribute{{Name: "unknown", Sensitivity: "", Value: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 0 || len(decisions) != 1 || decisions[0].Reason != ReasonSensitivity {
		t.Fatalf("attributes=%#v decisions=%#v", attributes, decisions)
	}
}

func FuzzRedactionNeverLeaksDeniedValue(f *testing.F) {
	f.Add([]byte("token-value"), "safe.value")
	f.Fuzz(func(t *testing.T, secret []byte, name string) {
		if len(secret) == 0 {
			return
		}
		if !validAttributeName(name) || unsafeName(name) {
			name = "safe.value"
		}
		marker := "DENIED-" + string(secret)
		attrs, decisions, err := DefaultPolicy().Redact([]InputAttribute{{Name: name, Sensitivity: SensitivitySecret, Value: marker}})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal([]any{attrs, decisions})
		if strings.Contains(string(encoded), marker) {
			t.Fatal("denied value leaked")
		}
	})
}

// TestRedactionIsVocabularyDrivenNotContentDriven pins the boundary
// docs/observability-v1alpha1.md documents: the policy decides from the
// attribute's name and the word list, not from the shape of its value. The
// emitter is not a secret scanner, and a caller that names an attribute
// dishonestly gets its value published. Stating that in prose alone would let
// the behaviour drift away from the promise in either direction.
func TestRedactionIsVocabularyDrivenNotContentDriven(t *testing.T) {
	t.Parallel()
	const secret = "-----BEGIN OPENSSH PRIVATE KEY-----"

	for name, redactedByName := range map[string]bool{
		"private_key": true,
		"secret":      true,
		"token":       true,
		"password":    true,
		"credential":  true,
		"payload":     false,
		"note":        false,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			memory, _ := NewMemorySink("memory", 4)
			emitter := testEmitter(t, memory)
			draft := testDraft()
			draft.Attributes = []InputAttribute{{Name: name, Sensitivity: SensitivityInternal, Value: secret}}
			event, _, err := emitter.Emit(context.Background(), draft)
			if err != nil {
				t.Fatalf("emit: %v", err)
			}
			encoded, err := event.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			published := bytes.Contains(encoded, []byte(secret))
			if redactedByName && published {
				t.Fatalf("attribute %q published the value verbatim", name)
			}
			if !redactedByName && !published {
				t.Fatalf("attribute %q was redacted; the policy is documented as vocabulary-driven", name)
			}
		})
	}
}
