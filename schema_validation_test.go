// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The published schemas are a contract with anyone who reads this repository's
// output without running its Go. Until this file existed, parity was asserted
// by reflecting over a handful of chosen constants — so the build-result
// schema sat at v0.1.0 across three releases while the producer emitted
// v0.1.3, and every test stayed green because nothing had chosen to compare
// that particular constant.
//
// Sampling cannot close that gap; only running the real documents through a
// real validator can. Each case below takes a document this repository actually
// produces or ships, validates it against the schema that claims to describe
// it, and then mutates it so that both sides must reject the same thing.

func compile(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(path, doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	schema, err := c.Compile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return schema
}

func asDocument(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func documentFromFile(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// TestTrackedDocumentsSatisfyTheirPublishedSchema is the direct check that was
// missing. Every one of these files is either shipped in the release archive or
// read by an executable checker, so a schema that rejects one is a schema that
// lies about this repository's own output.
func TestTrackedDocumentsSatisfyTheirPublishedSchema(t *testing.T) {
	t.Parallel()
	for name, pair := range map[string]struct{ document, schema string }{
		"release contract": {"release/v1alpha1.json", "schemas/release-contract-v1alpha1.schema.json"},
		"governance":       {"governance/main-v1alpha1.json", "schemas/repository-governance-v1alpha1.schema.json"},
		"provenance":       {"provenance/v1alpha1.json", "schemas/provenance-contract-v1alpha1.schema.json"},
		"fuzz contract":    {"fuzz/v1alpha1.json", "schemas/fuzz-contract-v1alpha1.schema.json"},
		"example manifest": {"examples/basic/agent.json", "schemas/task-manifest-v1alpha1.schema.json"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := os.Stat(pair.document); err != nil {
				t.Skipf("document not present: %v", err)
			}
			schema := compile(t, pair.schema)
			if err := schema.Validate(documentFromFile(t, pair.document)); err != nil {
				t.Fatalf("%s does not satisfy %s:\n%v", pair.document, pair.schema, err)
			}
		})
	}
}

// TestSchemaAndGoRejectTheSameDocuments is the other direction. A schema that
// accepts what the Go validator refuses is as broken as one that refuses what
// Go produces; both split the producer from the consumer.
func TestSchemaAndGoRejectTheSameDocuments(t *testing.T) {
	t.Parallel()
	schema := compile(t, "schemas/task-manifest-v1alpha1.schema.json")
	base := map[string]any{
		"schema_version": "v1alpha1",
		"id":             "probe",
		"instructions":   []any{"AGENTS.md"},
		"command":        []any{"/bin/true"},
		"acceptance":     map[string]any{"exit_codes": []any{float64(0)}},
	}
	if err := schema.Validate(asDocument(t, base)); err != nil {
		t.Fatalf("canonical manifest rejected by its own schema:\n%v", err)
	}
	if _, err := DecodeTaskManifest(strings.NewReader(mustJSON(t, base))); err != nil {
		t.Fatalf("canonical manifest rejected by the Go validator: %v", err)
	}

	for name, edit := range map[string]func(map[string]any){
		"unsupported schema version": func(m map[string]any) { m["schema_version"] = "v1alpha0" },
		"empty command":              func(m map[string]any) { m["command"] = []any{} },
		"no instructions":            func(m map[string]any) { m["instructions"] = []any{} },
		"no accepted exit code":      func(m map[string]any) { m["acceptance"] = map[string]any{"exit_codes": []any{}} },
		"zero output budget":         func(m map[string]any) { m["max_output_bytes"] = float64(0) },
		"zero context budget":        func(m map[string]any) { m["max_context_bytes"] = float64(0) },
		"negative output budget":     func(m map[string]any) { m["max_output_bytes"] = float64(-1) },
		"output budget over bound":   func(m map[string]any) { m["max_output_bytes"] = float64(1 << 30) },
		"unknown field":              func(m map[string]any) { m["extra"] = "value" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := map[string]any{}
			for key, value := range base {
				candidate[key] = value
			}
			edit(candidate)
			schemaErr := schema.Validate(asDocument(t, candidate))
			_, goErr := DecodeTaskManifest(strings.NewReader(mustJSON(t, candidate)))
			switch {
			case schemaErr == nil && goErr == nil:
				t.Fatal("both the schema and the Go validator accepted an invalid manifest")
			case schemaErr == nil:
				t.Fatalf("the schema accepted what Go rejected (%v); a consumer would produce documents the runtime cannot load", goErr)
			case goErr == nil:
				t.Fatalf("Go accepted what the schema rejected (%v); a consumer would reject valid runtime output", schemaErr)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
