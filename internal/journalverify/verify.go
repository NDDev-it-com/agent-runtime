// SPDX-License-Identifier: AGPL-3.0-only

// Package journalverify proves the Goal journals this repository tracks are
// artifacts the product accepts.
//
// Every other contract here is proven by an executable checker under cmd/ — CI,
// governance, release, provenance, fuzz, cold compile. The Goal contract, which
// is the product rather than a property of the repository, had none, and that
// is exactly how it came to ship a journal it rejects: tightening the schema so
// receipt keys must be phases made an existing tracked file invalid, and
// nothing compared the two. The file travels inside the published source
// archive and is listed in its SPDX inventory, so the release carried an
// artifact its own CLI refuses to load.
//
// The check is deliberately double. The Go contract and the published schema
// are two statements of one vocabulary, and a journal has to satisfy both: Go
// alone would let the schema drift, and the schema alone would let the durable
// invariants the type enforces go unchecked.
package journalverify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/NDDev-it-com/agent-runtime/goal"
)

// DefaultDirectory is where this repository keeps its tracked journals.
const DefaultDirectory = ".agent-runtime/goals"

// SchemaPath is the published description of the same vocabulary.
const SchemaPath = "schemas/goal-journal-v1alpha1.schema.json"

// Result reports what was proven, so a caller can print evidence rather than a
// bare success.
type Result struct {
	Directory string
	Journals  []string
}

// Verify loads every journal in directory and holds it to both the Go contract
// and the published schema. An empty directory is a failure: a checker that
// passes because it found nothing to check is the kind of control this
// repository exists to remove.
func Verify(root, directory, schemaPath string) (Result, error) {
	pattern := filepath.Join(root, directory, "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return Result{}, fmt.Errorf("scan %s: %w", directory, err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return Result{}, fmt.Errorf("no goal journals under %s; this check would pass vacuously", directory)
	}
	schema, err := compileSchema(filepath.Join(root, schemaPath))
	if err != nil {
		return Result{}, err
	}
	result := Result{Directory: directory}
	for _, path := range paths {
		name := filepath.Base(path)
		if err := verifyOne(path, schema); err != nil {
			return Result{}, fmt.Errorf("%s: %w", filepath.Join(directory, name), err)
		}
		result.Journals = append(result.Journals, name)
	}
	return result, nil
}

func verifyOne(path string, schema *jsonschema.Schema) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// The Go contract first: it is what a caller's CLI and library will apply,
	// so a journal that fails here is unusable whatever the schema says.
	journal, err := goal.Store{Path: path}.Load()
	if err != nil {
		return fmt.Errorf("the Goal contract rejects this journal: %w", err)
	}
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	if err := schema.Validate(document); err != nil {
		return fmt.Errorf("the published schema rejects this journal: %w", err)
	}
	// Re-encoding must reproduce the file. A journal that only round-trips
	// approximately would drift each time the runtime rewrote it, and it ships
	// inside the release archive byte for byte.
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("re-encode: %w", err)
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(string(encoded)) {
		return errors.New("the journal is not the canonical encoding of what it decodes to")
	}
	return nil
}

func compileSchema(path string) (*jsonschema.Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read goal schema: %w", err)
	}
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse goal schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(path, document); err != nil {
		return nil, fmt.Errorf("load goal schema: %w", err)
	}
	schema, err := compiler.Compile(path)
	if err != nil {
		return nil, fmt.Errorf("compile goal schema: %w", err)
	}
	return schema, nil
}
