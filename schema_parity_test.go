// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

func TestSchemaAndLicenseParity(t *testing.T) {
	t.Parallel()
	task := readSchema(t, "schemas/task-manifest-v1alpha1.schema.json")
	goal := readSchema(t, "schemas/goal-journal-v1alpha1.schema.json")
	for name, schema := range map[string]map[string]any{"task": task, "goal": goal} {
		if schema["x-license"] != "AGPL-3.0-only" {
			t.Errorf("%s schema license=%v", name, schema["x-license"])
		}
	}
	if task["properties"].(map[string]any)["schema_version"].(map[string]any)["const"] != TaskSchemaVersion {
		t.Fatal("Task schema version drift")
	}
	defs := goal["$defs"].(map[string]any)
	gotPhases := stringsFromAny(defs["phase"].(map[string]any)["enum"])
	wantPhases := make([]string, len(goalpkg.Phases))
	for i, p := range goalpkg.Phases {
		wantPhases[i] = string(p)
	}
	if !reflect.DeepEqual(gotPhases, wantPhases) {
		t.Fatalf("Goal phase schema drift: got %v want %v", gotPhases, wantPhases)
	}
	gotEvidence := stringsFromAny(defs["evidence"].(map[string]any)["properties"].(map[string]any)["type"].(map[string]any)["enum"])
	wantEvidence := []string{"command", "file", "link", "commit", "test", "issue"}
	sort.Strings(gotEvidence)
	sort.Strings(wantEvidence)
	if !reflect.DeepEqual(gotEvidence, wantEvidence) {
		t.Fatalf("evidence schema drift: got %v want %v", gotEvidence, wantEvidence)
	}
	evidenceProperties := defs["evidence"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"reference", "result"} {
		if evidenceProperties[field].(map[string]any)["maxLength"] != float64(goalpkg.MaxEvidenceFieldBytes) {
			t.Fatalf("evidence %s bound drift", field)
		}
	}
	nextWork := defs["closure"].(map[string]any)["properties"].(map[string]any)["next_work"].(map[string]any)
	if nextWork["minItems"] != float64(1) || nextWork["maxItems"] != float64(goalpkg.MaxEvidenceRecords) || nextWork["uniqueItems"] != true {
		t.Fatalf("NextWork schema bounds drift: %#v", nextWork)
	}
}

func TestGoSourcesCarrySPDXHeader(t *testing.T) {
	t.Parallel()
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(data), "// SPDX-License-Identifier: AGPL-3.0-only\n") {
			t.Errorf("missing SPDX header: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func stringsFromAny(value any) []string {
	raw := value.([]any)
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = v.(string)
	}
	return out
}
