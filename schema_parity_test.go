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
	releasepkg "github.com/NDDev-it-com/agent-runtime/internal/releasecontract"
)

func TestSchemaAndLicenseParity(t *testing.T) {
	t.Parallel()
	task := readSchema(t, "schemas/task-manifest-v1alpha1.schema.json")
	goal := readSchema(t, "schemas/goal-journal-v1alpha1.schema.json")
	governance := readSchema(t, "schemas/repository-governance-v1alpha1.schema.json")
	releaseContract := readSchema(t, "schemas/release-contract-v1alpha1.schema.json")
	releaseManifest := readSchema(t, "schemas/release-manifest-v1alpha1.schema.json")
	provenance := readSchema(t, "schemas/provenance-contract-v1alpha1.schema.json")
	for name, schema := range map[string]map[string]any{"task": task, "goal": goal, "governance": governance, "release contract": releaseContract, "release manifest": releaseManifest, "provenance": provenance} {
		if schema["x-license"] != "AGPL-3.0-only" {
			t.Errorf("%s schema license=%v", name, schema["x-license"])
		}
	}
	if governance["properties"].(map[string]any)["schema_version"].(map[string]any)["const"] != "v1alpha1" {
		t.Fatal("repository governance schema version drift")
	}
	if releaseContract["properties"].(map[string]any)["version"].(map[string]any)["const"] != "v0.1.0" || releaseManifest["properties"].(map[string]any)["schema_version"].(map[string]any)["const"] != "v1alpha1" {
		t.Fatal("release schema identity drift")
	}
	if provenance["properties"].(map[string]any)["integration_openpgp_status"].(map[string]any)["const"] != "active" || provenance["properties"].(map[string]any)["trust_update_policy"].(map[string]any)["const"] != "reviewed-contract-change" {
		t.Fatal("provenance trust policy schema drift")
	}
	release, err := releasepkg.Load("release/v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	wantDependencyPaths := make([]string, len(release.Dependencies))
	for index := range release.Dependencies {
		wantDependencyPaths[index] = release.Dependencies[index].ModulePath
	}
	sort.Strings(wantDependencyPaths)
	dependencyItems := releaseContract["properties"].(map[string]any)["dependencies"].(map[string]any)["items"].(map[string]any)
	gotDependencyPaths := stringsFromAny(dependencyItems["properties"].(map[string]any)["module_path"].(map[string]any)["enum"])
	sort.Strings(gotDependencyPaths)
	if !reflect.DeepEqual(gotDependencyPaths, wantDependencyPaths) {
		t.Fatalf("release dependency schema closure drift: got %v want %v", gotDependencyPaths, wantDependencyPaths)
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
	var sources []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		sources = append(sources, filepath.ToSlash(path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(sources)
	wantFixtures := []string{
		"internal/releasecontract/testdata/ownership_migration_negative/darwin.go",
		"internal/releasecontract/testdata/ownership_migration_negative/linux.go",
	}
	for _, fixture := range wantFixtures {
		index := sort.SearchStrings(sources, fixture)
		if index == len(sources) || sources[index] != fixture {
			t.Errorf("fixture escaped repository Go source contract: %s", fixture)
		}
	}
	for _, path := range sources {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read Go source %s: %v", path, err)
			continue
		}
		if !strings.HasPrefix(string(data), "// SPDX-License-Identifier: AGPL-3.0-only\n") {
			t.Errorf("missing SPDX header: %s", path)
		}
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
