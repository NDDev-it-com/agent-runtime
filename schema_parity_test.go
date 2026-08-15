// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

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
	releaseBuildResult := readSchema(t, "schemas/release-build-result-v1alpha1.schema.json")
	provenance := readSchema(t, "schemas/provenance-contract-v1alpha1.schema.json")
	fuzz := readSchema(t, "schemas/fuzz-contract-v1alpha1.schema.json")
	for name, schema := range map[string]map[string]any{"task": task, "goal": goal, "governance": governance, "release contract": releaseContract, "release manifest": releaseManifest, "release build result": releaseBuildResult, "provenance": provenance, "fuzz": fuzz} {
		if schema["x-license"] != releasepkg.CanonicalLicense {
			t.Errorf("%s schema license=%v", name, schema["x-license"])
		}
	}
	if governance["properties"].(map[string]any)["schema_version"].(map[string]any)["const"] != "v1alpha1" {
		t.Fatal("repository governance schema version drift")
	}
	if releaseManifest["properties"].(map[string]any)["schema_version"].(map[string]any)["const"] != "v1alpha1" {
		t.Fatal("release schema identity drift")
	}
	buildResultProperties := releaseBuildResult["properties"].(map[string]any)
	if buildResultProperties["license"].(map[string]any)["const"] != releasepkg.CanonicalLicense || buildResultProperties["schema_version"].(map[string]any)["const"] != releasepkg.BuildResultSchemaVersion {
		t.Fatal("release build result license/schema identity drift")
	}
	// The release version is restated in five places and this was the one
	// nothing compared, so the build-result schema sat at v0.1.0 while the
	// producer emitted v0.1.3 and every test stayed green. Both release schemas
	// are pinned to the contract here so neither can drift alone again.
	contract, err := releasepkg.Load("release/v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, schema := range map[string]map[string]any{"release contract": releaseContract, "release build result": releaseBuildResult} {
		if got := schema["properties"].(map[string]any)["version"].(map[string]any)["const"]; got != contract.Version {
			t.Errorf("%s schema pins version %v, contract is %s", name, got, contract.Version)
		}
	}
	if provenance["properties"].(map[string]any)["integration_openpgp_status"].(map[string]any)["const"] != "active" || provenance["properties"].(map[string]any)["trust_update_policy"].(map[string]any)["const"] != "reviewed-contract-change" {
		t.Fatal("provenance trust policy schema drift")
	}
	if fuzz["properties"].(map[string]any)["fuzztime"].(map[string]any)["const"] != "100x" || fuzz["properties"].(map[string]any)["parallel"].(map[string]any)["const"] != float64(1) {
		t.Fatal("fuzz execution bounds schema drift")
	}
	wantDependencyPaths := make([]string, len(contract.Dependencies))
	for index := range contract.Dependencies {
		wantDependencyPaths[index] = contract.Dependencies[index].ModulePath
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
	wantPhases := make([]string, len(goalpkg.Phases()))
	for i, p := range goalpkg.Phases() {
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
	// The Goal schema and the Go contract must agree on the identifier grammar and
	// on receipts being keyed by the phase enumeration. The schema left both open,
	// so a journal the runtime rejects still validated against the distributable
	// contract.
	identifier, ok := defs["identifier"].(map[string]any)["pattern"].(string)
	if !ok {
		t.Fatal("Goal schema does not define a shared identifier grammar")
	}
	if identifier != idPattern.String() {
		t.Fatalf("identifier grammar drift: schema %q, runtime %q", identifier, idPattern.String())
	}
	goalProperties := goal["properties"].(map[string]any)["goal"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"id"} {
		if ref := goalProperties[field].(map[string]any)["$ref"]; ref != "#/$defs/identifier" {
			t.Fatalf("goal %s does not use the shared identifier grammar: %v", field, ref)
		}
	}
	if ref := defs["checklistItem"].(map[string]any)["properties"].(map[string]any)["id"].(map[string]any)["$ref"]; ref != "#/$defs/identifier" {
		t.Fatalf("checklist item id does not use the shared identifier grammar: %v", ref)
	}
	if ref := goalProperties["receipts"].(map[string]any)["propertyNames"].(map[string]any)["$ref"]; ref != "#/$defs/phase" {
		t.Fatalf("receipts are not keyed by the phase enumeration: %v", ref)
	}
	assertIdentifierParity(t, identifier)

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

// assertIdentifierParity checks that the published grammar and the Goal state
// machine accept exactly the same identifiers.
func assertIdentifierParity(t *testing.T, pattern string) {
	t.Helper()
	grammar := regexp.MustCompile(pattern)
	cases := map[string]bool{
		"release": true, "release-ready": true, "a": true, "a.b_c-d": true, "curl": true, "run-command": true,
		"": false, "Release": false, "1release": false, "release--ready": false, "release-": false, ".release": false,
	}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	for id, want := range cases {
		if got := grammar.MatchString(id); got != want {
			t.Errorf("schema grammar accepts %q = %v, want %v", id, got, want)
		}
		_, err := goalpkg.New(id, "intent", []goalpkg.ChecklistItem{{ID: "item", Acceptance: "criterion"}}, nil, now)
		if got := err == nil; got != want {
			t.Errorf("Goal accepts id %q = %v, want %v (%v)", id, got, want, err)
		}
		_, err = goalpkg.New("release", "intent", []goalpkg.ChecklistItem{{ID: id, Acceptance: "criterion"}}, nil, now)
		if got := err == nil; got != want {
			t.Errorf("Goal accepts checklist id %q = %v, want %v (%v)", id, got, want, err)
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
