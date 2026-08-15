// SPDX-License-Identifier: AGPL-3.0-only

package journalverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const root = "../.."

func TestRepositoryJournalsSatisfyBothContracts(t *testing.T) {
	t.Parallel()
	result, err := Verify(root, DefaultDirectory, SchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Journals) == 0 {
		t.Fatal("no journals verified")
	}
	t.Logf("verified %d journals: %s", len(result.Journals), strings.Join(result.Journals, ", "))
}

// TestVerifyRefusesToPassVacuously covers the failure mode this checker exists
// to remove. A gate that reports success because it found nothing to inspect is
// indistinguishable from one that inspected everything and found it sound.
func TestVerifyRefusesToPassVacuously(t *testing.T) {
	t.Parallel()
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "goals"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(empty, "goals", filepath.Join(root, SchemaPath)); err == nil {
		t.Fatal("an empty journal directory was reported as verified")
	}
}

// TestVerifyRejectsJournalsEitherContractRefuses pins that both statements of
// the vocabulary are applied. Checking only Go would let the published schema
// drift; checking only the schema would skip the durable invariants the type
// enforces.
func TestVerifyRejectsJournalsEitherContractRefuses(t *testing.T) {
	t.Parallel()
	valid, err := os.ReadFile(filepath.Join(root, DefaultDirectory, "initial-release.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, damage := range map[string]func(string) string{
		// The exact shape that shipped: a receipt keyed by something that is
		// not a phase. Both contracts must refuse it.
		"receipt keyed by a non-phase": func(s string) string {
			return strings.Replace(s, `"orient": {`, `"recovery_cycle_orient": {`, 1)
		},
		"evidence type outside the vocabulary": func(s string) string {
			return strings.Replace(s, `"type": "file"`, `"type": "source"`, 1)
		},
		"completed item without evidence": func(s string) string {
			return strings.Replace(s, `"status": "complete"`, `"status": "complete", "evidence": []`, 1)
		},
		"unsupported schema version": func(s string) string {
			return strings.Replace(s, `"schema_version": "v1alpha1"`, `"schema_version": "v1alpha0"`, 1)
		},
		"non-canonical encoding": func(s string) string {
			return strings.ReplaceAll(s, "\n  ", "\n    ")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			goals := filepath.Join(dir, "goals")
			if err := os.MkdirAll(goals, 0o700); err != nil {
				t.Fatal(err)
			}
			damaged := damage(string(valid))
			if damaged == string(valid) {
				t.Fatal("the damage is stale: it no longer changes the journal")
			}
			if err := os.WriteFile(filepath.Join(goals, "damaged.json"), []byte(damaged), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(dir, "goals", filepath.Join(root, SchemaPath)); err == nil {
				t.Fatal("a journal neither contract should accept was verified")
			}
		})
	}
}
