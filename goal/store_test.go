// SPDX-License-Identifier: AGPL-3.0-only

package goal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTripAndRevisionConflict(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state", "goal.json")
	store := Store{Path: path}
	initial := newTestJournal(t)
	if err := store.Create(initial); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 1 || loaded.Goal.CurrentPhase != PhaseOrient {
		t.Fatalf("loaded=%#v", loaded)
	}
	updated, err := store.Update(1, func(j *Journal) error {
		return j.Advance(Receipt{Phase: PhaseOrient, Summary: "oriented", Evidence: newTestEvidence()}, testNow)
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Goal.CurrentPhase != PhaseGapPlan {
		t.Fatalf("updated=%#v", updated)
	}
	if _, err := store.Update(1, func(j *Journal) error { return nil }); !IsCode(err, CodeConflict) {
		t.Fatalf("conflict error=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestStoreRejectsCorruptJournal(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "goal.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"v1alpha1"} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: path}).Load(); err == nil {
		t.Fatal("expected corrupt journal error")
	}
}
