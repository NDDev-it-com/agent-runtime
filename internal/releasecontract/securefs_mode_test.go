// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package releasecontract

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Release output must be identical on every host. O_CREAT and mkdirat subtract
// the process umask from the requested mode, so without an explicit fchmod a
// bundle built under umask 077 carried mode 0600 and failed its own verifier.
func TestPublishedModesAreIndependentOfTheProcessUmask(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := privateTempDir(t)
	out := filepath.Join(parent, "release")

	requested := map[int]uint32{}
	opts := defaultTransactionOptions()
	opts.fchmod = func(fd int, mode uint32) error {
		requested[fd] = mode
		return unix.Fchmod(fd, mode)
	}
	if err := publishBundleWithOptions(out, c, assets, opts); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(out, c); err != nil {
		t.Fatal(err)
	}
	// The stage directory plus every published asset had its mode set explicitly.
	if len(requested) != 1+len(c.Assets.Names()) {
		t.Fatalf("explicit mode calls=%d, want %d", len(requested), 1+len(c.Assets.Names()))
	}
	modes := map[uint32]int{}
	for _, mode := range requested {
		modes[mode]++
	}
	if modes[stageDirectoryMode] != 1 || modes[assetFileMode] != len(c.Assets.Names()) {
		t.Fatalf("requested modes=%v", modes)
	}
	for _, name := range c.Assets.Names() {
		info, err := os.Lstat(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != assetFileMode {
			t.Fatalf("asset %q published with mode %o, want %o", name, info.Mode().Perm(), assetFileMode)
		}
	}
}

func TestPublishFailsClosedWhenTheStageModeCannotBeSet(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := privateTempDir(t)
	out := filepath.Join(parent, "release")
	failure := errors.New("fchmod refused")
	opts := defaultTransactionOptions()
	opts.fchmod = func(int, uint32) error { return failure }

	if err := publishBundleWithOptions(out, c, assets, opts); !errors.Is(err, failure) {
		t.Fatalf("publish did not fail closed on an unsettable stage mode: %v", err)
	}
	if _, err := os.Lstat(out); err == nil {
		t.Fatal("a failed publish left a destination behind")
	}
	// The stage is removed because nothing inside it was created yet.
	assertNoStageEntries(t, parent)
}

func TestPublishFailsClosedWhenAnAssetModeCannotBeSet(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := privateTempDir(t)
	out := filepath.Join(parent, "release")
	failure := errors.New("fchmod refused")
	calls := 0
	opts := defaultTransactionOptions()
	opts.fchmod = func(fd int, mode uint32) error {
		calls++
		if calls == 1 {
			return unix.Fchmod(fd, mode)
		}
		return failure
	}

	if err := publishBundleWithOptions(out, c, assets, opts); !errors.Is(err, failure) {
		t.Fatalf("publish did not fail closed on an unsettable asset mode: %v", err)
	}
	if _, err := os.Lstat(out); err == nil {
		t.Fatal("a failed publish left a destination behind")
	}
	// Stage state may be retained here by design: an asset whose mode could not
	// be set no longer matches its recorded identity, and the transaction
	// preserves rather than deletes state it can no longer account for.
}
