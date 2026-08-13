// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package releasecontract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var errInjectedRoot = errors.New("injected root failure")

func TestSecurePublishSuccessNoOverwriteAndNoTemporaryLeak(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := t.TempDir()
	out := filepath.Join(parent, "release")
	closed := map[uint64]int{}
	opts := defaultTransactionOptions()
	opts.close = func(request closeRequest) error {
		closed[request.ownerID()]++
		return request.closeUnderlying()
	}
	if err := publishBundleWithOptions(out, c, assets, opts); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(out, c); err != nil {
		t.Fatal(err)
	}
	for ownerID, count := range closed {
		if count != 1 {
			t.Fatalf("owner %d closed %d times", ownerID, count)
		}
	}
	assertNoStageEntries(t, parent)
	if err := publishBundleWithOptions(out, c, assets, defaultTransactionOptions()); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("second publisher error=%v", err)
	} else {
		assertOutputFailure(t, err, OutputDestinationExists)
	}
	if err := VerifyBundle(out, c); err != nil {
		t.Fatal(err)
	}
}

func TestSecurePublishRequiresExistingPrivateParentAndMissingLeaf(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	root := t.TempDir()
	for _, test := range []struct {
		name string
		path string
		kind OutputFailure
		prepare func() error
	}{
		{name: "missing parent", path: filepath.Join(root, "missing", "release"), kind: OutputInvalidParent},
		{name: "shared parent mode", path: filepath.Join(root, "shared", "release"), kind: OutputInvalidParent, prepare: func() error { return os.Mkdir(filepath.Join(root, "shared"), 0o755) }},
		{name: "existing file", path: filepath.Join(root, "file"), kind: OutputDestinationExists, prepare: func() error { return os.WriteFile(filepath.Join(root, "file"), []byte("foreign"), 0o600) }},
		{name: "existing directory", path: filepath.Join(root, "directory"), kind: OutputDestinationExists, prepare: func() error { return os.Mkdir(filepath.Join(root, "directory"), 0o700) }},
		{name: "existing symlink", path: filepath.Join(root, "symlink"), kind: OutputDestinationExists, prepare: func() error { return os.Symlink("foreign", filepath.Join(root, "symlink")) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if test.prepare != nil {
				if err := test.prepare(); err != nil {
					t.Fatal(err)
				}
			}
			err := publishBundleWithOptions(test.path, c, assets, defaultTransactionOptions())
			assertOutputFailure(t, err, test.kind)
		})
	}
}

func TestNormalizedFilesystemMetadataContract(t *testing.T) {
	t.Parallel()
	var st unix.Stat_t
	st.Mode = unix.S_IFREG | 0o644
	st.Nlink = 1
	identity := identityOf(st)
	record := &assetRecord{identity: identity, parent: identity, mode: 0o644}
	if fileType(st) != uint32(unix.S_IFREG) || filePermissions(st) != 0o644 || linkCount(st) != 1 {
		t.Fatal("lossless filesystem metadata normalization drifted")
	}
	if !assetMetadataMatches(record, identity, st) {
		t.Fatal("canonical owned regular file metadata rejected")
	}
	st.Mode = unix.S_IFDIR | 0o644
	if assetMetadataMatches(record, identity, st) {
		t.Fatal("directory accepted as an owned regular file")
	}
}

func TestDirectoryTrustRolesAreObjectSpecific(t *testing.T) {
	t.Parallel()
	openDirectory := func(t *testing.T, path string) (int, fileIdentity) {
		t.Helper()
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := identityForFD(fd)
		if err != nil {
			_ = unix.Close(fd)
			t.Fatal(err)
		}
		return fd, identity
	}
	for _, test := range []struct {
		name string
		mode os.FileMode
		role directoryTrustRole
		wantOK bool
	}{
		{name: "caller private 0700", mode: 0o700, role: directoryRoleCallerParent, wantOK: true},
		{name: "stage private 0700", mode: 0o700, role: directoryRoleStage, wantOK: true},
		{name: "ancestor shared 0755", mode: 0o755, role: directoryRoleAncestor, wantOK: true},
		{name: "caller group writable", mode: 0o770, role: directoryRoleCallerParent},
		{name: "caller world writable", mode: 0o707, role: directoryRoleCallerParent},
		{name: "caller lacks owner write", mode: 0o500, role: directoryRoleCallerParent},
		{name: "stage permissive", mode: 0o755, role: directoryRoleStage},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "role")
			if err := os.Mkdir(path, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			fd, identity := openDirectory(t, path)
			defer unix.Close(fd)
			err := validateDirectoryRole(fd, identity, test.role)
			if test.wantOK && err != nil {
				t.Fatal(err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("unsafe directory role accepted")
			}
		})
	}
	t.Run("wrong identity", func(t *testing.T) {
		fd, identity := openDirectory(t, t.TempDir())
		defer unix.Close(fd)
		identity.ino++
		if err := validateDirectoryRole(fd, identity, directoryRoleCallerParent); err == nil {
			t.Fatal("substituted identity accepted")
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		fd, identity := openDirectory(t, t.TempDir())
		defer unix.Close(fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		if err := validateDirectoryMetadata(st, identity, directoryRoleCallerParent, uint32(st.Uid)+1); err == nil {
			t.Fatal("wrong owner accepted")
		}
	})
	t.Run("unlinked directory", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "deleted")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		fd, identity := openDirectory(t, path)
		defer unix.Close(fd)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := validateDirectoryRole(fd, identity, directoryRoleCallerParent); err == nil {
			t.Fatal("unlinked directory accepted")
		}
	})
	t.Run("stale descriptor", func(t *testing.T) {
		fd, identity := openDirectory(t, t.TempDir())
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		if err := validateDirectoryRole(fd, identity, directoryRoleCallerParent); err == nil {
			t.Fatal("closed descriptor accepted")
		}
	})
	t.Run("non-directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		identity, err := identityForFD(fd)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateDirectoryRole(fd, identity, directoryRoleCallerParent); err == nil {
			t.Fatal("regular file accepted as caller parent")
		}
	})
}

func TestAnchoredParentTraversesAndRevalidatesBoundedRelativeSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(actual, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink("actual", alias); err != nil {
		t.Fatal(err)
	}
	anchor, err := openAnchoredParent(filepath.Join(alias, "release"), defaultTransactionOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := anchor.release(false, defaultTransactionOptions()); err != nil {
			t.Error(err)
		}
	}()
	foundAlias := false
	for _, link := range anchor.symlinks {
		if link.name == "alias" && link.target == "actual" {
			foundAlias = true
		}
	}
	if !foundAlias {
		t.Fatalf("symlink transcript=%#v", anchor.symlinks)
	}
	if err := anchor.revalidate(defaultTransactionOptions()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other", alias); err != nil {
		t.Fatal(err)
	}
	if err := anchor.revalidate(defaultTransactionOptions()); err == nil {
		t.Fatal("symlink target/identity swap accepted")
	}
}

func TestSymlinkTargetPolicyRejectsAbsoluteEscapeCycleShapes(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"", "/private/var", "../escape", "a/../b", "./a", "a//b", strings.Repeat("a", 4097)} {
		if _, err := safeSymlinkTarget(target); err == nil {
			t.Fatalf("unsafe symlink target accepted: %q", target)
		}
	}
	if parts, err := safeSymlinkTarget("private/var"); err != nil || !reflect.DeepEqual(parts, []string{"private", "var"}) {
		t.Fatalf("relative alias rejected: %v %v", parts, err)
	}
}

func TestAnchoredParentRejectsSymlinkCycle(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Symlink("b", filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := openAnchoredParent(filepath.Join(root, "a", "release"), defaultTransactionOptions()); err == nil || !strings.Contains(err.Error(), "symlink hop bound") {
		t.Fatalf("symlink cycle did not fail at its bound: %v", err)
	}
}

func TestSecurePublishPartialOwnedSubsetsRollBack(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	for failAfter := 0; failAfter <= len(c.Assets.Names()); failAfter++ {
		failAfter := failAfter
		t.Run(fmt.Sprintf("after-%d-assets", failAfter), func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			out := filepath.Join(parent, "release")
			opened := 0
			opts := defaultTransactionOptions()
			opts.hook = func(point string, _ *bundleTransaction) error {
				if failAfter == 0 && point == "after_stage" {
					return errInjectedRoot
				}
				if strings.HasPrefix(point, "asset_opened:") {
					opened++
					if opened == failAfter {
						return errInjectedRoot
					}
				}
				return nil
			}
			err := publishBundleWithOptions(out, c, assets, opts)
			if !errors.Is(err, errInjectedRoot) {
				t.Fatalf("error=%v", err)
			}
			assertOutputFailure(t, err, OutputPartial)
			if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("partial destination: %v", statErr)
			}
			assertNoStageEntries(t, parent)
		})
	}
}

func TestSecurePublishHandlesPartialWrites(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	out := filepath.Join(t.TempDir(), "release")
	opts := defaultTransactionOptions()
	opts.write = func(fd int, data []byte) (int, error) {
		if len(data) > 1 {
			data = data[:len(data)/2]
		}
		return unix.Write(fd, data)
	}
	if err := publishBundleWithOptions(out, c, assets, opts); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(out, c); err != nil {
		t.Fatal(err)
	}
}

func TestSecurePublishDestinationRaceAndConcurrentPublishers(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	for _, kind := range []string{"directory", "file", "symlink"} {
		kind := kind
		t.Run("destination "+kind+" created before publish", func(t *testing.T) {
			parent := t.TempDir()
			out := filepath.Join(parent, "release")
			opts := defaultTransactionOptions()
			opts.hook = func(point string, tx *bundleTransaction) error {
				if point != "before_publish" {
					return nil
				}
				switch kind {
				case "directory":
					return unix.Mkdirat(tx.anchor.parentFD(), tx.finalName, 0o700)
				case "file":
					fd, err := unix.Openat(tx.anchor.parentFD(), tx.finalName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0o600)
					if err == nil {
						err = closeTestDescriptor(fd)
					}
					return err
				default:
					return unix.Symlinkat("attacker", tx.anchor.parentFD(), tx.finalName)
				}
			}
			err := publishBundleWithOptions(out, c, assets, opts)
			if !errors.Is(err, unix.EEXIST) {
				t.Fatalf("error=%v", err)
			}
			assertOutputFailure(t, err, OutputDestinationExists)
			assertNoStageEntries(t, parent)
		})
	}
	t.Run("two publishers", func(t *testing.T) {
		parent := t.TempDir()
		out := filepath.Join(parent, "release")
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); errs <- publishBundleWithOptions(out, c, assets, defaultTransactionOptions()) }()
		}
		wg.Wait()
		close(errs)
		success, exists := 0, 0
		for err := range errs {
			if err == nil {
				success++
			} else if errors.Is(err, unix.EEXIST) {
				exists++
			} else {
				t.Fatalf("unexpected error %v", err)
			}
		}
		if success != 1 || exists != 1 {
			t.Fatalf("success=%d exists=%d", success, exists)
		}
		if err := VerifyBundle(out, c); err != nil {
			t.Fatal(err)
		}
		assertNoStageEntries(t, parent)
	})
}

func TestSecurePublishPostPublishFailureRollsBackOnlyOwnedFinal(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := t.TempDir()
	out := filepath.Join(parent, "release")
	opts := defaultTransactionOptions()
	opts.hook = func(point string, _ *bundleTransaction) error {
		if point == "after_publish" {
			return errInjectedRoot
		}
		return nil
	}
	err := publishBundleWithOptions(out, c, assets, opts)
	if !errors.Is(err, errInjectedRoot) {
		t.Fatalf("root lost: %v", err)
	}
	if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("published rollback leaked: %v", statErr)
	}
	assertNoStageEntries(t, parent)
}

func TestSecurePublishStageRenameWithoutReplacementUsesOwnedIdentity(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := t.TempDir()
	out := filepath.Join(parent, "release")
	opts := defaultTransactionOptions()
	opts.hook = func(point string, tx *bundleTransaction) error {
		if point == "after_write" {
			if err := unix.Renameat(tx.anchor.parentFD(), tx.stageName, tx.anchor.parentFD(), tx.stageName+"-moved"); err != nil {
				return err
			}
			return errInjectedRoot
		}
		return nil
	}
	err := publishBundleWithOptions(out, c, assets, opts)
	if !errors.Is(err, errInjectedRoot) {
		t.Fatalf("root lost: %v", err)
	}
	assertNoStageEntries(t, parent)
}

func TestPublicVerifyBundleRejectsSymlinkAndUnexpectedClosure(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := publishBundleWithOptions(real, c, assets, defaultTransactionOptions()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(link, c); err == nil {
		t.Fatal("symlinked bundle accepted")
	}
	if err := os.WriteFile(filepath.Join(real, "foreign"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(real, c); err == nil {
		t.Fatal("unexpected asset accepted")
	}
}

func TestSecurePublishPreservesForeignAndReplacedEntriesAsResidualDebt(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	tests := []struct {
		name   string
		mutate func(*bundleTransaction) error
	}{
		{"unexpected entry", func(tx *bundleTransaction) error {
			fd, err := unix.Openat(tx.stage.handle(), "foreign", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0o644)
			if err == nil {
				err = closeTestDescriptor(fd)
			}
			return err
		}},
		{"same-name replacement", func(tx *bundleTransaction) error {
			name := c.Assets.Archive
			if err := unix.Unlinkat(tx.stage.handle(), name, 0); err != nil {
				return err
			}
			fd, err := unix.Openat(tx.stage.handle(), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0o644)
			if err == nil {
				_, _ = unix.Write(fd, []byte("foreign"))
				err = closeTestDescriptor(fd)
			}
			return err
		}},
		{"nested entry", func(tx *bundleTransaction) error { return unix.Mkdirat(tx.stage.handle(), "nested", 0o700) }},
		{"mode replacement", func(tx *bundleTransaction) error { return unix.Fchmodat(tx.stage.handle(), c.Assets.Notes, 0o600, 0) }},
		{"nlink replacement", func(tx *bundleTransaction) error {
			return unix.Linkat(tx.stage.handle(), c.Assets.Manifest, tx.stage.handle(), "foreign-link", 0)
		}},
		{"type replacement", func(tx *bundleTransaction) error {
			name := c.Assets.SBOM
			if err := unix.Unlinkat(tx.stage.handle(), name, 0); err != nil {
				return err
			}
			return unix.Symlinkat("foreign-target", tx.stage.handle(), name)
		}},
		{"stage replacement", func(tx *bundleTransaction) error {
			moved := tx.stageName + "-moved"
			if err := unix.Renameat(tx.anchor.parentFD(), tx.stageName, tx.anchor.parentFD(), moved); err != nil {
				return err
			}
			return unix.Mkdirat(tx.anchor.parentFD(), tx.stageName, 0o700)
		}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			out := filepath.Join(parent, "release")
			opts := defaultTransactionOptions()
			opts.hook = func(point string, tx *bundleTransaction) error {
				if point == "after_write" {
					if err := tc.mutate(tx); err != nil {
						return err
					}
					return errInjectedRoot
				}
				return nil
			}
			err := publishBundleWithOptions(out, c, assets, opts)
			if !errors.Is(err, errInjectedRoot) {
				t.Fatalf("root lost: %v", err)
			}
			var debt *residualDebtError
			if !errors.As(err, &debt) {
				t.Fatalf("residual debt absent: %v", err)
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) == 0 {
				t.Fatal("foreign/replaced state was deleted")
			}
		})
	}
}

func TestSecurePublishAncestorSwapNeverWritesAttackerTree(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(root, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "release")
	opts := defaultTransactionOptions()
	opts.hook = func(point string, _ *bundleTransaction) error {
		if point == "after_write" {
			if err := os.Rename(parent, parent+"-moved"); err != nil {
				return err
			}
			if err := os.Symlink(attacker, parent); err != nil {
				return err
			}
		}
		return nil
	}
	err := publishBundleWithOptions(out, c, assets, opts)
	if err == nil {
		t.Fatal("ancestor substitution accepted")
	}
	assertOutputFailure(t, err, OutputIdentityChanged)
	entries, readErr := os.ReadDir(attacker)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("attacker tree modified: %v", entries)
	}
	if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination visible through attacker path: %v", statErr)
	}
}

func TestSecurePublishVerifyTimeAssetSwapFailsClosed(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := t.TempDir()
	out := filepath.Join(parent, "release")
	opts := defaultTransactionOptions()
	opts.hook = func(point string, tx *bundleTransaction) error {
		if point == "after_verify" {
			name := c.Assets.Notes
			if err := unix.Unlinkat(tx.stage.handle(), name, 0); err != nil {
				return err
			}
			fd, err := unix.Openat(tx.stage.handle(), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0o644)
			if err == nil {
				err = closeTestDescriptor(fd)
			}
			return err
		}
		return nil
	}
	err := publishBundleWithOptions(out, c, assets, opts)
	if err == nil {
		t.Fatal("verify-time swap accepted")
	}
	var debt *residualDebtError
	if !errors.As(err, &debt) {
		t.Fatalf("residual debt absent: %v", err)
	}
	if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial output: %v", statErr)
	}
}

func TestSecurePublishAggregatesRootAndCleanupErrorsDeterministically(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	parent := t.TempDir()
	out := filepath.Join(parent, "release")
	errSync := errors.New("sync cleanup evidence")
	errClose := errors.New("close cleanup evidence")
	errUnlink := errors.New("unlink cleanup evidence")
	opts := defaultTransactionOptions()
	opts.hook = func(point string, _ *bundleTransaction) error {
		if point == "after_stage" {
			return errInjectedRoot
		}
		return nil
	}
	opts.fsync = func(int) error { return errSync }
	opts.close = func(request closeRequest) error {
		closeErr := request.closeUnderlying()
		if request.ownerRole() == fdRoleStage {
			return errors.Join(errClose, closeErr)
		}
		return closeErr
	}
	opts.unlinkat = func(int, string, int) error { return errUnlink }
	err := publishBundleWithOptions(out, c, assets, opts)
	for _, want := range []error{errInjectedRoot, errSync, errClose, errUnlink} {
		if !errors.Is(err, want) {
			t.Fatalf("missing %v in %v", want, err)
		}
	}
	assertOutputFailure(t, err, OutputCleanup)
	text := err.Error()
	positions := []int{strings.Index(text, "injected root failure"), strings.Index(text, "sync cleanup evidence"), strings.Index(text, "unlink cleanup evidence"), strings.Index(text, "close cleanup evidence")}
	for index, position := range positions {
		if position < 0 {
			t.Fatalf("missing ordered evidence: %s", text)
		}
		if index > 0 && position < positions[index-1] {
			t.Fatalf("cleanup evidence order changed: %s", text)
		}
	}
}

func TestRevalidationCloseFailureIsRoleTargetedAndFailClosed(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	out := filepath.Join(t.TempDir(), "release")
	errRevalidationClose := errors.New("revalidation close evidence")
	calls := map[uint64]int{}
	opts := defaultTransactionOptions()
	opts.close = func(request closeRequest) error {
		calls[request.ownerID()]++
		closeErr := request.closeUnderlying()
		if request.ownerRole() == fdRoleRevalidationParent {
			return errors.Join(errRevalidationClose, closeErr)
		}
		return closeErr
	}
	err := publishBundleWithOptions(out, c, assets, opts)
	if !errors.Is(err, errRevalidationClose) {
		t.Fatalf("revalidation close failure swallowed: %v", err)
	}
	for ownerID, count := range calls {
		if count != 1 {
			t.Fatalf("owner %d closed %d times", ownerID, count)
		}
	}
	if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed revalidation exposed destination: %v", statErr)
	}
}

func TestFDOwnershipIdentitySurvivesForcedRawDescriptorReuse(t *testing.T) {
	t.Parallel()
	calls := map[uint64]int{}
	rawUses := map[int]int{}
	opts := defaultTransactionOptions()
	opts.close = func(request closeRequest) error {
		calls[request.ownerID()]++
		rawUses[request.rawHandle()]++
		return request.closeUnderlying()
	}
	for range 32 {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		owner := newFDOwner(fd, fdRoleVerifiedAsset, "forced reuse fixture")
		if err := owner.closeOnce(opts, "close forced reuse fixture"); err != nil {
			t.Fatal(err)
		}
		if err := owner.closeOnce(opts, "repeat close must be inert"); err != nil {
			t.Fatal(err)
		}
	}
	reused := false
	for _, count := range rawUses {
		if count > 1 {
			reused = true
		}
	}
	if !reused {
		t.Fatal("fixture did not force raw descriptor reuse")
	}
	if len(calls) != 32 {
		t.Fatalf("ownership identities=%d, want 32", len(calls))
	}
	for ownerID, count := range calls {
		if count != 1 {
			t.Fatalf("owner %d closed %d times", ownerID, count)
		}
	}
}

func TestSecurePublishCloseOwnershipFailuresDoNotDoubleClose(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	for _, kind := range []string{"asset", "stage", "parent"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			out := filepath.Join(parent, "release")
			opts := defaultTransactionOptions()
			var targetOwner uint64
			calls := map[uint64]int{}
			opts.hook = func(point string, tx *bundleTransaction) error {
				if point == "after_write" {
					switch kind {
					case "asset":
						targetOwner = tx.assetIDs[c.Assets.Archive].fd.metadata().ownerID()
					case "stage":
						targetOwner = tx.stage.metadata().ownerID()
					case "parent":
						targetOwner = tx.anchor.nodes[len(tx.anchor.nodes)-1].fd.metadata().ownerID()
					}
				}
				return nil
			}
			errClose := fmt.Errorf("%s close evidence", kind)
			opts.close = func(request closeRequest) error {
				calls[request.ownerID()]++
				closeErr := request.closeUnderlying()
				if request.ownerID() == targetOwner {
					return errors.Join(errClose, closeErr)
				}
				return closeErr
			}
			err := publishBundleWithOptions(out, c, assets, opts)
			if !errors.Is(err, errClose) {
				t.Fatalf("close evidence absent: %v", err)
			}
			if calls[targetOwner] != 1 {
				t.Fatalf("target owner close calls=%d", calls[targetOwner])
			}
			for ownerID, count := range calls {
				if count != 1 {
					t.Fatalf("owner %d closed %d times", ownerID, count)
				}
			}
		})
	}
}

func TestSecurePublishInjectedWriteFsyncRenameEnumerationAndUnlinkFailures(t *testing.T) {
	t.Parallel()
	c, assets := transactionFixture(t)
	tests := []struct {
		name      string
		configure func(*transactionOptions)
	}{
		{"write", func(o *transactionOptions) { o.write = func(int, []byte) (int, error) { return 0, syscall.EIO } }},
		{"asset fsync", func(o *transactionOptions) { o.fsync = func(int) error { return syscall.EIO } }},
		{"rename", func(o *transactionOptions) {
			o.renameNoReplace = func(int, string, int, string) error { return syscall.ENOTSUP }
		}},
		{"enumerate", func(o *transactionOptions) { o.enumerate = func(int) ([]string, error) { return nil, syscall.EIO } }},
		{"unlink", func(o *transactionOptions) {
			o.hook = func(point string, _ *bundleTransaction) error {
				if point == "after_stage" {
					return errInjectedRoot
				}
				return nil
			}
			o.unlinkat = func(int, string, int) error { return syscall.EPERM }
		}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			out := filepath.Join(parent, "release")
			opts := defaultTransactionOptions()
			tc.configure(&opts)
			if err := publishBundleWithOptions(out, c, assets, opts); err == nil {
				t.Fatal("injected failure accepted")
			}
			if _, err := os.Lstat(out); err == nil {
				t.Fatal("final destination visible")
			}
		})
	}
}

func transactionFixture(t *testing.T) (Contract, map[string][]byte) {
	t.Helper()
	c := testContract()
	root := fixtureRepo(t)
	resolved := strings.TrimSpace(gitOutput(t, root, "rev-parse", "HEAD"))
	files, err := readTree(root, resolved, c.Limits)
	if err != nil {
		t.Fatal(err)
	}
	assets, err := buildBundleData(files, resolved, time.Unix(1, 0).UTC(), c)
	if err != nil {
		t.Fatal(err)
	}
	return c, assets
}

func closeTestDescriptor(fd int) error {
	owner := newFDOwner(fd, fdRoleTestFixture, "test fixture descriptor")
	return owner.closeOnce(defaultTransactionOptions(), "close test fixture descriptor")
}
func assertNoStageEntries(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".release-stage-") {
			t.Fatalf("stage leaked: %s", entry.Name())
		}
	}
}

func assertOutputFailure(t *testing.T, err error, want OutputFailure) {
	t.Helper()
	if err == nil {
		t.Fatalf("missing typed output failure %q", want)
	}
	var output *OutputError
	if !errors.As(err, &output) || output.Kind != want || output.Operation == "" || output.Err == nil {
		t.Fatalf("output failure=%#v error=%v, want %q", output, err, want)
	}
}
