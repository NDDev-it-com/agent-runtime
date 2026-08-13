// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package signatureverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPlatformAncestorWalkerAcceptsCanonicalRepositoryPath(t *testing.T) {
	t.Parallel()
	fixture := newSignedRepository(t)
	identity, err := captureRepositoryIdentity(fixture.repository)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		if len(identity.aliases) != 1 || identity.aliases[0].name != "var" || identity.aliases[0].target != "private/var" {
			t.Fatalf("Darwin canonical alias transcript=%#v", identity.aliases)
		}
	} else if len(identity.aliases) != 0 {
		t.Fatalf("Linux accepted alias transcript=%#v", identity.aliases)
	}
	if err := identity.revalidate(); err != nil {
		t.Fatal(err)
	}
	if err := identity.close(); err != nil {
		t.Fatal(err)
	}
}

func TestAliasPoliciesAreExactAndFailClosed(t *testing.T) {
	t.Parallel()
	root := unixIdentity{uid: 0, mode: uint32(unix.S_IFDIR | 0o755), nlink: 1}
	link := unixIdentity{uid: 0, mode: uint32(unix.S_IFLNK | 0o777), nlink: 1}
	if components, err := (darwinCanonicalAliasPolicy{}).authorize(0, "var", "private/var", root, link, false); err != nil || strings.Join(components, "/") != "private/var" {
		t.Fatalf("canonical Darwin alias rejected: components=%v err=%v", components, err)
	}
	mutations := []struct {
		index       int
		name        string
		target      string
		parent      unixIdentity
		link        unixIdentity
		alreadyUsed bool
	}{
		{1, "var", "private/var", root, link, false},
		{0, "tmp", "private/var", root, link, false},
		{0, "var", "/private/var", root, link, false},
		{0, "var", "private/../private/var", root, link, false},
		{0, "var", "private/var", root, link, true},
		{0, "var", "private/var", unixIdentity{uid: 1, mode: root.mode, nlink: 1}, link, false},
		{0, "var", "private/var", unixIdentity{uid: 0, gid: 1, mode: root.mode, nlink: 1}, link, false},
		{0, "var", "private/var", root, unixIdentity{uid: 1, mode: link.mode, nlink: 1}, false},
		{0, "var", "private/var", root, unixIdentity{uid: 0, gid: 1, mode: link.mode, nlink: 1}, false},
		{0, "var", "private/var", root, unixIdentity{uid: 0, mode: link.mode, nlink: 2}, false},
	}
	for index, mutation := range mutations {
		if _, err := (darwinCanonicalAliasPolicy{}).authorize(mutation.index, mutation.name, mutation.target, mutation.parent, mutation.link, mutation.alreadyUsed); err == nil {
			t.Errorf("Darwin unsafe alias mutation %d accepted", index)
		}
	}
	if _, err := (denyAliasPolicy{}).authorize(0, "var", "private/var", root, link, false); err == nil {
		t.Fatal("Linux accepted a repository alias")
	}
}

func TestIdentityInvariantsDistinguishChurnFromReplacement(t *testing.T) {
	t.Parallel()
	directory := unixIdentity{dev: 1, ino: 2, mode: uint32(unix.S_IFDIR | 0o750), nlink: 3, uid: 4, gid: 5}
	legitimateChurn := directory
	legitimateChurn.nlink = 17
	if err := validateIdentity(directoryObject, directory, legitimateChurn); err != nil {
		t.Fatalf("live directory link-count churn rejected: %v", err)
	}
	symlink := unixIdentity{dev: 1, ino: 8, mode: uint32(unix.S_IFLNK | 0o755), nlink: 1, uid: 0, gid: 0}
	if err := validateIdentity(symlinkObject, symlink, symlink); err != nil {
		t.Fatalf("stable symlink rejected: %v", err)
	}
	mutations := map[string]struct {
		kind    filesystemObjectKind
		current unixIdentity
	}{
		"device":             {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.dev++ })},
		"inode":              {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.ino++ })},
		"type":               {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.mode = uint32(unix.S_IFREG | 0o750) })},
		"owner uid":          {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.uid++ })},
		"owner gid":          {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.gid++ })},
		"mode":               {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.mode ^= 0o020 })},
		"unlinked directory": {directoryObject, withIdentity(directory, func(value *unixIdentity) { value.nlink = 0 })},
		"symlink hard link":  {symlinkObject, withIdentity(symlink, func(value *unixIdentity) { value.nlink = 2 })},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			recorded := directory
			if mutation.kind == symlinkObject {
				recorded = symlink
			}
			if err := validateIdentity(mutation.kind, recorded, mutation.current); err == nil {
				t.Fatal("security-relevant identity drift accepted")
			}
		})
	}
}

func withIdentity(identity unixIdentity, mutate func(*unixIdentity)) unixIdentity {
	mutate(&identity)
	return identity
}

func TestAncestorWalkerAllowsUnrelatedChildChurn(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := captureRepositoryIdentity(repository)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := identity.close(); err != nil {
			t.Error(err)
		}
	}()
	sibling := filepath.Join(root, "unrelated-child")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := identity.revalidate(); err != nil {
		t.Fatalf("child creation changed stable identity: %v", err)
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}
	if err := identity.revalidate(); err != nil {
		t.Fatalf("child removal changed stable identity: %v", err)
	}
}

func TestAncestorWalkerRejectsComponentReplacement(t *testing.T) {
	for name, replacement := range map[string]func(string, string) error{
		"directory inode swap": func(original, replacementPath string) error {
			return os.Mkdir(replacementPath, 0o700)
		},
		"symlink insertion": func(original, replacementPath string) error {
			return os.Symlink(original, replacementPath)
		},
	} {
		t.Run(name, func(t *testing.T) {
			container := t.TempDir()
			ancestor := filepath.Join(container, "ancestor")
			repository := filepath.Join(ancestor, "repository")
			if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o700); err != nil {
				t.Fatal(err)
			}
			identity, err := captureRepositoryIdentity(repository)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := identity.close(); err != nil {
					t.Error(err)
				}
			}()
			moved := ancestor + ".owned"
			if err := os.Rename(ancestor, moved); err != nil {
				t.Fatal(err)
			}
			if err := replacement(moved, ancestor); err != nil {
				t.Fatal(err)
			}
			if err := identity.revalidate(); err == nil || !strings.Contains(err.Error(), "path identity changed") {
				t.Fatalf("ancestor replacement accepted: %v", err)
			}
			if err := os.Remove(ancestor); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, ancestor); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParallelRepositoriesUnderSharedAncestor(t *testing.T) {
	shared := t.TempDir()
	for index := 0; index < 8; index++ {
		index := index
		t.Run(fmt.Sprintf("repository-%d", index), func(t *testing.T) {
			t.Parallel()
			fixture := newSignedRepositoryIn(t, shared, fmt.Sprintf("fixture-%d", index))
			var stdout, stderr bytes.Buffer
			if _, err := verifyWithPolicy(context.Background(), Request{Repository: fixture.repository, Kind: Commit, ObjectSHA: fixture.commit, Stdout: &stdout, Stderr: &stderr}, execRunner{}, fixture.policy(t)); err != nil {
				t.Fatalf("parallel repository verification failed: %v", err)
			}
		})
	}
}

func TestAncestorWalkerRejectsUntrustedAliasAndBudgets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "attacker")
	if err := os.Symlink("target", alias); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRepositoryIdentity(alias); err == nil {
		t.Fatal("untrusted repository alias accepted")
	}
	components := make([]string, maxAncestorComponents+1)
	for index := range components {
		components[index] = "a"
	}
	if _, err := captureRepositoryIdentity(string(filepath.Separator) + filepath.Join(components...)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("ancestor component budget did not fail closed: %v", err)
	}
}

func TestRepositoryMetadataChangeFailsBeforeVerification(t *testing.T) {
	fixture := newSignedRepository(t)
	original, err := os.Stat(fixture.repository)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Repository: fixture.repository, Kind: Commit, ObjectSHA: fixture.commit, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	_, err = verifyWithOptions(context.Background(), request, fixture.policy(t), verifyOptions{
		commands: execRunner{}, snapshot: defaultSnapshotOperations(),
		beforeVerify: func(string) error { return os.Chmod(fixture.repository, original.Mode().Perm()^0o020) },
	})
	if restoreErr := os.Chmod(fixture.repository, original.Mode().Perm()); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("repository mode change accepted: %v", err)
	}
}

func TestAncestorCloseJoinsEveryFailure(t *testing.T) {
	t.Parallel()
	first := errors.New("first close")
	second := errors.New("second close")
	identity := repositoryIdentity{
		nodes: []ancestorNode{{fd: 1}, {fd: 2}},
		closeFD: func(fd int) error {
			if fd == 1 {
				return first
			}
			return second
		},
	}
	err := identity.close()
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("descriptor close failures were not joined: %v", err)
	}
	if err := identity.close(); err != nil {
		t.Fatalf("close-once ownership retried descriptors: %v", err)
	}
}
