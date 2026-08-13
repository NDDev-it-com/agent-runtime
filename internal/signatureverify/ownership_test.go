// SPDX-License-Identifier: AGPL-3.0-only

package signatureverify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustSnapshotCreationPreservesStageFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]func(ownedFile) ownedFile{
		"write": func(file ownedFile) ownedFile {
			return &faultFile{ownedFile: file, writeErr: errors.New("write failure")}
		},
		"fsync": func(file ownedFile) ownedFile {
			return &faultFile{ownedFile: file, syncErr: errors.New("fsync failure")}
		},
		"close": func(file ownedFile) ownedFile {
			return &faultFile{ownedFile: file, closeErr: errors.New("close failure")}
		},
	}
	for name, wrap := range tests {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			operations := defaultSnapshotOperations()
			operations.mkdirTemp = func(string, string) (string, error) {
				return os.MkdirTemp(base, "trust-")
			}
			open := operations.openFile
			operations.openFile = func(path string, flags int, mode os.FileMode) (ownedFile, error) {
				file, err := open(path, flags, mode)
				if err != nil {
					return nil, err
				}
				return wrap(file), nil
			}
			if _, err := createTrustSnapshot([]byte("trust\n"), operations); err == nil || !strings.Contains(err.Error(), name+" failure") {
				t.Fatalf("%s failure was lost: %v", name, err)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("failed snapshot leaked: %v", entries)
			}
		})
	}
}

func TestTrustSnapshotCleanupFailureJoinsRootFailure(t *testing.T) {
	fixture := newSignedRepository(t)
	rootFailure := errors.New("verification root failure")
	cleanupFailure := errors.New("injected cleanup failure")
	operations := defaultSnapshotOperations()
	base := t.TempDir()
	operations.mkdirTemp = func(string, string) (string, error) {
		return os.MkdirTemp(base, "trust-")
	}
	operations.remove = func(string) error { return cleanupFailure }
	commands := &recordingRunner{
		failureAt:    3,
		failure:      rootFailure,
		trackedTrust: []byte(fixture.principal + " " + fixture.publicKey + "\n"),
	}
	request := Request{
		Repository: fixture.repository,
		Kind:       Commit,
		ObjectSHA:  fixture.commit,
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}
	_, err := verifyWithOptions(context.Background(), request, fixture.policy(t), verifyOptions{
		commands: commands,
		snapshot: operations,
	})
	if !errors.Is(err, rootFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("root and cleanup failures were not both preserved: %v", err)
	}
}

func TestTrustSnapshotInPlaceMutationFailsClosed(t *testing.T) {
	fixture := newSignedRepository(t)
	request := Request{
		Repository: fixture.repository,
		Kind:       Commit,
		ObjectSHA:  fixture.commit,
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}
	_, err := verifyWithOptions(context.Background(), request, fixture.policy(t), verifyOptions{
		commands: execRunner{},
		snapshot: defaultSnapshotOperations(),
		beforeVerify: func(path string) error {
			return os.WriteFile(path, []byte("changed in place\n"), 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "contents changed") {
		t.Fatalf("in-place trust mutation was accepted: %v", err)
	}
}

func TestTrustSnapshotReplacementIsPreservedAsResidualDebt(t *testing.T) {
	fixture := newSignedRepository(t)
	var snapshotPath, ownedPath string
	request := Request{
		Repository: fixture.repository,
		Kind:       Commit,
		ObjectSHA:  fixture.commit,
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}
	_, err := verifyWithOptions(context.Background(), request, fixture.policy(t), verifyOptions{
		commands: execRunner{},
		snapshot: defaultSnapshotOperations(),
		beforeVerify: func(path string) error {
			snapshotPath = path
			ownedPath = path + ".owned"
			if err := os.Rename(path, ownedPath); err != nil {
				return err
			}
			return os.WriteFile(path, []byte("foreign replacement\n"), 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "residual unowned trust snapshot preserved") {
		t.Fatalf("snapshot replacement did not fail with residual debt: %v", err)
	}
	if data, readErr := os.ReadFile(snapshotPath); readErr != nil || string(data) != "foreign replacement\n" {
		t.Fatalf("foreign replacement was removed or changed: data=%q err=%v", data, readErr)
	}
	if removeErr := os.Remove(snapshotPath); removeErr != nil {
		t.Fatal(removeErr)
	}
	if removeErr := os.Remove(ownedPath); removeErr != nil {
		t.Fatal(removeErr)
	}
	if removeErr := os.Remove(filepath.Dir(snapshotPath)); removeErr != nil {
		t.Fatal(removeErr)
	}
}

func TestRepositoryReplacementCannotRedirectVerification(t *testing.T) {
	fixture := newSignedRepository(t)
	moved := fixture.repository + ".owned"
	request := Request{
		Repository: fixture.repository,
		Kind:       Commit,
		ObjectSHA:  fixture.commit,
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}
	_, err := verifyWithOptions(context.Background(), request, fixture.policy(t), verifyOptions{
		commands: execRunner{},
		snapshot: defaultSnapshotOperations(),
		beforeVerify: func(string) error {
			if err := os.Rename(fixture.repository, moved); err != nil {
				return err
			}
			return os.Symlink(t.TempDir(), fixture.repository)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "repository path identity changed") {
		t.Fatalf("repository replacement was not rejected: %v", err)
	}
	if removeErr := os.Remove(fixture.repository); removeErr != nil {
		t.Fatal(removeErr)
	}
	if restoreErr := os.Rename(moved, fixture.repository); restoreErr != nil {
		t.Fatal(restoreErr)
	}
}

type faultFile struct {
	ownedFile
	writeErr error
	syncErr  error
	closeErr error
}

func (file *faultFile) Write(data []byte) (int, error) {
	if file.writeErr != nil {
		return 0, file.writeErr
	}
	return file.ownedFile.Write(data)
}

func (file *faultFile) Sync() error {
	if file.syncErr != nil {
		return file.syncErr
	}
	return file.ownedFile.Sync()
}

func (file *faultFile) Close() error {
	rootErr := file.ownedFile.Close()
	return errors.Join(rootErr, file.closeErr)
}
