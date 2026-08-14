// SPDX-License-Identifier: AGPL-3.0-only

package signatureverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type ownedFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
	Stat() (os.FileInfo, error)
}

type snapshotOperations struct {
	mkdirTemp func(string, string) (string, error)
	openFile  func(string, int, os.FileMode) (ownedFile, error)
	lstat     func(string) (os.FileInfo, error)
	remove    func(string) error
	syncDir   func(string) error
}

func defaultSnapshotOperations() snapshotOperations {
	return snapshotOperations{
		mkdirTemp: os.MkdirTemp,
		openFile: func(path string, flags int, mode os.FileMode) (ownedFile, error) {
			return os.OpenFile(path, flags, mode)
		},
		lstat:  os.Lstat,
		remove: os.Remove,
		syncDir: func(path string) error {
			directory, err := os.Open(path)
			if err != nil {
				return err
			}
			return errors.Join(directory.Sync(), directory.Close())
		},
	}
}

type trustSnapshot struct {
	directory     string
	path          string
	directoryInfo os.FileInfo
	fileInfo      os.FileInfo
	digest        [sha256.Size]byte
	operations    snapshotOperations
}

func createTrustSnapshot(contents []byte, operations snapshotOperations) (_ *trustSnapshot, rootErr error) {
	directory, err := operations.mkdirTemp("", "agent-runtime-signature-trust-")
	if err != nil {
		return nil, fmt.Errorf("create isolated signature trust directory: %w", err)
	}
	directoryInfo, err := operations.lstat(directory)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("inspect isolated signature trust directory: %w", err), fmt.Errorf("residual trust path requires review at %q", directory))
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("residual unowned trust directory preserved at %q", directory)
	}
	snapshot := &trustSnapshot{directory: directory, path: filepath.Join(directory, "allowed-signers"), directoryInfo: directoryInfo, digest: sha256.Sum256(contents), operations: operations}
	defer func() {
		if rootErr != nil {
			rootErr = errors.Join(rootErr, snapshot.cleanup())
		}
	}()
	file, err := operations.openFile(snapshot.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create isolated signature trust file: %w", err)
	}
	consumed := false
	closeOwned := func() error {
		if consumed {
			return errors.New("isolated signature trust file close attempted twice")
		}
		consumed = true
		return file.Close()
	}
	fileInfo, statErr := file.Stat()
	if statErr == nil {
		snapshot.fileInfo = fileInfo
	}
	if statErr != nil || !fileInfo.Mode().IsRegular() {
		return nil, errors.Join(errors.New("isolated signature trust file has unsafe identity"), closeOwned())
	}
	if err := writeAll(file, contents); err != nil {
		return nil, errors.Join(fmt.Errorf("write isolated signature trust file: %w", err), closeOwned())
	}
	if err := file.Sync(); err != nil {
		return nil, errors.Join(fmt.Errorf("fsync isolated signature trust file: %w", err), closeOwned())
	}
	if err := closeOwned(); err != nil {
		return nil, fmt.Errorf("close isolated signature trust file: %w", err)
	}
	if err := operations.syncDir(directory); err != nil {
		return nil, fmt.Errorf("fsync isolated signature trust directory: %w", err)
	}
	return snapshot, nil
}

func writeAll(writer io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := writer.Write(contents)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(contents) {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func (snapshot *trustSnapshot) revalidate() error {
	directory, err := snapshot.operations.lstat(snapshot.directory)
	if err != nil || !os.SameFile(directory, snapshot.directoryInfo) || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return errors.New("isolated signature trust directory identity changed")
	}
	file, err := snapshot.operations.lstat(snapshot.path)
	if err != nil || !os.SameFile(file, snapshot.fileInfo) || !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 {
		return errors.New("isolated signature trust file identity changed")
	}
	opened, err := os.Open(snapshot.path)
	if err != nil {
		return fmt.Errorf("open isolated signature trust file for revalidation: %w", err)
	}
	openedInfo, statErr := opened.Stat()
	contents, readErr := io.ReadAll(io.LimitReader(opened, maxAllowlistBytes+1))
	closeErr := opened.Close()
	if statErr != nil || !os.SameFile(openedInfo, snapshot.fileInfo) || readErr != nil || closeErr != nil {
		return errors.Join(errors.New("isolated signature trust file changed while revalidating"), statErr, readErr, closeErr)
	}
	digest := sha256.Sum256(contents)
	if !bytes.Equal(digest[:], snapshot.digest[:]) {
		return errors.New("isolated signature trust file contents changed")
	}
	return nil
}

func (snapshot *trustSnapshot) cleanup() error {
	var cleanup []error
	file, err := snapshot.operations.lstat(snapshot.path)
	if errors.Is(err, os.ErrNotExist) {
		// Already absent is safe.
	} else if err != nil {
		cleanup = append(cleanup, fmt.Errorf("inspect trust snapshot cleanup %q: %w", snapshot.path, err))
	} else if snapshot.fileInfo == nil || !os.SameFile(file, snapshot.fileInfo) || !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 {
		cleanup = append(cleanup, fmt.Errorf("residual unowned trust snapshot preserved at %q", snapshot.path))
	} else if err := snapshot.operations.remove(snapshot.path); err != nil {
		cleanup = append(cleanup, fmt.Errorf("remove owned trust snapshot %q: %w", snapshot.path, err))
	} else if err := snapshot.operations.syncDir(snapshot.directory); err != nil {
		cleanup = append(cleanup, fmt.Errorf("fsync trust directory after snapshot removal %q: %w", snapshot.directory, err))
	}
	directory, err := snapshot.operations.lstat(snapshot.directory)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(cleanup...)
	}
	if err != nil {
		cleanup = append(cleanup, fmt.Errorf("inspect trust directory cleanup %q: %w", snapshot.directory, err))
	} else if !os.SameFile(directory, snapshot.directoryInfo) || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		cleanup = append(cleanup, fmt.Errorf("residual unowned trust directory preserved at %q", snapshot.directory))
	} else if err := snapshot.operations.remove(snapshot.directory); err != nil {
		cleanup = append(cleanup, fmt.Errorf("remove owned trust directory %q: %w", snapshot.directory, err))
	}
	return errors.Join(cleanup...)
}

type identityBoundRunner struct {
	delegate   runner
	repository repositoryIdentity
}

func (bound identityBoundRunner) run(ctx context.Context, args []string, directory string, environment []string) ([]byte, []byte, error) {
	if err := bound.repository.revalidate(); err != nil {
		return nil, nil, err
	}
	explicitArgs := append([]string{
		"--no-replace-objects",
		"--git-dir=" + bound.repository.gitDirectory,
		"--work-tree=" + bound.repository.root,
	}, args...)
	stdout, stderr, rootErr := bound.delegate.run(ctx, explicitArgs, directory, environment)
	return stdout, stderr, errors.Join(rootErr, bound.repository.revalidate())
}
