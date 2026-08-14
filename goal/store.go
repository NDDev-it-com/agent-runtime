// SPDX-License-Identifier: AGPL-3.0-only

package goal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type Store struct{ Path string }

func (s Store) Create(j Journal) error {
	if err := j.Validate(); err != nil {
		return err
	}
	if !j.IsGenesis() {
		return invalid("journal must be created in its genesis state")
	}
	if s.Path == "" {
		return invalid("journal path is required")
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer s.unlock(lock)
	if _, err := os.Lstat(s.Path); err == nil {
		return &Error{Code: CodeConflict, Message: "journal already exists"}
	} else if !os.IsNotExist(err) {
		return ioError("inspect journal", err)
	}
	return s.write(j)
}

func (s Store) Load() (Journal, error) {
	file, err := os.Open(filepath.Clean(s.Path))
	if err != nil {
		return Journal{}, ioError("open journal", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var j Journal
	if err := decoder.Decode(&j); err != nil {
		return Journal{}, ioError("decode journal", err)
	}
	if err := ensureJournalEOF(decoder); err != nil {
		return Journal{}, err
	}
	if err := j.Validate(); err != nil {
		return Journal{}, err
	}
	return j, nil
}

func (s Store) Update(expectedRevision uint64, mutate func(*Journal) error) (Journal, error) {
	lock, err := s.lock()
	if err != nil {
		return Journal{}, err
	}
	defer s.unlock(lock)
	j, err := s.Load()
	if err != nil {
		return Journal{}, err
	}
	if j.Revision != expectedRevision {
		return Journal{}, &Error{Code: CodeConflict, Message: fmt.Sprintf("revision conflict: expected %d, found %d", expectedRevision, j.Revision)}
	}
	before := j.Clone()
	if err := mutate(&j); err != nil {
		return Journal{}, err
	}
	if err := j.Validate(); err != nil {
		return Journal{}, err
	}
	if err := j.ValidateTransitionFrom(before); err != nil {
		return Journal{}, err
	}
	if err := s.write(j); err != nil {
		return Journal{}, err
	}
	return j, nil
}

func (s Store) write(j Journal) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ioError("create journal directory", err)
	}
	tmp, err := os.CreateTemp(dir, ".goal-journal-*")
	if err != nil {
		return ioError("create temporary journal", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return ioError("set journal permissions", err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(j); err != nil {
		tmp.Close()
		return ioError("encode journal", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ioError("sync journal", err)
	}
	if err := tmp.Close(); err != nil {
		return ioError("close journal", err)
	}
	if err := os.Rename(tmpPath, s.Path); err != nil {
		return ioError("replace journal", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return ioError("open journal directory", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ioError("sync journal directory", err)
	}
	return nil
}

func (s Store) lock() (*os.File, error) {
	if s.Path == "" {
		return nil, invalid("journal path is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return nil, ioError("create journal directory", err)
	}
	file, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, ioError("open journal lock", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, ioError("lock journal", err)
	}
	return file, nil
}
func (s Store) unlock(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
func ioError(action string, err error) error {
	return &Error{Code: CodeJournalIO, Message: action, Cause: err}
}
func ensureJournalEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if err == io.EOF {
			return nil
		}
		return ioError("decode trailing journal data", err)
	}
	return invalid("journal contains multiple JSON values")
}
