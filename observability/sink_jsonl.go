// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
)

type JSONLOptions struct {
	Name           string
	SyncEveryWrite bool
	MaxFileBytes   int64
}
type syncWriteCloser interface {
	io.Writer
	io.Closer
	Sync() error
}
type JSONLSink struct {
	mu             sync.Mutex
	name           string
	file           syncWriteCloser
	syncEveryWrite bool
	ids            map[string]bool
	closed         bool
	poisoned       bool
	maxFileBytes   int64
	size           int64
}

func OpenJSONLSink(path string, options JSONLOptions) (*JSONLSink, error) {
	if path == "" || !safeID(options.Name) {
		return nil, &SinkError{Code: SinkFailure}
	}
	maxBytes := options.MaxFileBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxFileBytes
	}
	if maxBytes < MaxEnvelopeBytes || maxBytes > MaximumMaxFileBytes {
		return nil, &SinkError{Code: SinkFailure}
	}
	ids, size, err := scanJSONL(path, maxBytes)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	info, statErr := os.Lstat(path)
	openedInfo, openedErr := file.Stat()
	if statErr != nil || openedErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, &SinkError{Code: SinkFailure}
	}
	return &JSONLSink{name: options.Name, file: file, syncEveryWrite: options.SyncEveryWrite, ids: ids, maxFileBytes: maxBytes, size: size}, nil
}
func newJSONLSinkWriter(name string, file syncWriteCloser, syncEveryWrite bool) (*JSONLSink, error) {
	if !safeID(name) || file == nil {
		return nil, &SinkError{Code: SinkFailure}
	}
	return &JSONLSink{name: name, file: file, syncEveryWrite: syncEveryWrite, ids: map[string]bool{}, maxFileBytes: DefaultMaxFileBytes}, nil
}
func (s *JSONLSink) Name() string { return s.name }
func (s *JSONLSink) Write(ctx context.Context, event Envelope) (WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return WriteResult{}, &SinkError{Code: SinkContext}
	}
	if s.closed {
		return WriteResult{}, &SinkError{Code: SinkClosed}
	}
	if s.poisoned {
		return WriteResult{}, &SinkError{Code: SinkPartialWrite}
	}
	if s.ids[event.EventID()] {
		return WriteResult{Duplicate: true}, nil
	}
	data, err := event.CanonicalJSON()
	if err != nil {
		return WriteResult{}, &SinkError{Code: SinkCorruptData}
	}
	data = append(data, '\n')
	if s.size+int64(len(data)) > s.maxFileBytes {
		return WriteResult{}, &SinkError{Code: SinkBackpressure}
	}
	written, writeErr := s.file.Write(data)
	if writeErr != nil || written != len(data) {
		s.poisoned = true
		return WriteResult{}, &SinkError{Code: SinkPartialWrite}
	}
	if s.syncEveryWrite {
		if err := s.file.Sync(); err != nil {
			s.poisoned = true
			return WriteResult{}, &SinkError{Code: SinkPartialWrite}
		}
	}
	s.ids[event.EventID()] = true
	s.size += int64(len(data))
	return WriteResult{}, nil
}
func (s *JSONLSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return &SinkError{Code: SinkContext}
	}
	if s.closed {
		return &SinkError{Code: SinkClosed}
	}
	if s.poisoned {
		return &SinkError{Code: SinkPartialWrite}
	}
	if err := s.file.Sync(); err != nil {
		s.poisoned = true
		return &SinkError{Code: SinkPartialWrite}
	}
	return nil
}
func (s *JSONLSink) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return &SinkError{Code: SinkContext}
	}
	if !s.poisoned {
		if err := s.file.Sync(); err != nil {
			s.poisoned = true
			_ = s.file.Close()
			s.closed = true
			return &SinkError{Code: SinkPartialWrite}
		}
	}
	if err := s.file.Close(); err != nil {
		s.closed = true
		return &SinkError{Code: SinkFailure}
	}
	s.closed = true
	return nil
}

func scanJSONL(path string, maxBytes int64) (map[string]bool, int64, error) {
	ids := map[string]bool{}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return ids, 0, nil
	}
	if err != nil {
		return nil, 0, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, 0, &SinkError{Code: SinkBackpressure}
	}
	if info.Size() > 0 {
		if _, err := file.Seek(-1, io.SeekEnd); err != nil {
			return nil, 0, &SinkError{Code: SinkCorruptData}
		}
		last := []byte{0}
		if _, err := io.ReadFull(file, last); err != nil || last[0] != '\n' {
			return nil, 0, &SinkError{Code: SinkPartialWrite}
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, 0, &SinkError{Code: SinkCorruptData}
		}
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), MaxEnvelopeBytes+1)
	for scanner.Scan() {
		if len(ids) >= MaxReplayEvents {
			return nil, 0, &SinkError{Code: SinkBackpressure}
		}
		line := append([]byte(nil), scanner.Bytes()...)
		var event Envelope
		if err := event.UnmarshalJSON(line); err != nil {
			if strings.Contains(err.Error(), "unsupported event schema_version") {
				return nil, 0, &SinkError{Code: SinkUnsupportedVersion}
			}
			return nil, 0, &SinkError{Code: SinkCorruptData}
		}
		canonical, err := event.CanonicalJSON()
		if err != nil || !bytes.Equal(line, canonical) {
			return nil, 0, &SinkError{Code: SinkCorruptData}
		}
		if ids[event.EventID()] {
			return nil, 0, &SinkError{Code: SinkCorruptData}
		}
		ids[event.EventID()] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, &SinkError{Code: SinkCorruptData}
	}
	return ids, info.Size(), nil
}

func ReplayJSONL(path string) ([]Envelope, map[string]uint64, error) {
	if _, _, err := scanJSONL(path, MaximumMaxFileBytes); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), MaxEnvelopeBytes+1)
	events := []Envelope{}
	sequences := map[string]uint64{}
	for scanner.Scan() {
		if len(events) >= MaxReplayEvents {
			return nil, nil, &SinkError{Code: SinkBackpressure}
		}
		var event Envelope
		if err := event.UnmarshalJSON(scanner.Bytes()); err != nil {
			return nil, nil, &SinkError{Code: SinkCorruptData}
		}
		key := streamKey(event.Subject())
		if event.Sequence() <= sequences[key] {
			return nil, nil, &SinkError{Code: SinkCorruptData}
		}
		sequences[key] = event.Sequence()
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, &SinkError{Code: SinkCorruptData}
	}
	return events, sequences, nil
}
