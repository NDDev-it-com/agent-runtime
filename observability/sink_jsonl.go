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
	// One descriptor for the whole life of the sink. O_APPEND puts every write
	// at the end regardless of where reading left the offset, so the history
	// this sink trusts and the file it extends are the same object. Opening to
	// scan and reopening to append let a rename between the two split them:
	// duplicate-identity and size state would describe the file that was read
	// while the writes went somewhere else.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	openedInfo, openedErr := file.Stat()
	if openedErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, &SinkError{Code: SinkFailure}
	}
	// The name must still resolve to the object now held. A path that resolved
	// elsewhere is refused rather than followed, because a caller configured a
	// destination, not whatever currently answers to it.
	named, namedErr := os.Lstat(path)
	if namedErr != nil || !os.SameFile(named, openedInfo) {
		_ = file.Close()
		return nil, &SinkError{Code: SinkFailure}
	}
	history, err := readJSONLFile(file, maxBytes, nil)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &JSONLSink{name: options.Name, file: file, syncEveryWrite: options.SyncEveryWrite, ids: history.ids, maxFileBytes: maxBytes, size: history.size}, nil
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

// jsonlHistory is the validated state of an existing JSONL file.
type jsonlHistory struct {
	ids       map[string]bool
	sequences map[string]uint64
	size      int64
}

// readJSONL is the single definition of a valid JSONL history: canonical
// single-line envelopes, a newline-terminated final record, unique event
// identity, and a strictly increasing sequence within each subject stream. The
// sink applies it before appending and ReplayJSONL applies it before restoring,
// so one file can never be acceptable to append to yet impossible to replay.
// When collect is non-nil every decoded envelope is appended to it in file order.
func readJSONL(path string, maxBytes int64, collect *[]Envelope) (jsonlHistory, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return jsonlHistory{ids: map[string]bool{}, sequences: map[string]uint64{}}, nil
	}
	if err != nil {
		return jsonlHistory{}, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	defer file.Close()
	return readJSONLFile(file, maxBytes, collect)
}

// readJSONLFile reads the history of an already-open file. Taking the
// descriptor rather than the path is what lets the sink validate and then
// append to one object: reopening by name between the two left the recovered
// identity and size describing the file that was read while every append went
// to whatever the name resolved to afterwards.
func readJSONLFile(file *os.File, maxBytes int64, collect *[]Envelope) (jsonlHistory, error) {
	history := jsonlHistory{ids: map[string]bool{}, sequences: map[string]uint64{}}
	info, err := file.Stat()
	if err != nil {
		return jsonlHistory{}, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return jsonlHistory{}, &SinkError{Code: SinkBackpressure}
	}
	if info.Size() > 0 {
		if _, err := file.Seek(-1, io.SeekEnd); err != nil {
			return jsonlHistory{}, &SinkError{Code: SinkCorruptData}
		}
		last := []byte{0}
		if _, err := io.ReadFull(file, last); err != nil || last[0] != '\n' {
			return jsonlHistory{}, &SinkError{Code: SinkPartialWrite}
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return jsonlHistory{}, &SinkError{Code: SinkCorruptData}
		}
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), MaxEnvelopeBytes+1)
	for scanner.Scan() {
		if len(history.ids) >= MaxReplayEvents {
			return jsonlHistory{}, &SinkError{Code: SinkBackpressure}
		}
		line := append([]byte(nil), scanner.Bytes()...)
		var event Envelope
		if err := event.UnmarshalJSON(line); err != nil {
			if strings.Contains(err.Error(), "unsupported event schema_version") {
				return jsonlHistory{}, &SinkError{Code: SinkUnsupportedVersion}
			}
			return jsonlHistory{}, &SinkError{Code: SinkCorruptData}
		}
		canonical, err := event.CanonicalJSON()
		if err != nil || !bytes.Equal(line, canonical) {
			return jsonlHistory{}, &SinkError{Code: SinkCorruptData}
		}
		key := streamKey(event.Subject())
		if history.ids[event.EventID()] || event.Sequence() <= history.sequences[key] {
			return jsonlHistory{}, &SinkError{Code: SinkCorruptData}
		}
		history.ids[event.EventID()] = true
		history.sequences[key] = event.Sequence()
		if collect != nil {
			*collect = append(*collect, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return jsonlHistory{}, &SinkError{Code: SinkCorruptData}
	}
	history.size = info.Size()
	return history, nil
}

// ReplayJSONL restores every envelope and the next sequence per subject stream.
// A missing file is an explicit failure rather than an empty history, because
// replaying a checkpoint that is not there is a caller error, not a fresh start.
func ReplayJSONL(path string) ([]Envelope, map[string]uint64, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, nil, &SinkError{Code: SinkUnavailable, Retryable: true}
	}
	events := []Envelope{}
	history, err := readJSONL(path, MaximumMaxFileBytes, &events)
	if err != nil {
		return nil, nil, err
	}
	return events, history.sequences, nil
}
