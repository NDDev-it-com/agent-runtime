// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"sync"
)

type MemorySink struct {
	mu       sync.Mutex
	name     string
	capacity int
	events   []Envelope
	ids      map[string]bool
	closed   bool
}

func NewMemorySink(name string, capacity int) (*MemorySink, error) {
	if !safeID(name) || capacity < 1 {
		return nil, &SinkError{Code: SinkFailure}
	}
	return &MemorySink{name: name, capacity: capacity, ids: map[string]bool{}}, nil
}
func (s *MemorySink) Name() string { return s.name }
func (s *MemorySink) Write(ctx context.Context, event Envelope) (WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return WriteResult{}, &SinkError{Code: SinkContext}
	}
	if s.closed {
		return WriteResult{}, &SinkError{Code: SinkClosed}
	}
	if err := event.Validate(); err != nil {
		return WriteResult{}, &SinkError{Code: SinkCorruptData}
	}
	if s.ids[event.EventID()] {
		return WriteResult{Duplicate: true}, nil
	}
	if len(s.events) >= s.capacity {
		return WriteResult{}, &SinkError{Code: SinkBackpressure, Retryable: true}
	}
	s.events = append(s.events, event)
	s.ids[event.EventID()] = true
	return WriteResult{}, nil
}
func (s *MemorySink) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &SinkError{Code: SinkContext}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return &SinkError{Code: SinkClosed}
	}
	return nil
}
func (s *MemorySink) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &SinkError{Code: SinkContext}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
func (s *MemorySink) Snapshot() []Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Envelope(nil), s.events...)
}
