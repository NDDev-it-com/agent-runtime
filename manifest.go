// SPDX-License-Identifier: AGPL-3.0-only

// Package agentruntime validates and runs small, vendor-neutral Task manifests.
//
// The package treats Task manifests and their commands as trusted input. It
// confines selected files to a workspace, but it is not an OS sandbox.
package agentruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	TaskSchemaVersion      = "v1alpha1"
	DefaultTimeout         = 5 * time.Minute
	DefaultMaxOutputBytes  = int64(1 << 20)
	DefaultMaxContextBytes = int64(1 << 20)
)

var (
	idPattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type TaskManifest struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Description   string         `json:"description,omitempty"`
	Instructions  []string       `json:"instructions"`
	Command       []string       `json:"command"`
	Acceptance    TaskAcceptance `json:"acceptance"`
	Workdir       string         `json:"workdir,omitempty"`
	Env           []string       `json:"env,omitempty"`
	Timeout       Duration       `json:"timeout,omitempty"`
	MaxOutput     int64          `json:"max_output_bytes,omitempty"`
	MaxContext    int64          `json:"max_context_bytes,omitempty"`
}

type TaskAcceptance struct {
	ExitCodes      []int    `json:"exit_codes"`
	OutputContains []string `json:"output_contains,omitempty"`
}

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func DecodeTaskManifest(r io.Reader) (TaskManifest, error) {
	const maxManifestBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return TaskManifest{}, fmt.Errorf("read task manifest: %w", err)
	}
	if len(data) > maxManifestBytes {
		return TaskManifest{}, fmt.Errorf("task manifest exceeds %d bytes", maxManifestBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest TaskManifest
	if err := decoder.Decode(&manifest); err != nil {
		return TaskManifest{}, fmt.Errorf("decode task manifest: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return TaskManifest{}, err
	}
	stated, err := statedBounds(data)
	if err != nil {
		return TaskManifest{}, err
	}
	manifest.applyDefaults(stated)
	if err := manifest.Validate(); err != nil {
		return TaskManifest{}, err
	}
	return manifest, nil
}

// statedBounds reports which bounds the document actually wrote. Go cannot tell
// an omitted field from one set to its zero value, but JSON can, and the
// difference matters: `"timeout": "0s"` asked for no execution time at all and
// used to be granted the five-minute default instead, which is the widest
// possible reading of the narrowest possible request. The same held for a zero
// output or context budget, each of which quietly became a mebibyte. A negative
// value was already refused, so zero was the one way to fail open.
func statedBounds(document []byte) (statedFields, error) {
	var stated struct {
		Timeout    *Duration `json:"timeout"`
		MaxOutput  *int64    `json:"max_output_bytes"`
		MaxContext *int64    `json:"max_context_bytes"`
	}
	// Unknown fields are already refused by the decode above; this pass reads
	// only presence, so it must not reject the rest of the document.
	if err := json.Unmarshal(document, &stated); err != nil {
		return statedFields{}, fmt.Errorf("decode task manifest bounds: %w", err)
	}
	return statedFields{
		timeout:    stated.Timeout != nil,
		maxOutput:  stated.MaxOutput != nil,
		maxContext: stated.MaxContext != nil,
	}, nil
}

// statedFields records which bounds a document wrote, so a default is only ever
// substituted for silence.
type statedFields struct{ timeout, maxOutput, maxContext bool }

// noneStated is the reading for a Go value, whose zero fields are silence
// rather than a stated bound.
var noneStated = statedFields{}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("decode manifest: multiple JSON values")
		}
		return fmt.Errorf("decode manifest: %w", err)
	}
	return nil
}

// applyDefaults fills the bounds the caller left silent. A bound the caller
// stated is never rewritten, so an explicit zero survives to Validate and is
// refused there rather than being widened into a default.
func (m *TaskManifest) applyDefaults(stated statedFields) {
	if m.Workdir == "" {
		m.Workdir = "."
	}
	if !stated.timeout && m.Timeout.Duration == 0 {
		m.Timeout.Duration = DefaultTimeout
	}
	if !stated.maxOutput && m.MaxOutput == 0 {
		m.MaxOutput = DefaultMaxOutputBytes
	}
	if !stated.maxContext && m.MaxContext == 0 {
		m.MaxContext = DefaultMaxContextBytes
	}
}

// Prepare returns a validated copy with runtime defaults applied to the bounds
// left at their zero value. It is useful to observers that must distinguish
// validation from execution without mutating the caller's manifest.
//
// A Go struct literal carries no record of which fields it omitted, so every
// zero here is read as silence. A document that states a bound explicitly is
// held to it by DecodeTaskManifest instead.
func (m TaskManifest) Prepare() (TaskManifest, error) {
	m.applyDefaults(noneStated)
	if err := m.Validate(); err != nil {
		return TaskManifest{}, err
	}
	return m, nil
}

func (m TaskManifest) Validate() error {
	var problems []string
	if m.SchemaVersion != TaskSchemaVersion {
		problems = append(problems, "schema_version must be "+TaskSchemaVersion)
	}
	if !idPattern.MatchString(m.ID) {
		problems = append(problems, "id must match "+idPattern.String())
	}
	if len(m.Instructions) == 0 {
		problems = append(problems, "instructions must contain at least one path")
	}
	if len(m.Command) == 0 || strings.TrimSpace(first(m.Command)) == "" {
		problems = append(problems, "command must contain an executable")
	}
	if len(m.Acceptance.ExitCodes) == 0 {
		problems = append(problems, "acceptance.exit_codes must contain at least one exit code")
	}
	seenExit := map[int]bool{}
	for _, code := range m.Acceptance.ExitCodes {
		if code < 0 || code > 255 {
			problems = append(problems, "acceptance exit codes must be between 0 and 255")
		}
		if seenExit[code] {
			problems = append(problems, "duplicate acceptance exit code")
		}
		seenExit[code] = true
	}
	for _, text := range m.Acceptance.OutputContains {
		if text == "" {
			problems = append(problems, "acceptance output_contains values must not be empty")
		}
	}
	if m.Timeout.Duration <= 0 || m.Timeout.Duration > 24*time.Hour {
		problems = append(problems, "timeout must be greater than zero and at most 24h")
	}
	if m.MaxOutput < 1 || m.MaxOutput > 64<<20 {
		problems = append(problems, "max_output_bytes must be between 1 and 67108864")
	}
	if m.MaxContext < 1 || m.MaxContext > 16<<20 {
		problems = append(problems, "max_context_bytes must be between 1 and 16777216")
	}
	seenPaths := map[string]bool{}
	for _, path := range m.Instructions {
		if strings.TrimSpace(path) == "" {
			problems = append(problems, "instruction paths must not be empty")
		}
		if seenPaths[path] {
			problems = append(problems, "duplicate instruction path: "+path)
		}
		seenPaths[path] = true
	}
	seenEnv := map[string]bool{}
	for _, name := range m.Env {
		if !envPattern.MatchString(name) {
			problems = append(problems, "invalid environment variable name: "+name)
		}
		if seenEnv[name] {
			problems = append(problems, "duplicate environment variable: "+name)
		}
		seenEnv[name] = true
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
