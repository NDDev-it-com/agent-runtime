// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	AgentID    string `json:"agent_id"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
	TimedOut   bool   `json:"timed_out"`
	Accepted   bool   `json:"accepted"`
}

type Runner struct {
	Workspace Workspace
	LookupEnv func(string) (string, bool)
}

func (r Runner) Run(ctx context.Context, manifest TaskManifest) (Result, error) {
	prepared, err := manifest.Prepare()
	if err != nil {
		return Result{}, err
	}
	manifest = prepared
	if r.Workspace.root == "" {
		return Result{}, errors.New("workspace is required")
	}
	contextBytes, err := r.Workspace.BuildContext(manifest.Instructions, manifest.MaxContext)
	if err != nil {
		return Result{}, fmt.Errorf("build context: %w", err)
	}
	workdir, err := r.Workspace.ResolveDirectory(manifest.Workdir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve workdir: %w", err)
	}
	lookup := r.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}

	runCtx, cancel := context.WithTimeout(ctx, manifest.Timeout.Duration)
	defer cancel()
	cmd := exec.CommandContext(runCtx, manifest.Command[0], manifest.Command[1:]...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = workdir
	cmd.Env = selectedEnvironment(manifest.Env, lookup)
	cmd.Stdin = bytes.NewReader(contextBytes)
	output := &boundedBuffer{limit: manifest.MaxOutput}
	cmd.Stdout, cmd.Stderr = output, output
	started := time.Now()
	err = cmd.Run()
	result := Result{AgentID: manifest.ID, ExitCode: 0, DurationMS: time.Since(started).Milliseconds(), Output: output.String(), Truncated: output.truncated, TimedOut: errors.Is(runCtx.Err(), context.DeadlineExceeded)}
	if err == nil {
		result.Accepted = accepted(manifest.Acceptance, result)
		if result.Accepted {
			return result, nil
		}
		return result, fmt.Errorf("Task %q did not meet acceptance", manifest.ID)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else {
		result.ExitCode = -1
	}
	if result.TimedOut {
		return result, fmt.Errorf("agent %q timed out after %s", manifest.ID, manifest.Timeout.Duration)
	}
	result.Accepted = accepted(manifest.Acceptance, result)
	if result.Accepted {
		return result, nil
	}
	return result, fmt.Errorf("Task %q did not meet acceptance (exit code %d): %w", manifest.ID, result.ExitCode, err)
}

func accepted(criteria TaskAcceptance, result Result) bool {
	exitOK := false
	for _, code := range criteria.ExitCodes {
		if result.ExitCode == code {
			exitOK = true
			break
		}
	}
	if !exitOK {
		return false
	}
	for _, text := range criteria.OutputContains {
		if !strings.Contains(result.Output, text) {
			return false
		}
	}
	return true
}

func selectedEnvironment(names []string, lookup func(string) (string, bool)) []string {
	env := make([]string, 0, len(names))
	for _, name := range names {
		if value, ok := lookup(name); ok {
			env = append(env, name+"="+value)
		}
	}
	sort.Strings(env)
	return env
}

type boundedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - int64(b.buf.Len())
	if remaining > 0 {
		write := int64(len(p))
		if write > remaining {
			write = remaining
		}
		_, _ = b.buf.Write(p[:write])
	}
	if int64(len(p)) > remaining {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.ToValidUTF8(b.buf.String(), "�")
}
