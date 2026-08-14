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
	// ExecutablePath is the file this run actually executed. A bare command name
	// is resolved through the caller's PATH — the manifest does not decide it —
	// so the choice is recorded here rather than left invisible. Empty when the
	// name could not be resolved, in which case the run fails with the same error
	// it always did.
	ExecutablePath string `json:"executable_path"`
	TimedOut       bool   `json:"timed_out"`
	Cancelled      bool   `json:"cancelled"`
	Accepted       bool   `json:"accepted"`
}

// errTaskTimeout attributes a termination to the manifest timeout. A caller
// deadline and the manifest timeout both surface as context.DeadlineExceeded on
// the derived context, so the cancellation cause is the only thing that can tell
// them apart.
var errTaskTimeout = errors.New("task timeout exceeded")

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

	executable, resolved := resolveExecutable(manifest.Command[0])

	runCtx, cancel := context.WithTimeoutCause(ctx, manifest.Timeout.Duration, errTaskTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, executable, manifest.Command[1:]...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = workdir
	cmd.Env = selectedEnvironment(manifest.Env, lookup)
	cmd.Stdin = bytes.NewReader(contextBytes)
	output := &boundedBuffer{limit: manifest.MaxOutput}
	cmd.Stdout, cmd.Stderr = output, output
	started := time.Now()
	err = cmd.Run()
	cause := context.Cause(runCtx)
	terminated := err != nil && cause != nil
	result := Result{AgentID: manifest.ID, ExecutablePath: resolved, DurationMS: time.Since(started).Milliseconds(), Output: output.String(), Truncated: output.truncated}
	result.TimedOut = terminated && errors.Is(cause, errTaskTimeout)
	result.Cancelled = terminated && !result.TimedOut
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
		return result, fmt.Errorf("Task %q exceeded its %s timeout", manifest.ID, manifest.Timeout.Duration)
	}
	if result.Cancelled {
		return result, fmt.Errorf("Task %q was ended by its caller: %w", manifest.ID, cause)
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

// resolveExecutable reports the file a bare command name resolves to, and the
// argument exec should be given. Resolution happens once, here, so the run can
// record what it chose; exec.Command would otherwise resolve the same name
// invisibly and discard the answer.
//
// A name containing a separator is a path already and is passed through
// untouched. A bare name that resolves is replaced by its absolute path, which
// is what exec would have executed anyway. A bare name that does not resolve is
// passed through so the failure is produced by exec, with the same message as
// before.
func resolveExecutable(name string) (argument, resolved string) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, name
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return name, ""
	}
	return path, path
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
