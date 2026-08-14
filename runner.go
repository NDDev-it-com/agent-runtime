// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
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

// terminationGrace bounds how long a terminated run may hold its output pipes
// open before the runtime stops waiting. It is added to the manifest timeout,
// so a Task's wall-clock ceiling is the timeout plus this grace, not the
// timeout alone.
const terminationGrace = 2 * time.Second

type Runner struct {
	Workspace Workspace
	// LookupEnv is the single source of environment values this Runner reads.
	// It supplies the values named by the manifest allowlist and the PATH the
	// command name is resolved against, so an embedder that sets it decides
	// both what the child sees and which executable runs. Defaults to
	// os.LookupEnv.
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

	executable, err := resolveExecutable(manifest.Command[0], lookup)
	if err != nil {
		return Result{AgentID: manifest.ID, ExitCode: -1}, fmt.Errorf("resolve command for Task %q: %w", manifest.ID, err)
	}

	runCtx, cancel := context.WithTimeoutCause(ctx, manifest.Timeout.Duration, errTaskTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, executable, manifest.Command[1:]...)
	cmd.WaitDelay = terminationGrace
	cmd.Dir = workdir
	cmd.Env = selectedEnvironment(manifest.Env, lookup)
	cmd.Stdin = bytes.NewReader(contextBytes)
	output := &boundedBuffer{limit: manifest.MaxOutput}
	cmd.Stdout, cmd.Stderr = output, output
	ownProcessGroup(cmd)
	// Recording that termination was initiated, rather than inferring it from
	// the context afterwards, is what tells an ordinary failure apart from a
	// cancelled run. Reading context.Cause after Run returned attributed a
	// process that had already exited non-zero to the caller whenever the
	// cancellation landed in between: measured at five runs in four hundred.
	var terminatedByRuntime atomic.Bool
	cmd.Cancel = func() error {
		terminatedByRuntime.Store(true)
		return terminateProcessGroup(cmd)
	}
	started := time.Now()
	err = cmd.Run()
	cause := context.Cause(runCtx)
	// A process that returned its own exit status ran to completion, whatever
	// the context did meanwhile. Only a process the runtime actually terminated
	// carries no status of its own, and that is the one to attribute to a
	// timeout or a caller. Both halves are needed: the context alone cannot
	// tell the two apart, and the cancel hook alone fires even when the child
	// had already exited, because it races the tail of Wait.
	terminated := err != nil && terminatedByRuntime.Load() && !exitedOnItsOwn(err)
	result := Result{AgentID: manifest.ID, ExecutablePath: executable, DurationMS: time.Since(started).Milliseconds(), Output: output.String(), Truncated: output.truncated}
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

// exitedOnItsOwn reports whether the child returned an exit status rather than
// being terminated. A killed process is reported by the operating system as
// signalled and carries no status of its own, so this is the discrimination the
// context cannot make.
func exitedOnItsOwn(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ProcessState != nil && exitErr.ProcessState.Exited()
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

// resolveExecutable reports the file a command name refers to, resolved against
// the PATH this Runner reads through LookupEnv rather than the one exec.Command
// would read from the process. Resolution and the child environment then come
// from one source, so an embedder that supplies LookupEnv gets a deterministic
// answer instead of one the host decides.
//
// A name containing a separator is a path already and is returned untouched.
// Empty and relative PATH entries are skipped: both resolve against the
// runtime's working directory, which is not the Task's workdir and is exactly
// the ambient state this resolution exists to remove.
func resolveExecutable(name string, lookup func(string) (string, bool)) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, nil
	}
	search, _ := lookup("PATH")
	for _, directory := range filepath.SplitList(search) {
		if directory == "" || !filepath.IsAbs(directory) {
			continue
		}
		candidate := filepath.Join(directory, name)
		info, statErr := os.Stat(candidate)
		if statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%q: executable file not found in $PATH", name)
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

// String returns the captured output with invalid UTF-8 repaired, bounded by
// the declared limit.
//
// The repair is why the bound has to be reapplied. Each isolated invalid byte
// becomes a three-byte replacement rune, so output capped at the limit while
// raw could exceed it once repaired: a twelve-byte budget returned twenty-four
// bytes, and that string went on to the Result, its JSON encoding and every
// downstream event. The limit is a promise about what a caller receives, so it
// is enforced on what a caller receives, cut on a rune boundary.
func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	repaired := strings.ToValidUTF8(b.buf.String(), "�")
	if int64(len(repaired)) <= b.limit {
		return repaired
	}
	cut := b.limit
	for cut > 0 && !utf8.RuneStart(repaired[cut]) {
		cut--
	}
	b.truncated = true
	return repaired[:cut]
}
