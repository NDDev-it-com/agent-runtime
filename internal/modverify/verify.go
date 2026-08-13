// SPDX-License-Identifier: AGPL-3.0-only

// Package modverify verifies that Go module metadata is tidy without modifying it.
package modverify

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const localToolchain = "GOTOOLCHAIN=local"

// Verify runs the authoritative, non-mutating Go module tidy check in root.
// The child process writes directly to stdout and stderr so diagnostic output
// retains its original output boundary.
func Verify(ctx context.Context, root string, stdout, stderr io.Writer) error {
	return verify(ctx, root, stdout, stderr, osCommandRunner{})
}

type invocation struct {
	path   string
	args   []string
	dir    string
	env    []string
	stdout io.Writer
	stderr io.Writer
}

type commandRunner interface {
	run(context.Context, invocation) error
}

type osCommandRunner struct{}

func (osCommandRunner) run(ctx context.Context, call invocation) error {
	command := exec.CommandContext(ctx, call.path, call.args...)
	command.Dir = call.dir
	command.Env = call.env
	command.Stdout = call.stdout
	command.Stderr = call.stderr
	return command.Run()
}

func verify(ctx context.Context, root string, stdout, stderr io.Writer, runner commandRunner) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("verify module tidy: repository root is empty")
	}
	if stdout == nil || stderr == nil {
		return fmt.Errorf("verify module tidy: stdout and stderr are required")
	}
	call := invocation{
		path:   "go",
		args:   []string{"mod", "tidy", "-diff"},
		dir:    root,
		env:    withLocalToolchain(os.Environ()),
		stdout: stdout,
		stderr: stderr,
	}
	if err := runner.run(ctx, call); err != nil {
		return fmt.Errorf("verify module tidy with `GOTOOLCHAIN=local go mod tidy -diff`: %w", err)
	}
	return nil
}

func withLocalToolchain(environment []string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GOTOOLCHAIN=") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, localToolchain)
}
