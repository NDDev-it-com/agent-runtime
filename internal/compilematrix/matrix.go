// SPDX-License-Identifier: AGPL-3.0-only

// Package compilematrix cold-compiles every package for supported targets.
package compilematrix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const WrapperEnvironment = "AGENT_RUNTIME_COLD_COMPILE_WRAPPER=1"

type Target struct {
	GOOS   string
	GOARCH string
}

var SupportedTargets = []Target{
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
}

type Options struct {
	Repository string
	Wrapper    string
	Stdout     io.Writer
	Stderr     io.Writer
}

type commandRunner interface {
	run(context.Context, string, []string, string, []string, io.Writer, io.Writer) error
}

type execRunner struct{}

func (execRunner) run(ctx context.Context, executable string, arguments []string, directory string, environment []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func Run(ctx context.Context, options Options) error {
	return run(ctx, options, execRunner{}, os.MkdirTemp, os.RemoveAll)
}

func run(
	ctx context.Context,
	options Options,
	commands commandRunner,
	makeTemp func(string, string) (string, error),
	removeAll func(string) error,
) (rootErr error) {
	if strings.TrimSpace(options.Repository) == "" || strings.TrimSpace(options.Wrapper) == "" {
		return errors.New("cold compile requires repository and wrapper paths")
	}
	if options.Stdout == nil || options.Stderr == nil {
		return errors.New("cold compile output writers are required")
	}
	repository, err := filepath.Abs(options.Repository)
	if err != nil {
		return fmt.Errorf("resolve cold compile repository: %w", err)
	}
	for _, target := range SupportedTargets {
		cacheDirectory, err := makeTemp("", "agent-runtime-cold-compile-"+target.GOOS+"-"+target.GOARCH+"-")
		if err != nil {
			return errors.Join(rootErr, fmt.Errorf("create %s/%s cold cache: %w", target.GOOS, target.GOARCH, err))
		}
		laneErr := runTarget(ctx, options, commands, repository, cacheDirectory, target)
		cleanupErr := removeAll(cacheDirectory)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("remove owned %s/%s cold cache %q: %w", target.GOOS, target.GOARCH, cacheDirectory, cleanupErr)
		}
		if err := errors.Join(laneErr, cleanupErr); err != nil {
			return errors.Join(rootErr, err)
		}
		if _, err := fmt.Fprintf(options.Stdout, "cold compile valid: %s/%s\n", target.GOOS, target.GOARCH); err != nil {
			return fmt.Errorf("write cold compile summary: %w", err)
		}
	}
	return nil
}

func runTarget(ctx context.Context, options Options, commands commandRunner, repository, cacheDirectory string, target Target) error {
	environment := filteredEnvironment(os.Environ(), map[string]string{
		"GOOS": target.GOOS, "GOARCH": target.GOARCH, "GOCACHE": cacheDirectory,
		"GOTOOLCHAIN": "local", "CGO_ENABLED": "0", strings.SplitN(WrapperEnvironment, "=", 2)[0]: "1",
	})
	arguments := []string{"test", "-exec=" + options.Wrapper, "-run", "^$", "-count=1", "./..."}
	if err := commands.run(ctx, "go", arguments, repository, environment, options.Stdout, options.Stderr); err != nil {
		return fmt.Errorf("cold compile %s/%s: %w", target.GOOS, target.GOARCH, err)
	}
	return nil
}

func filteredEnvironment(current []string, replacements map[string]string) []string {
	result := make([]string, 0, len(current)+len(replacements))
	for _, entry := range current {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, replaced := replacements[name]; replaced {
			continue
		}
		result = append(result, entry)
	}
	for _, name := range []string{"GOOS", "GOARCH", "GOCACHE", "GOTOOLCHAIN", "CGO_ENABLED", "AGENT_RUNTIME_COLD_COMPILE_WRAPPER"} {
		result = append(result, name+"="+replacements[name])
	}
	return result
}
