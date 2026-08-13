// SPDX-License-Identifier: AGPL-3.0-only

// Package compilematrix cold-compiles every package for supported targets.
package compilematrix

import (
	"context"
	"crypto/sha256"
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
	return run(ctx, options, execRunner{}, os.MkdirTemp, os.RemoveAll, copyDriver)
}

type driverIdentity struct {
	path   string
	size   int64
	mode   os.FileMode
	digest [sha256.Size]byte
	file   os.FileInfo
}

type driverCopier func(string, string) (driverIdentity, error)

func run(
	ctx context.Context,
	options Options,
	commands commandRunner,
	makeTemp func(string, string) (string, error),
	removeAll func(string) error,
	copyOwnedDriver driverCopier,
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
		laneRoot, err := makeTemp("", "agent-runtime-cold-compile-"+target.GOOS+"-"+target.GOARCH+"-")
		if err != nil {
			return errors.Join(rootErr, fmt.Errorf("create %s/%s cold lane: %w", target.GOOS, target.GOARCH, err))
		}
		laneErr := prepareAndRunTarget(ctx, options, commands, repository, laneRoot, target, copyOwnedDriver)
		cleanupErr := removeAll(laneRoot)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("remove owned %s/%s cold lane %q: %w", target.GOOS, target.GOARCH, laneRoot, cleanupErr)
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

func prepareAndRunTarget(ctx context.Context, options Options, commands commandRunner, repository, laneRoot string, target Target, copyOwnedDriver driverCopier) error {
	cacheDirectory := filepath.Join(laneRoot, "cache")
	workDirectory := filepath.Join(laneRoot, "work")
	for _, directory := range []string{cacheDirectory, workDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return fmt.Errorf("create owned %s/%s directory %q: %w", target.GOOS, target.GOARCH, directory, err)
		}
	}
	driver, err := copyOwnedDriver(options.Wrapper, filepath.Join(laneRoot, "driver"))
	if err != nil {
		return fmt.Errorf("own %s/%s test driver: %w", target.GOOS, target.GOARCH, err)
	}
	if err := validateDriver(driver); err != nil {
		return fmt.Errorf("validate %s/%s test driver before compile: %w", target.GOOS, target.GOARCH, err)
	}
	environment := filteredEnvironment(os.Environ(), map[string]string{
		"GOOS": target.GOOS, "GOARCH": target.GOARCH, "GOCACHE": cacheDirectory, "GOTMPDIR": workDirectory,
		"GOTOOLCHAIN": "local", "CGO_ENABLED": "0", strings.SplitN(WrapperEnvironment, "=", 2)[0]: "1",
	})
	arguments := []string{"test", "-exec=" + driver.path, "-run", "^$", "-count=1", "./..."}
	if err := commands.run(ctx, "go", arguments, repository, environment, options.Stdout, options.Stderr); err != nil {
		return fmt.Errorf("cold compile %s/%s: %w", target.GOOS, target.GOARCH, err)
	}
	if err := validateDriver(driver); err != nil {
		return fmt.Errorf("validate %s/%s test driver after compile: %w", target.GOOS, target.GOARCH, err)
	}
	return nil
}

func copyDriver(source, destination string) (identity driverIdentity, rootErr error) {
	sourceFile, err := os.Open(source)
	if err != nil {
		return identity, err
	}
	defer func() { rootErr = errors.Join(rootErr, closeFile("source test driver", sourceFile)) }()
	info, err := sourceFile.Stat()
	if err != nil {
		return identity, err
	}
	if !info.Mode().IsRegular() {
		return identity, errors.New("source test driver is not one regular file")
	}
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return identity, err
	}
	defer func() { rootErr = errors.Join(rootErr, closeFile("owned test driver", destinationFile)) }()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destinationFile, hash), sourceFile)
	if err != nil {
		return identity, err
	}
	if written != info.Size() {
		return identity, errors.New("copy test driver was incomplete")
	}
	if err := destinationFile.Sync(); err != nil {
		return identity, err
	}
	ownedInfo, err := destinationFile.Stat()
	if err != nil {
		return identity, err
	}
	copy(identity.digest[:], hash.Sum(nil))
	identity.path, identity.size, identity.mode, identity.file = destination, written, 0o500, ownedInfo
	return identity, nil
}

func validateDriver(identity driverIdentity) (rootErr error) {
	driver, err := os.Open(identity.path)
	if err != nil {
		return err
	}
	defer func() { rootErr = errors.Join(rootErr, closeFile("validated test driver", driver)) }()
	info, err := driver.Stat()
	if err != nil {
		return err
	}
	if identity.file == nil || !os.SameFile(identity.file, info) || !info.Mode().IsRegular() || info.Mode().Perm() != identity.mode || info.Size() != identity.size {
		return errors.New("owned test driver identity, type, mode, or size changed")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, driver); err != nil {
		return err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	if digest != identity.digest {
		return errors.New("owned test driver content changed")
	}
	return nil
}

func closeFile(resource string, file *os.File) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", resource, err)
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
	for _, name := range []string{"GOOS", "GOARCH", "GOCACHE", "GOTMPDIR", "GOTOOLCHAIN", "CGO_ENABLED", "AGENT_RUNTIME_COLD_COMPILE_WRAPPER"} {
		result = append(result, name+"="+replacements[name])
	}
	return result
}
