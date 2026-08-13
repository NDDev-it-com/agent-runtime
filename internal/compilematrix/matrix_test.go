// SPDX-License-Identifier: AGPL-3.0-only

package compilematrix

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSupportedColdCompileMatrixIsExact(t *testing.T) {
	t.Parallel()
	want := []Target{
		{GOOS: "darwin", GOARCH: "amd64"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
	}
	if !reflect.DeepEqual(SupportedTargets, want) {
		t.Fatalf("cold compile matrix drift: got %#v want %#v", SupportedTargets, want)
	}
}

func TestColdCompileUsesFreshCacheAndExactNonExecutingCommand(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{}
	var created, removed []string
	base := t.TempDir()
	makeTemp := func(_, pattern string) (string, error) {
		directory, err := os.MkdirTemp(base, pattern)
		created = append(created, directory)
		return directory, err
	}
	removeAll := func(directory string) error {
		removed = append(removed, directory)
		return nil
	}
	var output bytes.Buffer
	copyDriver := func(_, destination string) (driverIdentity, error) {
		return writeOwnedDriver(destination, "driver")
	}
	err := run(context.Background(), Options{Repository: "/repository", Wrapper: "/wrapper", Stdout: &output, Stderr: io.Discard}, runner, makeTemp, removeAll, copyDriver)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != len(SupportedTargets) || !reflect.DeepEqual(created, removed) {
		t.Fatalf("lane ownership drift: calls=%d created=%v removed=%v", len(runner.calls), created, removed)
	}
	for index, call := range runner.calls {
		target := SupportedTargets[index]
		driver := filepath.Join(created[index], "driver")
		if call.executable != "go" || !reflect.DeepEqual(call.arguments, []string{"test", "-exec=" + driver, "-run", "^$", "-count=1", "./..."}) {
			t.Fatalf("unexpected command: %#v", call)
		}
		for _, expected := range []string{"GOOS=" + target.GOOS, "GOARCH=" + target.GOARCH, "GOCACHE=" + filepath.Join(created[index], "cache"), "GOTMPDIR=" + filepath.Join(created[index], "work"), "GOTOOLCHAIN=local", "CGO_ENABLED=0", WrapperEnvironment} {
			if !containsExact(call.environment, expected) {
				t.Errorf("%s/%s missing %q", target.GOOS, target.GOARCH, expected)
			}
		}
	}
}

func TestColdCompilePreservesRootAndCleanupFailure(t *testing.T) {
	t.Parallel()
	rootFailure := errors.New("compile failed")
	cleanupFailure := errors.New("cache cleanup failed")
	runner := &recordingRunner{failure: rootFailure}
	base := t.TempDir()
	err := run(
		context.Background(),
		Options{Repository: "/repository", Wrapper: "/wrapper", Stdout: io.Discard, Stderr: io.Discard},
		runner,
		func(string, string) (string, error) { return os.MkdirTemp(base, "lane-") },
		func(string) error { return cleanupFailure },
		func(_, destination string) (driverIdentity, error) { return writeOwnedDriver(destination, "driver") },
	)
	if !errors.Is(err, rootFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("root and cleanup errors were not preserved: %v", err)
	}
}

func TestOwnedDriverIdentityFailsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, driverIdentity)
	}{
		{name: "missing", mutate: func(t *testing.T, identity driverIdentity) { t.Helper(); mustRemove(t, identity.path) }},
		{name: "stale contents", mutate: func(t *testing.T, identity driverIdentity) {
			t.Helper()
			mustWriteFile(t, identity.path, "changed", 0o500)
		}},
		{name: "cleaned lane", mutate: func(t *testing.T, identity driverIdentity) { t.Helper(); mustRemove(t, filepath.Dir(identity.path)) }},
		{name: "concurrently replaced", mutate: replaceDriverWithSameBytes},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identity := mustOwnedDriver(t, "driver")
			test.mutate(t, identity)
			if err := validateDriver(identity); err == nil {
				t.Fatal("changed driver identity was accepted")
			}
		})
	}
}

func TestOwnedDriversCannotCrossTargetLanes(t *testing.T) {
	t.Parallel()
	first := mustOwnedDriver(t, "same bytes")
	second := mustOwnedDriver(t, "same bytes")
	first.path = second.path
	if err := validateDriver(first); err == nil {
		t.Fatal("driver from another target lane was accepted")
	}
}

func TestColdCompileDetectsDriverReplacementDuringCommand(t *testing.T) {
	t.Parallel()
	runner := &recordingRunner{hook: func(call recordedCall) error {
		driver := strings.TrimPrefix(call.arguments[1], "-exec=")
		identity, err := os.Stat(driver)
		if err != nil {
			return err
		}
		return replacePathWithSameBytes(driver, identity.Mode().Perm())
	}}
	base := t.TempDir()
	err := run(
		context.Background(),
		Options{Repository: "/repository", Wrapper: "/wrapper", Stdout: io.Discard, Stderr: io.Discard},
		runner,
		func(string, string) (string, error) { return os.MkdirTemp(base, "lane-") },
		os.RemoveAll,
		func(_, destination string) (driverIdentity, error) { return writeOwnedDriver(destination, "driver") },
	)
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("replacement did not fail closed: %v", err)
	}
}

func TestFilteredEnvironmentReplacesTargetAndCacheValues(t *testing.T) {
	t.Parallel()
	replacements := map[string]string{
		"GOOS": "linux", "GOARCH": "arm64", "GOCACHE": "/cold", "GOTMPDIR": "/work", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "AGENT_RUNTIME_COLD_COMPILE_WRAPPER": "1",
	}
	got := filteredEnvironment([]string{"PATH=/bin", "GOOS=attacker", "GOCACHE=warm", "MALFORMED"}, replacements)
	for _, expected := range []string{"PATH=/bin", "GOOS=linux", "GOARCH=arm64", "GOCACHE=/cold", "GOTMPDIR=/work", "GOTOOLCHAIN=local", "CGO_ENABLED=0", WrapperEnvironment} {
		if !containsExact(got, expected) {
			t.Fatalf("missing %q in %v", expected, got)
		}
	}
	if strings.Join(got, "\n") == "" || containsExact(got, "GOOS=attacker") || containsExact(got, "GOCACHE=warm") {
		t.Fatalf("ambient target/cache values survived: %v", got)
	}
}

func TestRepositoryColdCompileSurfacesAreCanonical(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	for name, relative := range map[string]string{
		"CI":           filepath.Join(".github", "workflows", "ci.yml"),
		"release":      filepath.Join(".github", "workflows", "release.yml"),
		"release docs": filepath.Join("docs", "releasing.md"),
	} {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), "go run ./cmd/check-cold-compile") != 1 {
			t.Errorf("%s must invoke the canonical cold compile gate exactly once", name)
		}
	}
}

func TestRepositoryBuildConstraintsFitSupportedMatrix(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		"//go:build darwin":            true,
		"//go:build linux":             true,
		"//go:build darwin || linux":   true,
		"//go:build !darwin && !linux": true,
	}
	err := filepath.Walk(root, func(sourceName string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "vendor") {
			return filepath.SkipDir
		}
		if info.IsDir() || filepath.Ext(sourceName) != ".go" {
			return nil
		}
		data, readErr := os.ReadFile(sourceName)
		if readErr != nil {
			return readErr
		}
		for lineNumber, line := range strings.Split(string(data), "\n") {
			if lineNumber > 10 {
				break
			}
			if strings.HasPrefix(line, "//go:build ") && !allowed[line] {
				t.Errorf("build constraint is outside the supported matrix: %s: %s", sourceName, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type recordedCall struct {
	executable  string
	arguments   []string
	environment []string
}

type recordingRunner struct {
	calls   []recordedCall
	failure error
	hook    func(recordedCall) error
}

func (runner *recordingRunner) run(_ context.Context, executable string, arguments []string, _ string, environment []string, _, _ io.Writer) error {
	call := recordedCall{
		executable: executable, arguments: append([]string(nil), arguments...), environment: append([]string(nil), environment...),
	}
	runner.calls = append(runner.calls, call)
	if runner.hook != nil {
		return runner.hook(call)
	}
	return runner.failure
}

func mustOwnedDriver(t *testing.T, contents string) driverIdentity {
	t.Helper()
	identity, err := writeOwnedDriver(filepath.Join(t.TempDir(), "driver"), contents)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func writeOwnedDriver(destination, contents string) (driverIdentity, error) {
	source, err := os.CreateTemp(filepath.Dir(destination), "source-")
	if err != nil {
		return driverIdentity{}, err
	}
	sourceName := source.Name()
	if _, err := source.WriteString(contents); err != nil {
		_ = source.Close()
		return driverIdentity{}, err
	}
	if err := source.Close(); err != nil {
		return driverIdentity{}, err
	}
	defer os.Remove(sourceName)
	return copyDriver(sourceName, destination)
}

func replaceDriverWithSameBytes(t *testing.T, identity driverIdentity) {
	t.Helper()
	if err := replacePathWithSameBytes(identity.path, identity.mode); err != nil {
		t.Fatal(err)
	}
}

func replacePathWithSameBytes(path string, mode os.FileMode) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	replaced := path + ".replaced"
	if err := os.Rename(path, replaced); err != nil {
		return err
	}
	if err := os.WriteFile(path, contents, mode); err != nil {
		return err
	}
	return os.Remove(replaced)
}

func mustWriteFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
