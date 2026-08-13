// SPDX-License-Identifier: AGPL-3.0-only

package compilematrix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		mutate func(*testing.T, *driverFixture)
	}{
		{name: "missing", mutate: func(t *testing.T, fixture *driverFixture) { t.Helper(); fixture.removeDriver(t) }},
		{name: "stale contents", mutate: func(t *testing.T, fixture *driverFixture) {
			t.Helper()
			if err := fixture.rewriteAndReseal("stale!"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "cleaned lane", mutate: func(t *testing.T, fixture *driverFixture) { t.Helper(); fixture.removeLane(t) }},
		{name: "concurrently replaced", mutate: func(t *testing.T, fixture *driverFixture) { t.Helper(); fixture.replaceWithSameBytes(t) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDriverFixture(t, "driver")
			test.mutate(t, fixture)
			if err := validateDriver(fixture.identity); err == nil {
				t.Fatal("changed driver identity was accepted")
			}
		})
	}
}

func TestOwnedDriversCannotCrossTargetLanes(t *testing.T) {
	t.Parallel()
	firstFixture := newDriverFixture(t, "same bytes")
	secondFixture := newDriverFixture(t, "same bytes")
	first := firstFixture.identity
	second := secondFixture.identity
	first.path = second.path
	if err := validateDriver(first); err == nil {
		t.Fatal("driver from another target lane was accepted")
	}
}

func TestDriverFixturesAreIndependentAndCleanupOwnedState(t *testing.T) {
	t.Parallel()
	first := newDriverFixture(t, "driver")
	second := newDriverFixture(t, "driver")
	if err := first.rewriteAndReseal("stale!"); err != nil {
		t.Fatal(err)
	}
	if err := validateDriver(second.identity); err != nil {
		t.Fatalf("one fixture mutated another: %v", err)
	}
	root := first.root
	first.cleanup(t)
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture-owned state leaked after cleanup: %v", err)
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

type driverFixture struct {
	root     string
	identity driverIdentity
	cleaned  bool
}

func newDriverFixture(t *testing.T, contents string) *driverFixture {
	t.Helper()
	root := t.TempDir()
	identity, err := writeOwnedDriver(filepath.Join(root, "driver"), contents)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &driverFixture{root: root, identity: identity}
	t.Cleanup(func() { fixture.cleanup(t) })
	return fixture
}

func (fixture *driverFixture) rewriteAndReseal(contents string) (rootErr error) {
	if len(contents) != int(fixture.identity.size) {
		return fmt.Errorf("stale fixture must preserve size: got %d want %d", len(contents), fixture.identity.size)
	}
	if err := fixture.validateOwnedIdentity(); err != nil {
		return err
	}
	if err := os.Chmod(fixture.identity.path, 0o700); err != nil {
		return err
	}
	defer func() {
		rootErr = errors.Join(rootErr, os.Chmod(fixture.identity.path, fixture.identity.mode))
		rootErr = errors.Join(rootErr, fixture.validateOwnedIdentity())
	}()
	file, err := os.OpenFile(fixture.identity.path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, contents); err != nil {
		rootErr = errors.Join(rootErr, err)
	}
	if err := file.Sync(); err != nil {
		rootErr = errors.Join(rootErr, err)
	}
	if err := file.Close(); err != nil {
		rootErr = errors.Join(rootErr, err)
	}
	return rootErr
}

func (fixture *driverFixture) replaceWithSameBytes(t *testing.T) {
	t.Helper()
	if err := replacePathWithSameBytes(fixture.identity.path, fixture.identity.mode); err != nil {
		t.Fatal(err)
	}
}

func (fixture *driverFixture) removeDriver(t *testing.T) {
	t.Helper()
	if err := os.Remove(fixture.identity.path); err != nil {
		t.Fatal(err)
	}
}

func (fixture *driverFixture) removeLane(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(fixture.root); err != nil {
		t.Fatal(err)
	}
	fixture.cleaned = true
}

func (fixture *driverFixture) validateOwnedIdentity() error {
	info, err := os.Lstat(fixture.identity.path)
	if err != nil {
		return err
	}
	if !os.SameFile(fixture.identity.file, info) || !info.Mode().IsRegular() || info.Mode().Perm() != fixture.identity.mode {
		return fmt.Errorf("fixture lost owned driver identity: mode=%v", info.Mode())
	}
	return nil
}

func (fixture *driverFixture) cleanup(t *testing.T) {
	t.Helper()
	if fixture.cleaned {
		return
	}
	fixture.cleaned = true
	if err := os.RemoveAll(fixture.root); err != nil {
		t.Errorf("clean fixture-owned driver state: %v", err)
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

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
