// SPDX-License-Identifier: AGPL-3.0-only

// Package fuzzverify inventories and runs every contracted Go fuzz target.
package fuzzverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
)

const SchemaVersion = "v1alpha1"

var targetName = regexp.MustCompile(`^Fuzz[A-Z][A-Za-z0-9_]*$`)

const modulePath = "github.com/NDDev-it-com/agent-runtime"

type Contract struct {
	SchemaVersion    string   `json:"schema_version"`
	FuzzTime         string   `json:"fuzztime"`
	FuzzMinimizeTime string   `json:"fuzzminimizetime"`
	Parallel         int      `json:"parallel"`
	Timeout          string   `json:"timeout"`
	MaxCorpusFiles   int      `json:"max_corpus_files_per_target"`
	MaxCorpusBytes   int64    `json:"max_corpus_bytes_per_target"`
	Targets          []Target `json:"targets"`
}

type Target struct {
	Package string `json:"package"`
	Name    string `json:"name"`
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
	command.Dir, command.Env = call.dir, call.env
	command.Stdout, command.Stderr = call.stdout, call.stderr
	return command.Run()
}

func Load(path string) (Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Contract{}, fmt.Errorf("read fuzz contract: %w", err)
	}
	var contract Contract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode fuzz contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Contract{}, errors.New("fuzz contract must contain one JSON value")
	}
	if err := contract.Validate(); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

func (contract Contract) Validate() error {
	if contract.SchemaVersion != SchemaVersion || contract.FuzzTime != "100x" || contract.FuzzMinimizeTime != "10x" || contract.Parallel != 1 || contract.Timeout != "2m" || contract.MaxCorpusFiles != 256 || contract.MaxCorpusBytes != 1<<20 {
		return errors.New("fuzz execution and corpus bounds are not canonical")
	}
	if len(contract.Targets) < 1 || len(contract.Targets) > 64 {
		return errors.New("fuzz target inventory is empty or exceeds the bound")
	}
	for index, target := range contract.Targets {
		if (target.Package != modulePath && !strings.HasPrefix(target.Package, modulePath+"/")) || !targetName.MatchString(target.Name) {
			return fmt.Errorf("fuzz target %d identity is invalid", index)
		}
		if index > 0 && !targetLess(contract.Targets[index-1], target) {
			return errors.New("fuzz target inventory is unsorted or duplicated")
		}
	}
	return nil
}

func Verify(ctx context.Context, root string, contract Contract, stdout, stderr io.Writer) error {
	return verify(ctx, root, contract, stdout, stderr, osCommandRunner{})
}

func verify(ctx context.Context, root string, contract Contract, stdout, stderr io.Writer, runner commandRunner) error {
	if strings.TrimSpace(root) == "" || stdout == nil || stderr == nil {
		return errors.New("fuzz verification root and output writers are required")
	}
	if err := contract.Validate(); err != nil {
		return err
	}
	discovered, err := Discover(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(discovered, contract.Targets) {
		return fmt.Errorf("fuzz target inventory drift: discovered=%v contracted=%v", discovered, contract.Targets)
	}
	if err := verifyCorpusBounds(root, contract); err != nil {
		return err
	}
	environment := localToolchain(os.Environ())
	for _, target := range contract.Targets {
		args := []string{"test", target.Package, "-run=^$", "-fuzz=^" + target.Name + "$", "-fuzztime=" + contract.FuzzTime, "-fuzzminimizetime=" + contract.FuzzMinimizeTime, "-parallel=" + strconv.Itoa(contract.Parallel), "-timeout=" + contract.Timeout}
		call := invocation{path: "go", args: args, dir: root, env: environment, stdout: stdout, stderr: stderr}
		if err := runner.run(ctx, call); err != nil {
			return fmt.Errorf("fuzz %s %s: %w", target.Package, target.Name, err)
		}
	}
	return nil
}

func Discover(root string) ([]Target, error) {
	moduleData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("read module identity: %w", err)
	}
	discoveredModule := modfile.ModulePath(moduleData)
	if discoveredModule != modulePath {
		return nil, errors.New("go.mod module path differs from the fuzz contract")
	}
	var targets []Target
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("fuzz inventory source is not a regular file: %s", path)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse fuzz inventory %s: %w", path, err)
		}
		relative, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		packagePath := discoveredModule
		if relative != "." {
			packagePath += "/" + filepath.ToSlash(relative)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "Fuzz") {
				targets = append(targets, Target{Package: packagePath, Name: function.Name.Name})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(targets, func(i, j int) bool { return targetLess(targets[i], targets[j]) })
	for index := 1; index < len(targets); index++ {
		if targets[index] == targets[index-1] {
			return nil, fmt.Errorf("duplicate fuzz target %s %s", targets[index].Package, targets[index].Name)
		}
	}
	return targets, nil
}

func verifyCorpusBounds(root string, contract Contract) error {
	moduleData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	discoveredModule := modfile.ModulePath(moduleData)
	if discoveredModule != modulePath {
		return errors.New("go.mod module path differs from the fuzz contract")
	}
	for _, target := range contract.Targets {
		relative := strings.TrimPrefix(target.Package, discoveredModule)
		if relative == target.Package || (relative != "" && !strings.HasPrefix(relative, "/")) {
			return fmt.Errorf("fuzz target package %q is outside the module", target.Package)
		}
		corpusRoot := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(relative, "/")), "testdata", "fuzz", target.Name)
		count := 0
		var size int64
		err := filepath.WalkDir(corpusRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				return fs.SkipDir
			}
			if walkErr != nil {
				return walkErr
			}
			if path == corpusRoot {
				return nil
			}
			if entry.IsDir() || !entry.Type().IsRegular() {
				return fmt.Errorf("fuzz corpus member is not a regular file: %s", path)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			count++
			size += info.Size()
			if count > contract.MaxCorpusFiles || size > contract.MaxCorpusBytes {
				return fmt.Errorf("fuzz corpus for %s exceeds the file or byte bound", target.Name)
			}
			return nil
		})
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func targetLess(left, right Target) bool {
	if left.Package != right.Package {
		return left.Package < right.Package
	}
	return left.Name < right.Name
}

func localToolchain(environment []string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "GOTOOLCHAIN=") {
			result = append(result, entry)
		}
	}
	return append(result, "GOTOOLCHAIN=local")
}
