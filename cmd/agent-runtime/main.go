// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	agentruntime "github.com/NDDev-it-com/agent-runtime"
	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var goalErr *goalpkg.Error
		if errors.As(err, &goalErr) {
			_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"error": string(goalErr.Code), "message": goalErr.Error()})
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "task":
		return taskCommand(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return nil
	case "goal":
		return goalCommand(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		return usage(stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) error {
	fmt.Fprintln(w, "usage: agent-runtime <task|goal|version> [options]")
	return nil
}

func flags(name string, args []string, stderr io.Writer) (*flag.FlagSet, *string, *string, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	manifest := set.String("manifest", "agent.json", "path to the Task manifest")
	workspace := set.String("workspace", ".", "workspace root")
	if err := set.Parse(args); err != nil {
		return nil, nil, nil, err
	}
	if set.NArg() != 0 {
		return nil, nil, nil, errors.New("unexpected positional arguments")
	}
	return set, manifest, workspace, nil
}

func load(path string) (agentruntime.TaskManifest, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return agentruntime.TaskManifest{}, fmt.Errorf("open task manifest: %w", err)
	}
	defer file.Close()
	return agentruntime.DecodeTaskManifest(file)
}

func taskCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-runtime task <validate|run>")
	}
	switch args[0] {
	case "validate":
		return validate(args[1:], stdout, stderr)
	case "run":
		return execute(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown task command %q", args[0])
	}
}

func validate(args []string, stdout, stderr io.Writer) error {
	_, manifestPath, workspacePath, err := flags("validate", args, stderr)
	if err != nil {
		return err
	}
	manifest, err := load(*manifestPath)
	if err != nil {
		return err
	}
	workspace, err := agentruntime.OpenWorkspace(*workspacePath)
	if err != nil {
		return err
	}
	if _, err := workspace.BuildContext(manifest.Instructions, manifest.MaxContext); err != nil {
		return err
	}
	if _, err := workspace.ResolveDirectory(manifest.Workdir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Task manifest %q is valid\n", manifest.ID)
	return nil
}

func execute(args []string, stdout, stderr io.Writer) error {
	_, manifestPath, workspacePath, err := flags("run", args, stderr)
	if err != nil {
		return err
	}
	manifest, err := load(*manifestPath)
	if err != nil {
		return err
	}
	workspace, err := agentruntime.OpenWorkspace(*workspacePath)
	if err != nil {
		return err
	}
	result, runErr := (agentruntime.Runner{Workspace: workspace}).Run(context.Background(), manifest)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return runErr
}
