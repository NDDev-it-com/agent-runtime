// SPDX-License-Identifier: AGPL-3.0-only

package governance

import (
	"errors"
	"fmt"
	"strings"
)

func VerifyCIWorkflow(contract Contract, workflow []byte) error {
	if err := contract.Validate(); err != nil {
		return err
	}
	text := strings.ReplaceAll(string(workflow), "\r\n", "\n")
	onBlock, err := yamlBlock(text, "on", 0)
	if err != nil {
		return err
	}
	if !hasYAMLKey(onBlock, "pull_request", 2) {
		return errors.New("CI workflow must run for every pull_request")
	}
	if strings.Contains(onBlock, "paths:") || strings.Contains(onBlock, "paths-ignore:") {
		return errors.New("CI workflow pull_request/push triggers must not use path filters")
	}
	if !hasYAMLKey(onBlock, "push", 2) || !strings.Contains(onBlock, "branches: [main]") {
		return errors.New("CI workflow must run on every push to main")
	}
	jobsBlock, err := yamlBlock(text, "jobs", 0)
	if err != nil {
		return err
	}
	for _, check := range contract.RequiredChecks {
		if check.Producer.Kind != "workflow" {
			continue
		}
		jobBlock, err := yamlBlock(jobsBlock, check.Producer.Job, 2)
		if err != nil {
			return fmt.Errorf("required check %q: %w", check.Context, err)
		}
		if hasYAMLKey(jobBlock, "name", 4) {
			return fmt.Errorf("required job %q must not override its stable check name", check.Producer.Job)
		}
		if check.Producer.MatrixOS == "" {
			if check.Context != check.Producer.Job {
				return fmt.Errorf("required check %q does not equal job %q", check.Context, check.Producer.Job)
			}
			continue
		}
		if check.Context != check.Producer.Job+" ("+check.Producer.MatrixOS+")" {
			return fmt.Errorf("required matrix context %q is not canonical", check.Context)
		}
		if !strings.Contains(jobBlock, "os: [ubuntu-latest, macos-latest]") {
			return errors.New("test matrix must contain the exact Ubuntu and macOS lanes")
		}
	}
	return nil
}

func yamlBlock(text, key string, indent int) (string, error) {
	lines := strings.Split(text, "\n")
	prefix := strings.Repeat(" ", indent) + key + ":"
	start := -1
	for i, line := range lines {
		if line == prefix || strings.HasPrefix(line, prefix+" ") {
			if start >= 0 {
				return "", fmt.Errorf("ambiguous duplicate YAML key %q", key)
			}
			start = i
		}
	}
	if start < 0 {
		return "", fmt.Errorf("YAML key %q not found", key)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		leading := len(line) - len(strings.TrimLeft(line, " "))
		if leading <= indent {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n"), nil
}

func hasYAMLKey(block, key string, indent int) bool {
	prefix := strings.Repeat(" ", indent) + key + ":"
	for _, line := range strings.Split(block, "\n") {
		if line == prefix || strings.HasPrefix(line, prefix+" ") {
			return true
		}
	}
	return false
}
