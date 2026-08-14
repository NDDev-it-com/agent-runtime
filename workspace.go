// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Workspace struct{ root string }

func OpenWorkspace(path string) (Workspace, error) {
	if path == "" {
		return Workspace{}, errors.New("workspace path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve workspace: %w", err)
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve workspace symlinks: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return Workspace{}, fmt.Errorf("stat workspace: %w", err)
	}
	if !info.IsDir() {
		return Workspace{}, errors.New("workspace is not a directory")
	}
	return Workspace{root: filepath.Clean(root)}, nil
}

func (w Workspace) Root() string { return w.root }

func (w Workspace) Resolve(path string) (string, error) {
	if w.root == "" {
		return "", errors.New("workspace is not initialized")
	}
	if path == "" {
		return "", errors.New("path is empty")
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(w.root, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", path, err)
	}
	rel, err := filepath.Rel(w.root, resolved)
	if err != nil {
		return "", fmt.Errorf("compare %q with workspace: %w", path, err)
	}
	if rel != "." && !filepath.IsLocal(rel) {
		return "", fmt.Errorf("path %q escapes workspace", path)
	}
	return resolved, nil
}

func (w Workspace) ResolveDirectory(path string) (string, error) {
	resolved, err := w.Resolve(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat directory %q: %w", path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %q is not a directory", path)
	}
	return resolved, nil
}

func (w Workspace) BuildContext(paths []string, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 {
		return nil, errors.New("context limit must be positive")
	}
	var out bytes.Buffer
	for _, path := range paths {
		content, header, err := w.readInstruction(path, maxBytes-int64(out.Len()))
		if err != nil {
			return nil, err
		}
		out.Write(header)
		out.Write(content)
		if needsTerminator(content) {
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), nil
}

// readInstruction reads one instruction file within the remaining context budget.
// The budget bounds the read itself rather than the assembled result, so a file
// far larger than the declared limit is rejected without being allocated. The
// body budget also reserves the newline BuildContext appends when a file does not
// end with one, so the assembled context never exceeds the declared limit.
func (w Workspace) readInstruction(path string, remaining int64) (content, header []byte, err error) {
	resolved, err := w.Resolve(path)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, nil, fmt.Errorf("open instruction %q: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			content, header, err = nil, nil, fmt.Errorf("close instruction %q: %w", path, closeErr)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat instruction %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("instruction %q is not a regular file", path)
	}
	header = []byte("\n--- " + filepath.ToSlash(path) + " ---\n")
	budget := remaining - int64(len(header))
	if budget < 0 || info.Size() > budget {
		return nil, nil, fmt.Errorf("instruction %q does not fit the remaining context budget", path)
	}
	content, err = io.ReadAll(io.LimitReader(file, budget+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read instruction %q: %w", path, err)
	}
	if int64(len(content)) > budget {
		return nil, nil, fmt.Errorf("instruction %q grew past the remaining context budget", path)
	}
	if needsTerminator(content) && int64(len(content)) > budget-1 {
		return nil, nil, fmt.Errorf("instruction %q does not fit the remaining context budget", path)
	}
	return content, header, nil
}

// needsTerminator reports whether BuildContext must append a newline so the next
// instruction boundary starts on its own line.
func needsTerminator(content []byte) bool {
	return len(content) == 0 || content[len(content)-1] != '\n'
}
