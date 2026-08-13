// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"bytes"
	"errors"
	"fmt"
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
	if rel == ".." || filepath.IsAbs(rel) || (len(rel) > 3 && rel[:3] == ".."+string(filepath.Separator)) {
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
		resolved, err := w.Resolve(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("stat instruction %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("instruction %q is not a regular file", path)
		}
		content, err := os.ReadFile(resolved)
		if err != nil {
			return nil, fmt.Errorf("read instruction %q: %w", path, err)
		}
		header := []byte("\n--- " + filepath.ToSlash(path) + " ---\n")
		if int64(out.Len()+len(header)+len(content)) > maxBytes {
			return nil, fmt.Errorf("assembled context exceeds %d bytes", maxBytes)
		}
		out.Write(header)
		out.Write(content)
		if len(content) == 0 || content[len(content)-1] != '\n' {
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), nil
}
