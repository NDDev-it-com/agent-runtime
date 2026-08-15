// SPDX-License-Identifier: AGPL-3.0-only

// Package trustedexec resolves the executables the trust path runs.
//
// Signature and provenance verification shell out to git and ssh-keygen, and
// which file those names refer to decides what the verdict is worth. Resolving
// them through the ambient PATH would let anyone who can set an environment
// variable choose the program that decides whether a commit is signed, so this
// package never reads PATH. It searches a fixed, ordered list of absolute
// directories and requires the result to be a regular, non-symlink, executable
// file.
//
// The trade is deliberate and it is not free: a host that keeps its tools
// outside these directories — Nix and Guix are the ones that matter — cannot
// run verification at all. Every mechanism that would cover them, an
// environment override or a PATH search, is an ambient input into the one code
// path that must not have any. Failing with a clear message naming what was
// searched is the better half of that trade, and SECURITY.md states it.
package trustedexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// searchPath is the whole search. It is a list rather than a single constant so
// that a Homebrew macOS host works without weakening anything: every entry is
// absolute and none comes from the environment.
var searchPath = []string{"/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"}

// Environment is the child environment the trust path runs commands under. It
// is here rather than duplicated at each call site because a second copy is a
// second thing to keep right.
var Environment = []string{
	"PATH=" + SearchPathValue(),
	"GIT_CONFIG_NOSYSTEM=1",
	"GIT_CONFIG_GLOBAL=" + os.DevNull,
	"GIT_CONFIG_COUNT=0",
	"GIT_NO_REPLACE_OBJECTS=1",
}

// SearchPathValue renders the search path as a PATH value. A child of the trust
// path gets exactly the directories this package is willing to resolve from,
// and nothing it inherited.
func SearchPathValue() string { return strings.Join(searchPath, ":") }

type resolution struct {
	path string
	err  error
}

var (
	cache   sync.Map // name -> resolution
	cacheMu sync.Mutex
)

// Git returns the git executable the trust path runs.
func Git() (string, error) { return Resolve("git") }

// SSHKeygen returns the ssh-keygen executable the trust path runs.
func SSHKeygen() (string, error) { return Resolve("ssh-keygen") }

// Resolve returns the absolute path of a trusted tool, resolved once per
// process. A name containing a separator is rejected rather than treated as a
// path, because accepting one would make the search optional.
func Resolve(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, os.PathSeparator) {
		return "", fmt.Errorf("trusted executable name %q must be a bare name", name)
	}
	if cached, ok := cache.Load(name); ok {
		got := cached.(resolution)
		return got.path, got.err
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cached, ok := cache.Load(name); ok {
		got := cached.(resolution)
		return got.path, got.err
	}
	got := search(name)
	cache.Store(name, got)
	return got.path, got.err
}

func search(name string) resolution {
	for _, directory := range searchPath {
		candidate := filepath.Join(directory, name)
		// Lstat, not Stat: a symlink here would let whatever it points at be
		// substituted without touching the directory this package trusts.
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		// A tool anyone can rewrite is a tool anyone can replace, and the
		// verdict it produces would be theirs rather than the repository's.
		if info.Mode().Perm()&0o022 != 0 {
			return resolution{err: fmt.Errorf("trusted executable %s is group or world writable", candidate)}
		}
		return resolution{path: candidate}
	}
	return resolution{err: fmt.Errorf("trusted executable %q was not found in %s; verification never reads PATH, so a host that keeps its tools elsewhere cannot run it", name, strings.Join(searchPath, ", "))}
}
