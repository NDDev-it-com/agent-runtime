// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package signatureverify

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyThroughGitPointerCheckouts covers the two ordinary layouts in which
// Git makes .git a pointer file rather than a directory. Both are checkouts a
// maintainer runs the documented release verification from.
func TestVerifyThroughGitPointerCheckouts(t *testing.T) {
	t.Parallel()
	for name, relocate := range map[string]func(*testing.T, signedRepository) string{
		"linked worktree": func(t *testing.T, fixture signedRepository) string {
			worktree := filepath.Join(filepath.Dir(fixture.repository), "linked")
			runGit(t, fixture.repository, "worktree", "add", "-q", "--detach", worktree, fixture.commit)
			return worktree
		},
		"absolute pointer": func(t *testing.T, fixture signedRepository) string {
			return repointGitDirectory(t, fixture, func(moved string) string { return moved })
		},
		"relative pointer": func(t *testing.T, fixture signedRepository) string {
			return repointGitDirectory(t, fixture, func(moved string) string {
				return filepath.Join("..", filepath.Base(moved))
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSignedRepository(t)
			checkout := relocate(t, fixture)
			if info, err := os.Lstat(filepath.Join(checkout, ".git")); err != nil {
				t.Fatal(err)
			} else if info.IsDir() {
				t.Fatalf("%s: fixture did not produce a .git pointer file", name)
			}

			var stdout, stderr bytes.Buffer
			request := Request{Repository: checkout, Kind: Commit, ObjectSHA: fixture.commit, Stdout: &stdout, Stderr: &stderr}
			result, err := verifyWithPolicy(context.Background(), request, execRunner{}, fixture.policy(t))
			if err != nil {
				t.Fatalf("verify: %v\nstdout=%s\nstderr=%s", err, stdout.Bytes(), stderr.Bytes())
			}
			if result.Principal != fixture.principal || result.CommitSHA != fixture.commit {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

// TestGitPointerBindsTheResolvedDirectory proves the pointer target — not the
// work tree — is what Git is given, and that the target is held by identity.
func TestGitPointerBindsTheResolvedDirectory(t *testing.T) {
	t.Parallel()
	fixture := newSignedRepository(t)
	moved := filepath.Join(filepath.Dir(fixture.repository), "git-directory")
	repointGitDirectory(t, fixture, func(string) string { return moved })

	identity, err := captureRepositoryIdentity(fixture.repository)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := identity.close(); err != nil {
			t.Error(err)
		}
	}()
	if identity.gitDirectory != moved {
		t.Fatalf("git directory = %q, want %q", identity.gitDirectory, moved)
	}
	if identity.pointer == nil || identity.linked == nil {
		t.Fatal("pointer checkout did not record the pointer or the linked chain")
	}
	for _, node := range identity.nodes {
		if node.component == ".git" {
			t.Fatal("pointer checkout recorded a .git directory node")
		}
	}
	if err := identity.revalidate(); err != nil {
		t.Fatal(err)
	}
}

// TestGitPointerRevalidationRejectsSubstitution proves a pointer swapped after
// capture is refused, so a redirected git directory cannot be picked up mid-run.
func TestGitPointerRevalidationRejectsSubstitution(t *testing.T) {
	t.Parallel()
	for name, substitute := range map[string]func(*testing.T, string){
		"rewritten in place": func(t *testing.T, pointer string) {
			writeRaw(t, pointer, []byte("gitdir: /nonexistent\n"))
		},
		"replaced by a new file": func(t *testing.T, pointer string) {
			replacement := pointer + ".replacement"
			writeRaw(t, replacement, []byte("gitdir: /nonexistent\n"))
			if err := os.Rename(replacement, pointer); err != nil {
				t.Fatal(err)
			}
		},
		"replaced by a directory": func(t *testing.T, pointer string) {
			if err := os.Remove(pointer); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(pointer, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSignedRepository(t)
			repointGitDirectory(t, fixture, func(moved string) string { return moved })
			identity, err := captureRepositoryIdentity(fixture.repository)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := identity.close(); err != nil {
					t.Error(err)
				}
			}()
			substitute(t, filepath.Join(fixture.repository, ".git"))
			if err := identity.revalidate(); err == nil {
				t.Fatal("revalidate accepted a substituted .git pointer")
			}
		})
	}
}

// TestGitPointerContentsAreBounded keeps the pointer grammar exact: anything
// that is not one "gitdir:" line naming an absolute-resolvable path is refused.
func TestGitPointerContentsAreBounded(t *testing.T) {
	t.Parallel()
	root := string(filepath.Separator) + filepath.Join("srv", "checkout")
	for name, contents := range map[string]string{
		"empty":            "",
		"wrong prefix":     "worktree: /srv/git\n",
		"no target":        "gitdir:\n",
		"blank target":     "gitdir:    \n",
		"embedded newline": "gitdir: /srv/git\ngitdir: /srv/other\n",
		"embedded NUL":     "gitdir: /srv/\x00git\n",
	} {
		t.Run(name, func(t *testing.T) {
			if target, err := gitPointerTarget(contents, root); err == nil {
				t.Fatalf("accepted malformed pointer %q as %q", contents, target)
			}
		})
	}
	for name, expectation := range map[string]struct{ contents, want string }{
		"absolute":         {"gitdir: /srv/git\n", string(filepath.Separator) + filepath.Join("srv", "git")},
		"relative":         {"gitdir: ../git\n", string(filepath.Separator) + filepath.Join("srv", "git")},
		"uncleaned":        {"gitdir: /srv/./checkout/../git\n", string(filepath.Separator) + filepath.Join("srv", "git")},
		"no trailing line": {"gitdir: /srv/git", string(filepath.Separator) + filepath.Join("srv", "git")},
	} {
		t.Run(name, func(t *testing.T) {
			target, err := gitPointerTarget(expectation.contents, root)
			if err != nil {
				t.Fatal(err)
			}
			if target != expectation.want {
				t.Fatalf("target = %q, want %q", target, expectation.want)
			}
		})
	}
}

// TestGitEntryStillRefusesLinksAndUnusableTargets proves widening .git to accept
// a regular file did not widen it to accept a symlink or an unusable target.
func TestGitEntryStillRefusesLinksAndUnusableTargets(t *testing.T) {
	t.Parallel()
	for name, damage := range map[string]func(*testing.T, signedRepository){
		"symlinked git directory": func(t *testing.T, fixture signedRepository) {
			moved := filepath.Join(filepath.Dir(fixture.repository), "git-directory")
			pointer := filepath.Join(fixture.repository, ".git")
			if err := os.Rename(pointer, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, pointer); err != nil {
				t.Fatal(err)
			}
		},
		"pointer to a missing directory": func(t *testing.T, fixture signedRepository) {
			repointGitDirectory(t, fixture, func(string) string {
				return filepath.Join(filepath.Dir(fixture.repository), "absent")
			})
		},
		"pointer to a regular file": func(t *testing.T, fixture signedRepository) {
			decoy := filepath.Join(filepath.Dir(fixture.repository), "decoy")
			writeRaw(t, decoy, []byte("not a git directory\n"))
			repointGitDirectory(t, fixture, func(string) string { return decoy })
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newSignedRepository(t)
			damage(t, fixture)
			identity, err := captureRepositoryIdentity(fixture.repository)
			if err == nil {
				if closeErr := identity.close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("capture accepted an unusable .git entry")
			}
			if strings.Contains(err.Error(), "panic") {
				t.Fatalf("unexpected failure mode: %v", err)
			}
		})
	}
}

// repointGitDirectory moves the fixture's git directory beside the work tree and
// leaves a pointer file naming it, reproducing a submodule-style checkout. The
// target is passed through spell so a test can choose an absolute or relative
// pointer. It returns the work tree.
func repointGitDirectory(t *testing.T, fixture signedRepository, spell func(moved string) string) string {
	t.Helper()
	moved := filepath.Join(filepath.Dir(fixture.repository), "git-directory")
	if err := os.Rename(filepath.Join(fixture.repository, ".git"), moved); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, filepath.Join(fixture.repository, ".git"), []byte("gitdir: "+spell(moved)+"\n"))
	return fixture.repository
}
