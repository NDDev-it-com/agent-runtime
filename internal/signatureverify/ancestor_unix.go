// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package signatureverify

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxAncestorComponents = 128
	maxAliasTargetBytes   = 256
	maxGitPointerBytes    = 4 << 10
	gitEntryName          = ".git"
	gitPointerPrefix      = "gitdir:"
)

type unixIdentity struct {
	dev   uint64
	ino   uint64
	mode  uint32
	nlink uint64
	uid   uint32
	gid   uint32
}

type filesystemObjectKind string

const (
	directoryObject   filesystemObjectKind = "directory"
	symlinkObject     filesystemObjectKind = "symlink"
	regularFileObject filesystemObjectKind = "regular file"
)

type ancestorNode struct {
	component string
	identity  unixIdentity
	fd        int
	closed    bool
}

type ancestorAlias struct {
	parent   unixIdentity
	name     string
	target   string
	identity unixIdentity
}

type gitPointerNode struct {
	identity unixIdentity
	contents string
	fd       int
	closed   bool
}

type repositoryIdentity struct {
	root string
	// gitDirectory is the path Git must be given as --git-dir. It is
	// root/.git for an ordinary checkout, and the resolved target of the
	// .git pointer file for a submodule or a linked worktree.
	gitDirectory string
	nodes        []ancestorNode
	aliases      []ancestorAlias
	// pointer and linked are set only when .git is a pointer file. linked
	// holds the ancestor identity of gitDirectory under the same discipline
	// applied to the work tree itself.
	pointer *gitPointerNode
	linked  *repositoryIdentity
	closeFD func(int) error
}

func captureRepositoryIdentity(root string) (repositoryIdentity, error) {
	return captureRepositoryIdentityWithPolicy(root, platformAliasPolicy(), unix.Close)
}

func captureRepositoryIdentityWithPolicy(root string, policy aliasPolicy, closeFD func(int) error) (identity repositoryIdentity, rootErr error) {
	identity, err := captureDirectoryChain(root, policy, closeFD)
	if err != nil {
		return identity, err
	}
	defer func() {
		if rootErr != nil {
			rootErr = errors.Join(rootErr, identity.close())
		}
	}()
	if err := identity.bindGitDirectory(policy); err != nil {
		return identity, err
	}
	if err := identity.revalidate(); err != nil {
		return identity, err
	}
	return identity, nil
}

// captureDirectoryChain holds one descriptor per component of an absolute path,
// refusing to follow links except where the platform alias policy authorises it.
func captureDirectoryChain(root string, policy aliasPolicy, closeFD func(int) error) (identity repositoryIdentity, rootErr error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return repositoryIdentity{}, errors.New("repository root must be one canonical absolute path")
	}
	components := strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || len(components) > maxAncestorComponents {
		return repositoryIdentity{}, errors.New("repository ancestor component budget exceeded")
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return repositoryIdentity{}, fmt.Errorf("open repository root anchor: %w", err)
	}
	rootStat, err := statFD(rootFD)
	if err != nil {
		return repositoryIdentity{}, errors.Join(err, closeFD(rootFD))
	}
	if err := validateIdentity(directoryObject, rootStat, rootStat); err != nil {
		return repositoryIdentity{}, errors.Join(fmt.Errorf("unsafe repository root anchor: %w", err), closeFD(rootFD))
	}
	identity = repositoryIdentity{root: root, nodes: []ancestorNode{{identity: rootStat, fd: rootFD}}, closeFD: closeFD}
	defer func() {
		if rootErr != nil {
			rootErr = errors.Join(rootErr, identity.close())
		}
	}()

	actual := append([]string(nil), components...)
	aliasUsed := false
	for index := 0; index < len(actual); index++ {
		if index >= maxAncestorComponents {
			return identity, errors.New("repository ancestor traversal budget exceeded")
		}
		component := actual[index]
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, 0) {
			return identity, errors.New("repository path contains an ambiguous component")
		}
		parent := &identity.nodes[len(identity.nodes)-1]
		fd, openErr := unix.Openat(parent.fd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			var linkStat unix.Stat_t
			if statErr := unix.Fstatat(parent.fd, component, &linkStat, unix.AT_SYMLINK_NOFOLLOW); statErr != nil || fileType(linkStat) != uint32(unix.S_IFLNK) {
				return identity, fmt.Errorf("open repository ancestor %q without following links: %w", component, openErr)
			}
			target, readErr := readlinkAt(parent.fd, component)
			if readErr != nil {
				return identity, fmt.Errorf("read repository ancestor alias %q: %w", component, readErr)
			}
			linkIdentity := identityOfStat(linkStat)
			if identityErr := validateIdentity(symlinkObject, linkIdentity, linkIdentity); identityErr != nil {
				return identity, fmt.Errorf("unsafe repository ancestor alias %q: %w", component, identityErr)
			}
			targetComponents, policyErr := policy.authorize(index, component, target, parent.identity, linkIdentity, aliasUsed)
			if policyErr != nil {
				return identity, policyErr
			}
			aliasUsed = true
			identity.aliases = append(identity.aliases, ancestorAlias{parent: parent.identity, name: component, target: target, identity: linkIdentity})
			actual = append(append(append([]string(nil), actual[:index]...), targetComponents...), actual[index+1:]...)
			index--
			continue
		}
		stat, statErr := statFD(fd)
		if statErr != nil {
			return identity, errors.Join(statErr, closeFD(fd))
		}
		if identityErr := validateIdentity(directoryObject, stat, stat); identityErr != nil {
			return identity, errors.Join(fmt.Errorf("repository ancestor %q is unsafe: %w", component, identityErr), closeFD(fd))
		}
		if aliasUsed && index < 2 && (stat.uid != 0 || stat.gid != 0 || stat.mode&0o022 != 0) {
			return identity, errors.Join(fmt.Errorf("canonical Darwin alias target %q has unsafe ownership or mode", component), closeFD(fd))
		}
		identity.nodes = append(identity.nodes, ancestorNode{component: component, identity: stat, fd: fd})
	}
	return identity, nil
}

// bindGitDirectory resolves the repository's git directory. An ordinary checkout
// has a .git directory, which is held as a further ancestor node. A submodule or
// a linked worktree has a .git pointer file naming the directory elsewhere; that
// target is held under the same no-follow, identity-bound discipline.
func (identity *repositoryIdentity) bindGitDirectory(policy aliasPolicy) error {
	parentFD := identity.nodes[len(identity.nodes)-1].fd
	gitFD, err := unix.Openat(parentFD, gitEntryName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if !errors.Is(err, unix.ENOTDIR) {
			return fmt.Errorf("open repository %s without following links: %w", gitEntryName, err)
		}
		return identity.bindGitPointer(parentFD, policy)
	}
	gitStat, err := statFD(gitFD)
	if err != nil {
		return errors.Join(err, identity.closeFD(gitFD))
	}
	if err := validateIdentity(directoryObject, gitStat, gitStat); err != nil {
		return errors.Join(fmt.Errorf("repository %s is unsafe: %w", gitEntryName, err), identity.closeFD(gitFD))
	}
	identity.nodes = append(identity.nodes, ancestorNode{component: gitEntryName, identity: gitStat, fd: gitFD})
	identity.gitDirectory = filepath.Join(identity.root, gitEntryName)
	return nil
}

func (identity *repositoryIdentity) bindGitPointer(parentFD int, policy aliasPolicy) (rootErr error) {
	pointerFD, err := unix.Openat(parentFD, gitEntryName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open repository %s without following links: %w", gitEntryName, err)
	}
	defer func() {
		if rootErr != nil {
			rootErr = errors.Join(rootErr, identity.closeFD(pointerFD))
		}
	}()
	stat, err := statFD(pointerFD)
	if err != nil {
		return err
	}
	if err := validateIdentity(regularFileObject, stat, stat); err != nil {
		return fmt.Errorf("repository %s pointer is unsafe: %w", gitEntryName, err)
	}
	contents, err := readGitPointer(pointerFD)
	if err != nil {
		return err
	}
	target, err := gitPointerTarget(contents, identity.root)
	if err != nil {
		return err
	}
	linked, err := captureDirectoryChain(target, policy, identity.closeFD)
	if err != nil {
		return fmt.Errorf("hold repository git directory %q: %w", target, err)
	}
	identity.pointer = &gitPointerNode{identity: stat, contents: contents, fd: pointerFD}
	identity.linked = &linked
	identity.gitDirectory = target
	return nil
}

// readGitPointer reads the pointer through the held descriptor, so the bytes
// parsed are the bytes of the inode whose identity was validated.
func readGitPointer(fd int) (string, error) {
	buffer := make([]byte, maxGitPointerBytes+1)
	length, err := unix.Pread(fd, buffer, 0)
	if err != nil {
		return "", fmt.Errorf("read repository %s pointer: %w", gitEntryName, err)
	}
	if length == 0 || length > maxGitPointerBytes {
		return "", fmt.Errorf("repository %s pointer is empty or exceeds its byte budget", gitEntryName)
	}
	return string(buffer[:length]), nil
}

func gitPointerTarget(contents, root string) (string, error) {
	line := strings.TrimRight(contents, "\n")
	if strings.ContainsAny(line, "\n\x00") {
		return "", fmt.Errorf("repository %s pointer must be a single line", gitEntryName)
	}
	rest, found := strings.CutPrefix(line, gitPointerPrefix)
	if !found {
		return "", fmt.Errorf("repository %s pointer must begin with %q", gitEntryName, gitPointerPrefix)
	}
	target := strings.TrimSpace(rest)
	if target == "" {
		return "", fmt.Errorf("repository %s pointer names no target", gitEntryName)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	if target = filepath.Clean(target); !filepath.IsAbs(target) {
		return "", fmt.Errorf("repository %s pointer target %q is not absolute", gitEntryName, target)
	}
	return target, nil
}

func (identity repositoryIdentity) revalidate() error {
	for index := range identity.nodes {
		current, err := statFD(identity.nodes[index].fd)
		if err != nil {
			return fmt.Errorf("stat held repository directory %q: %w", identity.nodes[index].component, err)
		}
		if err := validateIdentity(directoryObject, identity.nodes[index].identity, current); err != nil {
			return fmt.Errorf("held repository ancestor identity changed at component %q: %w", identity.nodes[index].component, err)
		}
	}
	for _, alias := range identity.aliases {
		parentFD := -1
		for index := range identity.nodes {
			if identity.nodes[index].identity == alias.parent {
				parentFD = identity.nodes[index].fd
				break
			}
		}
		if parentFD < 0 {
			return errors.New("repository alias parent identity is not held")
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(parentFD, alias.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("stat repository alias %q: %w", alias.name, err)
		}
		if err := validateIdentity(symlinkObject, alias.identity, identityOfStat(stat)); err != nil {
			return fmt.Errorf("repository alias identity changed at %q: %w", alias.name, err)
		}
		target, err := readlinkAt(parentFD, alias.name)
		if err != nil || target != alias.target {
			return fmt.Errorf("repository alias target changed at %q", alias.name)
		}
	}
	if err := identity.rewalk(); err != nil {
		return fmt.Errorf("repository path identity changed: %w", err)
	}
	if identity.pointer != nil {
		if err := identity.revalidatePointer(); err != nil {
			return err
		}
		if err := identity.linked.revalidate(); err != nil {
			return fmt.Errorf("repository git directory identity changed: %w", err)
		}
	}
	return nil
}

// revalidatePointer proves the pointer file still has the identity and the
// contents that produced gitDirectory, both through the held descriptor and
// through the name, so neither the inode nor the entry can have been swapped.
func (identity repositoryIdentity) revalidatePointer() error {
	current, err := statFD(identity.pointer.fd)
	if err != nil {
		return fmt.Errorf("stat held repository %s pointer: %w", gitEntryName, err)
	}
	if err := validateIdentity(regularFileObject, identity.pointer.identity, current); err != nil {
		return fmt.Errorf("held repository %s pointer identity changed: %w", gitEntryName, err)
	}
	contents, err := readGitPointer(identity.pointer.fd)
	if err != nil {
		return err
	}
	if contents != identity.pointer.contents {
		return fmt.Errorf("repository %s pointer contents changed", gitEntryName)
	}
	var named unix.Stat_t
	parentFD := identity.nodes[len(identity.nodes)-1].fd
	if err := unix.Fstatat(parentFD, gitEntryName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat repository %s pointer by name: %w", gitEntryName, err)
	}
	if err := validateIdentity(regularFileObject, identity.pointer.identity, identityOfStat(named)); err != nil {
		return fmt.Errorf("repository %s pointer was replaced: %w", gitEntryName, err)
	}
	return nil
}

func (identity repositoryIdentity) rewalk() (rootErr error) {
	if len(identity.nodes) == 0 {
		return errors.New("repository identity has no root anchor")
	}
	rootFD, err := unix.Openat(identity.nodes[0].fd, ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("duplicate held repository root anchor: %w", err)
	}
	currentFD := rootFD
	defer func() { rootErr = errors.Join(rootErr, identity.closeFD(currentFD)) }()
	for index := 1; index < len(identity.nodes); index++ {
		node := identity.nodes[index]
		nextFD, openErr := unix.Openat(currentFD, node.component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return fmt.Errorf("rewalk repository component %q: %w", node.component, openErr)
		}
		closeErr := identity.closeFD(currentFD)
		currentFD = nextFD
		if closeErr != nil {
			return fmt.Errorf("close repository rewalk descriptor: %w", closeErr)
		}
		stat, statErr := statFD(currentFD)
		if statErr != nil {
			return fmt.Errorf("stat repository rewalk component %q: %w", node.component, statErr)
		}
		if err := validateIdentity(directoryObject, node.identity, stat); err != nil {
			return fmt.Errorf("repository rewalk identity changed at %q: %w", node.component, err)
		}
	}
	return nil
}

func (identity *repositoryIdentity) close() error {
	var failures []error
	if identity.linked != nil {
		if err := identity.linked.close(); err != nil {
			failures = append(failures, err)
		}
	}
	if identity.pointer != nil && !identity.pointer.closed {
		identity.pointer.closed = true
		if err := identity.closeFD(identity.pointer.fd); err != nil {
			failures = append(failures, fmt.Errorf("close held repository %s pointer: %w", gitEntryName, err))
		}
	}
	for index := len(identity.nodes) - 1; index >= 0; index-- {
		if identity.nodes[index].closed {
			continue
		}
		identity.nodes[index].closed = true
		if err := identity.closeFD(identity.nodes[index].fd); err != nil {
			failures = append(failures, fmt.Errorf("close held repository descriptor %q: %w", identity.nodes[index].component, err))
		}
	}
	return errors.Join(failures...)
}

func statFD(fd int) (unixIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unixIdentity{}, err
	}
	return identityOfStat(stat), nil
}

func identityOfStat(stat unix.Stat_t) unixIdentity {
	return unixIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), mode: uint32(stat.Mode), nlink: uint64(stat.Nlink), uid: uint32(stat.Uid), gid: uint32(stat.Gid)}
}

func validateIdentity(kind filesystemObjectKind, recorded, current unixIdentity) error {
	expectedType := uint32(unix.S_IFDIR)
	switch kind {
	case directoryObject:
	case symlinkObject:
		expectedType = uint32(unix.S_IFLNK)
	case regularFileObject:
		expectedType = uint32(unix.S_IFREG)
	default:
		return fmt.Errorf("unsupported filesystem object kind %q", kind)
	}
	checks := []struct {
		field             string
		recorded, current uint64
	}{
		{"device", recorded.dev, current.dev},
		{"inode", recorded.ino, current.ino},
		{"type", uint64(fileTypeMode(recorded.mode)), uint64(fileTypeMode(current.mode))},
		{"owner_uid", uint64(recorded.uid), uint64(current.uid)},
		{"owner_gid", uint64(recorded.gid), uint64(current.gid)},
		{"security_mode", uint64(recorded.mode & 0o7777), uint64(current.mode & 0o7777)},
	}
	for _, check := range checks {
		if check.recorded != check.current {
			return fmt.Errorf("%s %s changed: recorded=%d current=%d", kind, check.field, check.recorded, check.current)
		}
	}
	if fileTypeMode(current.mode) != expectedType {
		return fmt.Errorf("%s has unsafe type %d", kind, fileTypeMode(current.mode))
	}
	if kind == symlinkObject || kind == regularFileObject {
		if recorded.nlink != 1 || current.nlink != 1 {
			return fmt.Errorf("%s link count must remain exactly one: recorded=%d current=%d", kind, recorded.nlink, current.nlink)
		}
	} else if recorded.nlink == 0 || current.nlink == 0 {
		return fmt.Errorf("directory is not live: recorded_nlink=%d current_nlink=%d", recorded.nlink, current.nlink)
	}
	return nil
}

func fileType(stat unix.Stat_t) uint32 { return uint32(stat.Mode) & uint32(unix.S_IFMT) }
func fileTypeMode(mode uint32) uint32  { return mode & uint32(unix.S_IFMT) }

func readlinkAt(directoryFD int, name string) (string, error) {
	buffer := make([]byte, maxAliasTargetBytes+1)
	length, err := unix.Readlinkat(directoryFD, name, buffer)
	if err != nil {
		return "", err
	}
	if length == 0 || length > maxAliasTargetBytes {
		return "", errors.New("repository alias target is empty or exceeds its byte budget")
	}
	return string(buffer[:length]), nil
}

type aliasPolicy interface {
	authorize(index int, name, target string, parent, link unixIdentity, alreadyUsed bool) ([]string, error)
}

type darwinCanonicalAliasPolicy struct{}

func (darwinCanonicalAliasPolicy) authorize(index int, name, target string, parent, link unixIdentity, alreadyUsed bool) ([]string, error) {
	if alreadyUsed || index != 0 || name != "var" || target != "private/var" {
		return nil, errors.New("repository ancestor alias is not the canonical Darwin /var transition")
	}
	if parent.uid != 0 || parent.gid != 0 || parent.mode&0o022 != 0 || link.uid != 0 || link.gid != 0 || fileTypeMode(link.mode) != uint32(unix.S_IFLNK) || link.nlink != 1 {
		return nil, errors.New("canonical Darwin /var alias has unsafe ownership, mode, type, or link count")
	}
	return []string{"private", "var"}, nil
}

type denyAliasPolicy struct{}

func (denyAliasPolicy) authorize(int, string, string, unixIdentity, unixIdentity, bool) ([]string, error) {
	return nil, errors.New("repository ancestor aliases are forbidden")
}
