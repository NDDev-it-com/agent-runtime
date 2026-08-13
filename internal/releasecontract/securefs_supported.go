// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package releasecontract

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var errSecurePublicationUnsupported = errors.New("secure no-replace release publication is unsupported")

type fileIdentity struct{ dev, ino uint64 }

type fdRole string

type directoryTrustRole string

const (
	fdRoleAnchorRoot          fdRole             = "anchor_root"
	fdRoleAnchorParent        fdRole             = "anchor_parent"
	fdRoleStage               fdRole             = "stage"
	fdRoleAsset               fdRole             = "asset"
	fdRoleVerifiedBundle      fdRole             = "verified_bundle"
	fdRoleVerifiedAsset       fdRole             = "verified_asset"
	fdRoleRevalidationRoot    fdRole             = "revalidation_root"
	fdRoleRevalidationParent  fdRole             = "revalidation_parent"
	fdRoleEnumeration         fdRole             = "enumeration"
	fdRoleTestFixture         fdRole             = "test_fixture"
	directoryRoleAncestor     directoryTrustRole = "traversed_ancestor"
	directoryRoleCallerParent directoryTrustRole = "caller_owned_parent"
	directoryRoleStage        directoryTrustRole = "builder_owned_stage"
)

type fdOwnership struct {
	id       uint64
	role     fdRole
	resource string
}

type closeRequest struct {
	owner fdOwnership
	fd    int
	close func() error
}

var nextFDOwnerID atomic.Uint64

type fdOwner struct {
	fd        int
	ownership fdOwnership
	close     func() error
	closed    bool
}

func newFDOwner(fd int, role fdRole, resource string) fdOwner {
	return newFDOwnerWithClose(fd, role, resource, func() error { return unix.Close(fd) })
}

func invalidFDOwner() fdOwner { return fdOwner{fd: -1, closed: true} }

func newFDOwnerWithClose(fd int, role fdRole, resource string, closeOperation func() error) fdOwner {
	return fdOwner{fd: fd, ownership: fdOwnership{id: nextFDOwnerID.Add(1), role: role, resource: resource}, close: closeOperation}
}

func (o *fdOwner) handle() int                { return o.fd }
func (o *fdOwner) isClosed() bool             { return o == nil || o.closed }
func (o *fdOwner) metadata() fdOwnership      { return o.ownership }
func (o fdOwnership) ownerID() uint64         { return o.id }
func (o fdOwnership) ownerRole() fdRole       { return o.role }
func (o fdOwnership) ownerResource() string   { return o.resource }
func (r closeRequest) ownerID() uint64        { return r.owner.ownerID() }
func (r closeRequest) ownerRole() fdRole      { return r.owner.ownerRole() }
func (r closeRequest) rawHandle() int         { return r.fd }
func (r closeRequest) closeUnderlying() error { return r.close() }

type assetState uint8

const (
	assetOpened assetState = iota + 1
	assetWritten
	assetSynced
	assetClosed
)

type assetRecord struct {
	name     string
	identity fileIdentity
	parent   fileIdentity
	mode     uint32
	expected int64
	state    assetState
	fd       fdOwner
}

type anchoredNode struct {
	name     string
	identity fileIdentity
	fd       fdOwner
}

type anchoredSymlink struct {
	parentNode int
	name       string
	identity   fileIdentity
	target     string
}

type anchoredPath struct {
	absolute bool
	nodes    []anchoredNode
	symlinks []anchoredSymlink
	final    string
}

// assetFileMode and stageDirectoryMode are the exact modes the release contract
// publishes and verifies. O_CREAT and mkdirat subtract the process umask from a
// requested mode, so both are applied explicitly with fchmod, which the umask
// does not affect. Without that, release output would depend on the shell that
// built it and a host with umask 077 could not build at all.
const (
	assetFileMode      = 0o644
	stageDirectoryMode = 0o700
)

type transactionOptions struct {
	hook            func(string, *bundleTransaction) error
	write           func(int, []byte) (int, error)
	fsync           func(int) error
	fchmod          func(int, uint32) error
	close           func(closeRequest) error
	renameNoReplace func(int, string, int, string) error
	unlinkat        func(int, string, int) error
	enumerate       func(int) ([]string, error)
}

type bundleTransaction struct {
	anchor        *anchoredPath
	stage         fdOwner
	stageName     string
	stageIdentity fileIdentity
	assetIDs      map[string]*assetRecord
	finalName     string
	published     bool
	committed     bool
	opts          transactionOptions
}

type residualDebtError struct {
	Stage  fileIdentity
	Parent fileIdentity
	Items  []string
}

func (e *residualDebtError) Error() string {
	return fmt.Sprintf("residual release state stage=%s parent=%s: %s", formatIdentity(e.Stage), formatIdentity(e.Parent), strings.Join(e.Items, "; "))
}

func defaultTransactionOptions() transactionOptions {
	return transactionOptions{
		write: unix.Write, fsync: unix.Fsync, fchmod: unix.Fchmod, close: func(request closeRequest) error { return request.closeUnderlying() },
		renameNoReplace: atomicRenameNoReplace, unlinkat: unix.Unlinkat,
	}
}

func normalizeTransactionOptions(opts transactionOptions) transactionOptions {
	defaults := defaultTransactionOptions()
	if opts.write == nil {
		opts.write = defaults.write
	}
	if opts.fsync == nil {
		opts.fsync = defaults.fsync
	}
	if opts.fchmod == nil {
		opts.fchmod = defaults.fchmod
	}
	if opts.close == nil {
		opts.close = defaults.close
	}
	if opts.renameNoReplace == nil {
		opts.renameNoReplace = defaults.renameNoReplace
	}
	if opts.unlinkat == nil {
		opts.unlinkat = defaults.unlinkat
	}
	if opts.enumerate == nil {
		closeOptions := opts
		opts.enumerate = func(fd int) ([]string, error) { return enumerateDir(fd, closeOptions) }
	}
	return opts
}

func publishBundle(output string, c Contract, assets map[string][]byte) error {
	return publishBundleWithOptions(output, c, assets, defaultTransactionOptions())
}

func publishBundleWithOptions(output string, c Contract, content map[string][]byte, opts transactionOptions) (rootErr error) {
	opts = normalizeTransactionOptions(opts)
	anchor, err := openAnchoredParent(output, opts)
	if err != nil {
		return outputError(OutputInvalidParent, "open existing private parent", err)
	}
	tx := &bundleTransaction{anchor: anchor, stage: invalidFDOwner(), assetIDs: map[string]*assetRecord{}, finalName: anchor.final, opts: opts}
	defer func() {
		cleanupErr := tx.rollback(c)
		anchorErr := anchor.release(rootErr != nil || cleanupErr != nil, opts)
		cleanupErr = orderedErrors(cleanupErr, anchorErr)
		rootErr = joinRootCleanup(rootErr, cleanupErr)
		if cleanupErr != nil {
			rootErr = outputError(OutputCleanup, "rollback and descriptor release", rootErr)
		} else if rootErr != nil {
			var typed *OutputError
			if !errors.As(rootErr, &typed) {
				kind := OutputPartial
				if !tx.published && tx.stageName == "" {
					kind = OutputInvalidParent
				}
				rootErr = outputError(kind, "publish bundle", rootErr)
			}
		}
	}()
	if err = validatePrivateOutputParent(anchor); err != nil {
		return outputError(OutputInvalidParent, "validate existing private parent", err)
	}
	var destination unix.Stat_t
	if statErr := unix.Fstatat(anchor.parentFD(), anchor.final, &destination, unix.AT_SYMLINK_NOFOLLOW); statErr == nil {
		return outputError(OutputDestinationExists, "validate non-existent final leaf", unix.EEXIST)
	} else if !errors.Is(statErr, unix.ENOENT) {
		return outputError(OutputInvalidParent, "inspect final leaf", statErr)
	}
	if err = tx.callHook("after_anchor"); err != nil {
		return err
	}
	if err = anchor.revalidate(opts); err != nil {
		return outputError(OutputIdentityChanged, "revalidate anchor before stage", err)
	}
	if err = tx.createStage(); err != nil {
		return err
	}
	if err = tx.callHook("after_stage"); err != nil {
		return err
	}
	if err = tx.writeAssets(c, content); err != nil {
		return err
	}
	if err = tx.callHook("after_write"); err != nil {
		return err
	}
	readback, err := tx.readOwnedAssets(c)
	if err != nil {
		return err
	}
	if err = verifyBundleData(readback, c); err != nil {
		return fmt.Errorf("verify fd-owned release bundle: %w", err)
	}
	if err = tx.callHook("after_verify"); err != nil {
		return err
	}
	if err = tx.revalidateStage(c, content); err != nil {
		return outputError(OutputIdentityChanged, "revalidate staged bundle", err)
	}
	if err = anchor.revalidate(opts); err != nil {
		return outputError(OutputIdentityChanged, "revalidate anchor before publish", err)
	}
	if err = opts.fsync(tx.stage.handle()); err != nil {
		return fmt.Errorf("fsync stage directory: %w", err)
	}
	if err = opts.fsync(anchor.parentFD()); err != nil {
		return fmt.Errorf("fsync parent before publish: %w", err)
	}
	if err = tx.callHook("before_publish"); err != nil {
		return err
	}
	if err = tx.revalidateStage(c, content); err != nil {
		return outputError(OutputIdentityChanged, "revalidate staged bundle at publish", err)
	}
	if err = anchor.revalidate(opts); err != nil {
		return outputError(OutputIdentityChanged, "revalidate anchor at publish", err)
	}
	if err = opts.renameNoReplace(anchor.parentFD(), tx.stageName, anchor.parentFD(), tx.finalName); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return outputError(OutputDestinationExists, "atomic no-replace publish", err)
		}
		return outputError(OutputIdentityChanged, "atomic no-replace publish", err)
	}
	tx.published = true
	if err = opts.fsync(anchor.parentFD()); err != nil {
		return fmt.Errorf("fsync parent after publish: %w", err)
	}
	if err = tx.callHook("after_publish"); err != nil {
		return err
	}
	if err = anchor.revalidate(opts); err != nil {
		return outputError(OutputIdentityChanged, "revalidate anchor after publish", err)
	}
	if err = tx.revalidatePublished(c, content); err != nil {
		return outputError(OutputIdentityChanged, "revalidate published bundle", err)
	}
	if err = tx.closeAssets(); err != nil {
		return err
	}
	if err = tx.stage.closeOnce(opts, "close published stage directory"); err != nil {
		return err
	}
	tx.committed = true
	return nil
}

func validatePrivateOutputParent(anchor *anchoredPath) error {
	if anchor == nil || anchor.parentFD() < 0 {
		return errors.New("output parent descriptor is absent")
	}
	last := len(anchor.nodes) - 1
	if err := validateDirectoryRole(anchor.parentFD(), anchor.nodes[last].identity, directoryRoleCallerParent); err != nil {
		return err
	}
	if last == 0 {
		return errors.New("caller-owned output parent must be an explicit path below the traversal anchor")
	}
	var entry unix.Stat_t
	if err := unix.Fstatat(anchor.nodes[last-1].fd.handle(), anchor.nodes[last].name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("lookup caller-owned parent entry: %w", err)
	}
	if fileType(entry) != uint32(unix.S_IFDIR) || !sameIdentity(identityOf(entry), anchor.nodes[last].identity) {
		return errors.New("caller-owned parent entry is missing, replaced, or redirected")
	}
	return nil
}

func validateDirectoryRole(fd int, expected fileIdentity, role directoryTrustRole) error {
	if fd < 0 {
		return fmt.Errorf("%s descriptor is absent", role)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat %s: %w", role, err)
	}
	return validateDirectoryMetadata(st, expected, role, uint32(os.Geteuid()))
}

func validateDirectoryMetadata(st unix.Stat_t, expected fileIdentity, role directoryTrustRole, ownerUID uint32) error {
	if fileType(st) != uint32(unix.S_IFDIR) || !sameIdentity(identityOf(st), expected) {
		return fmt.Errorf("%s type or identity invariant differs", role)
	}
	permissions := filePermissions(st)
	switch role {
	case directoryRoleAncestor:
		return nil
	case directoryRoleCallerParent:
		if uint32(st.Uid) != ownerUID || permissions&0o022 != 0 || permissions&0o700 != 0o700 {
			return errors.New("caller-owned parent must be effective-UID-owned, owner-rwx, and not group/other writable")
		}
	case directoryRoleStage:
		if uint32(st.Uid) != ownerUID || permissions != stageDirectoryMode {
			return errors.New("builder-owned stage must be effective-UID-owned mode-0700")
		}
	default:
		return errors.New("directory trust role is unknown")
	}
	return nil
}

func readBundleSecure(directory string, c Contract) (assets map[string][]byte, rootErr error) {
	opts := normalizeTransactionOptions(defaultTransactionOptions())
	anchor, dir, identity, err := openAnchoredDirectory(directory, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		rootErr = orderedErrors(rootErr, dir.closeOnce(opts, "close verified bundle directory"), anchor.release(false, opts))
	}()
	assets, ids, err := readExactAssets(dir.handle(), c, opts)
	if err != nil {
		return nil, err
	}
	if err = anchor.revalidate(opts); err != nil {
		return nil, fmt.Errorf("revalidate bundle anchor: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Fstatat(anchor.parentFD(), anchor.final, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if fileType(st) != uint32(unix.S_IFDIR) || !sameIdentity(identity, identityOf(st)) {
		return nil, errors.New("bundle directory identity changed")
	}
	for _, name := range sortedKeys(ids) {
		if err = unix.Fstatat(dir.handle(), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameIdentity(ids[name], identityOf(st)) {
			return nil, fmt.Errorf("bundle asset %q identity changed", name)
		}
	}
	return assets, nil
}

func openAnchoredParent(target string, opts transactionOptions) (*anchoredPath, error) {
	clean := filepath.Clean(target)
	if clean != target || clean == "." || strings.ContainsRune(target, 0) {
		return nil, errors.New("output path must be non-empty and host-canonical")
	}
	absolute := filepath.IsAbs(clean)
	trimmed := strings.TrimPrefix(clean, string(filepath.Separator))
	parts := strings.Split(trimmed, string(filepath.Separator))
	final := parts[len(parts)-1]
	if err := validatePortableRelativePath(final, 255); err != nil || strings.ContainsRune(final, '/') {
		return nil, fmt.Errorf("unsafe output basename %q", final)
	}
	rootName := "."
	if absolute {
		rootName = string(filepath.Separator)
	}
	rootFD, err := unix.Open(rootName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open output anchor: %w", err)
	}
	rootID, err := identityForFD(rootFD)
	if err != nil {
		return nil, orderedErrors(err, closeRaw(rootFD, fdRoleAnchorRoot, opts, "close failed root anchor"))
	}
	anchor := &anchoredPath{absolute: absolute, nodes: []anchoredNode{{identity: rootID, fd: newFDOwner(rootFD, fdRoleAnchorRoot, "root anchor")}}, final: final}
	components := append([]string{}, parts[:len(parts)-1]...)
	const maxSymlinkHops = 16
	symlinkHops := 0
	for len(components) > 0 {
		component := components[0]
		components = components[1:]
		if component == "" || component == "." || component == ".." {
			return nil, orderedErrors(errors.New("output parent has ambiguous component"), anchor.release(true, opts))
		}
		parentFD := anchor.parentFD()
		fd, openErr := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			var st unix.Stat_t
			if statErr := unix.Fstatat(parentFD, component, &st, unix.AT_SYMLINK_NOFOLLOW); statErr == nil && fileType(st) == uint32(unix.S_IFLNK) {
				symlinkHops++
				if symlinkHops > maxSymlinkHops {
					return nil, orderedErrors(errors.New("output parent exceeds symlink hop bound"), anchor.release(true, opts))
				}
				target, readErr := readlinkAt(parentFD, component)
				if readErr != nil {
					return nil, orderedErrors(fmt.Errorf("readlinkat parent %q: %w", component, readErr), anchor.release(true, opts))
				}
				targetParts, targetErr := safeSymlinkTarget(target)
				if targetErr != nil {
					return nil, orderedErrors(fmt.Errorf("unsafe parent symlink %q: %w", component, targetErr), anchor.release(true, opts))
				}
				anchor.symlinks = append(anchor.symlinks, anchoredSymlink{parentNode: len(anchor.nodes) - 1, name: component, identity: identityOf(st), target: target})
				components = append(targetParts, components...)
				continue
			}
		}
		if openErr != nil {
			return nil, orderedErrors(fmt.Errorf("openat existing parent %q: %w", component, openErr), anchor.release(true, opts))
		}
		id, idErr := identityForFD(fd)
		if idErr != nil {
			return nil, orderedErrors(idErr, closeRaw(fd, fdRoleAnchorParent, opts, "close unidentified parent "+component), anchor.release(true, opts))
		}
		anchor.nodes = append(anchor.nodes, anchoredNode{name: component, identity: id, fd: newFDOwner(fd, fdRoleAnchorParent, "parent "+component)})
		if roleErr := validateDirectoryRole(fd, id, directoryRoleAncestor); roleErr != nil {
			return nil, orderedErrors(roleErr, anchor.release(true, opts))
		}
	}
	return anchor, nil
}

func openAnchoredDirectory(target string, opts transactionOptions) (*anchoredPath, fdOwner, fileIdentity, error) {
	anchor, err := openAnchoredParent(target, opts)
	if err != nil {
		return nil, invalidFDOwner(), fileIdentity{}, err
	}
	fd, err := unix.Openat(anchor.parentFD(), anchor.final, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, invalidFDOwner(), fileIdentity{}, orderedErrors(err, anchor.release(false, opts))
	}
	id, err := identityForFD(fd)
	if err != nil {
		return nil, invalidFDOwner(), fileIdentity{}, orderedErrors(err, closeRaw(fd, fdRoleVerifiedBundle, opts, "close unidentified bundle"), anchor.release(false, opts))
	}
	return anchor, newFDOwner(fd, fdRoleVerifiedBundle, "verified bundle directory"), id, nil
}

func (a *anchoredPath) parentFD() int { return a.nodes[len(a.nodes)-1].fd.handle() }

func (a *anchoredPath) revalidate(opts transactionOptions) (rootErr error) {
	for _, link := range a.symlinks {
		if link.parentNode < 0 || link.parentNode >= len(a.nodes) {
			return errors.New("symlink transcript has invalid parent")
		}
		parent := &a.nodes[link.parentNode]
		if parent.fd.isClosed() {
			return errors.New("symlink transcript parent is closed")
		}
		var st unix.Stat_t
		if err := unix.Fstatat(parent.fd.handle(), link.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || fileType(st) != uint32(unix.S_IFLNK) || !sameIdentity(identityOf(st), link.identity) {
			return errors.New("output symlink identity changed")
		}
		target, err := readlinkAt(parent.fd.handle(), link.name)
		if err != nil || target != link.target {
			return errors.New("output symlink target changed")
		}
	}
	rootName := "."
	if a.absolute {
		rootName = string(filepath.Separator)
	}
	fd, err := unix.Open(rootName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	owner := newFDOwner(fd, fdRoleRevalidationRoot, "revalidation root")
	defer func() { rootErr = orderedErrors(rootErr, owner.closeOnce(opts, "close revalidation root")) }()
	id, err := identityForFD(owner.handle())
	if err != nil || !sameIdentity(id, a.nodes[0].identity) {
		return errors.New("output root anchor identity changed")
	}
	for index := 1; index < len(a.nodes); index++ {
		nextFD, openErr := unix.Openat(owner.handle(), a.nodes[index].name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		next := newFDOwner(nextFD, fdRoleRevalidationParent, "revalidation parent "+a.nodes[index].name)
		closeErr := owner.closeOnce(opts, "close prior revalidation directory")
		owner = next
		if closeErr != nil {
			return closeErr
		}
		id, err = identityForFD(owner.handle())
		if err != nil || !sameIdentity(id, a.nodes[index].identity) {
			return errors.New("output ancestor identity changed")
		}
	}
	return nil
}

func readlinkAt(parentFD int, name string) (string, error) {
	buffer := make([]byte, 4097)
	count, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil {
		return "", err
	}
	if count <= 0 || count >= len(buffer) {
		return "", errors.New("symlink target is empty or exceeds byte bound")
	}
	return string(buffer[:count]), nil
}

func safeSymlinkTarget(target string) ([]string, error) {
	if target == "" || len(target) > 4096 || strings.ContainsRune(target, 0) || filepath.IsAbs(target) {
		return nil, errors.New("symlink target must be one bounded relative path")
	}
	parts := strings.Split(target, string(filepath.Separator))
	if len(parts) > 256 {
		return nil, errors.New("symlink target exceeds component bound")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("symlink target contains an escape or ambiguous component")
		}
	}
	return parts, nil
}

func (a *anchoredPath) release(_ bool, opts transactionOptions) error {
	var errs []error
	for index := len(a.nodes) - 1; index >= 0; index-- {
		node := &a.nodes[index]
		errs = append(errs, node.fd.closeOnce(opts, "close "+node.fd.metadata().ownerResource()))
	}
	a.nodes = nil
	return orderedErrors(errs...)
}

func (tx *bundleTransaction) callHook(point string) error {
	if tx.opts.hook == nil {
		return nil
	}
	if err := tx.opts.hook(point, tx); err != nil {
		return fmt.Errorf("transaction hook %s: %w", point, err)
	}
	return nil
}

func (tx *bundleTransaction) createStage() error {
	for attempt := 0; attempt < 32; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		name := ".release-stage-" + hex.EncodeToString(random)
		if err := unix.Mkdirat(tx.anchor.parentFD(), name, stageDirectoryMode); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return err
		}
		fd, err := unix.Openat(tx.anchor.parentFD(), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return orderedErrors(err, contextual("remove unopened stage", tx.opts.unlinkat(tx.anchor.parentFD(), name, unix.AT_REMOVEDIR)))
		}
		if err := tx.opts.fchmod(fd, stageDirectoryMode); err != nil {
			return orderedErrors(err, closeRaw(fd, fdRoleStage, tx.opts, "close unowned stage"), contextual("remove unowned stage", tx.opts.unlinkat(tx.anchor.parentFD(), name, unix.AT_REMOVEDIR)))
		}
		id, err := identityForFD(fd)
		if err != nil {
			return orderedErrors(err, closeRaw(fd, fdRoleStage, tx.opts, "close unidentified stage"), contextual("remove unidentified stage", tx.opts.unlinkat(tx.anchor.parentFD(), name, unix.AT_REMOVEDIR)))
		}
		tx.stageName, tx.stageIdentity = name, id
		tx.stage = newFDOwner(fd, fdRoleStage, "stage directory "+formatIdentity(id))
		if err := validateDirectoryRole(fd, id, directoryRoleStage); err != nil {
			return err
		}
		return nil
	}
	return errors.New("cannot allocate unique release stage")
}

func (tx *bundleTransaction) writeAssets(c Contract, content map[string][]byte) error {
	for _, name := range c.Assets.Names() {
		data, ok := content[name]
		if !ok {
			return fmt.Errorf("missing asset %q", name)
		}
		fd, err := unix.Openat(tx.stage.handle(), name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, assetFileMode)
		if err != nil {
			return fmt.Errorf("create asset %q: %w", name, err)
		}
		// Set the mode before capturing identity, so the recorded identity describes
		// the published artifact rather than whatever the umask happened to allow.
		modeErr := tx.opts.fchmod(fd, assetFileMode)
		id, idErr := identityForFD(fd)
		record := &assetRecord{name: name, identity: id, parent: tx.stageIdentity, mode: assetFileMode, expected: int64(len(data)), state: assetOpened, fd: newFDOwner(fd, fdRoleAsset, "asset "+name)}
		tx.assetIDs[name] = record
		if modeErr != nil {
			return fmt.Errorf("set asset %q mode: %w", name, modeErr)
		}
		if idErr != nil {
			return fmt.Errorf("identify asset %q: %w", name, idErr)
		}
		if err = tx.callHook("asset_opened:" + name); err != nil {
			return err
		}
		remaining := data
		for len(remaining) > 0 {
			n, writeErr := tx.opts.write(fd, remaining)
			if writeErr != nil {
				return fmt.Errorf("write asset %q: %w", name, writeErr)
			}
			if n <= 0 || n > len(remaining) {
				return fmt.Errorf("write asset %q: %w", name, io.ErrShortWrite)
			}
			remaining = remaining[n:]
		}
		record.state = assetWritten
		if err = tx.opts.fsync(fd); err != nil {
			return fmt.Errorf("fsync asset %q: %w", name, err)
		}
		record.state = assetSynced
		if err = tx.callHook("asset_synced:" + name); err != nil {
			return err
		}
	}
	return nil
}

func (tx *bundleTransaction) readOwnedAssets(c Contract) (map[string][]byte, error) {
	assets := make(map[string][]byte, len(tx.assetIDs))
	for _, name := range c.Assets.Names() {
		record, ok := tx.assetIDs[name]
		if !ok || record.fd.isClosed() {
			return nil, fmt.Errorf("asset %q lacks an open owned fd", name)
		}
		var st unix.Stat_t
		if err := unix.Fstat(record.fd.handle(), &st); err != nil {
			return nil, fmt.Errorf("fstat asset %q: %w", name, err)
		}
		if !assetMetadataMatches(record, tx.stageIdentity, st) || st.Size != record.expected || st.Size > c.Limits.MaxTotalBytes {
			return nil, fmt.Errorf("asset %q fd metadata changed", name)
		}
		if _, err := unix.Seek(record.fd.handle(), 0, io.SeekStart); err != nil {
			return nil, err
		}
		data := make([]byte, st.Size)
		if _, err := io.ReadFull(fdReader{record.fd.handle()}, data); err != nil {
			return nil, err
		}
		assets[name] = data
	}
	return assets, nil
}

type fdReader struct{ fd int }

func (r fdReader) Read(p []byte) (int, error) {
	n, err := unix.Read(r.fd, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func (tx *bundleTransaction) revalidateStage(c Contract, expected map[string][]byte) error {
	var st unix.Stat_t
	if err := unix.Fstatat(tx.anchor.parentFD(), tx.stageName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stage entry missing: %w", err)
	}
	if err := validateDirectoryRole(tx.stage.handle(), tx.stageIdentity, directoryRoleStage); err != nil || fileType(st) != uint32(unix.S_IFDIR) || !sameIdentity(identityOf(st), tx.stageIdentity) {
		return errors.New("stage directory identity changed")
	}
	entries, err := tx.opts.enumerate(tx.stage.handle())
	if err != nil {
		return fmt.Errorf("enumerate stage: %w", err)
	}
	sort.Strings(entries)
	want := c.Assets.Names()
	sort.Strings(want)
	if strings.Join(entries, "\n") != strings.Join(want, "\n") {
		return errors.New("stage asset closure changed")
	}
	for _, name := range entries {
		record := tx.assetIDs[name]
		if err = unix.Fstatat(tx.stage.handle(), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !assetMetadataMatches(record, tx.stageIdentity, st) {
			return fmt.Errorf("stage asset %q identity changed", name)
		}
	}
	actual, err := tx.readOwnedAssets(c)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(expected) {
		if string(actual[name]) != string(expected[name]) {
			return fmt.Errorf("stage asset %q content changed", name)
		}
	}
	return nil
}

func (tx *bundleTransaction) revalidatePublished(c Contract, expected map[string][]byte) error {
	var st unix.Stat_t
	if err := unix.Fstatat(tx.anchor.parentFD(), tx.finalName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if fileType(st) != uint32(unix.S_IFDIR) || !sameIdentity(identityOf(st), tx.stageIdentity) {
		return errors.New("published directory identity changed")
	}
	return tx.revalidateOwnedDirectory(c, expected)
}

func (tx *bundleTransaction) revalidateOwnedDirectory(c Contract, expected map[string][]byte) error {
	entries, err := tx.opts.enumerate(tx.stage.handle())
	if err != nil {
		return err
	}
	sort.Strings(entries)
	want := c.Assets.Names()
	sort.Strings(want)
	if strings.Join(entries, "\n") != strings.Join(want, "\n") {
		return errors.New("published asset closure changed")
	}
	actual, err := tx.readOwnedAssets(c)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(expected) {
		if string(actual[name]) != string(expected[name]) {
			return fmt.Errorf("published asset %q content changed", name)
		}
	}
	return nil
}

func (tx *bundleTransaction) closeAssets() error {
	var errs []error
	for _, name := range sortedKeys(tx.assetIDs) {
		record := tx.assetIDs[name]
		err := record.fd.closeOnce(tx.opts, "close asset "+name)
		record.state = assetClosed
		errs = append(errs, err)
	}
	return orderedErrors(errs...)
}

func (tx *bundleTransaction) rollback(c Contract) error {
	if tx.committed {
		return nil
	}
	var errs []error
	errs = append(errs, tx.closeAssets())
	if tx.stage.handle() >= 0 && !tx.stage.isClosed() {
		errs = append(errs, tx.cleanupOwnedEntries(c))
		errs = append(errs, contextual("fsync rollback stage", tx.opts.fsync(tx.stage.handle())))
		entries, enumerateErr := tx.opts.enumerate(tx.stage.handle())
		if enumerateErr != nil {
			errs = append(errs, fmt.Errorf("rollback enumerate held stage: %w", enumerateErr))
		} else if len(entries) != 0 {
			sort.Strings(entries)
			reasons := make([]string, 0, len(entries))
			for _, name := range entries {
				reasons = append(reasons, name+": residual entry")
			}
			errs = append(errs, tx.residual(reasons))
		} else {
			target, locateErr := tx.locateOwnedDirectory(tx.rollbackDirectoryName())
			if locateErr != nil {
				errs = append(errs, locateErr)
			} else {
				errs = append(errs, contextual("remove empty owned release directory", tx.opts.unlinkat(tx.anchor.parentFD(), target, unix.AT_REMOVEDIR)))
			}
			errs = append(errs, contextual("fsync parent after rollback", tx.opts.fsync(tx.anchor.parentFD())))
		}
	}
	errs = append(errs, tx.stage.closeOnce(tx.opts, "close rollback stage directory"))
	return orderedErrors(errs...)
}

func (tx *bundleTransaction) rollbackDirectoryName() string {
	if tx.published {
		return tx.finalName
	}
	return tx.stageName
}

func (tx *bundleTransaction) locateOwnedDirectory(preferred string) (string, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(tx.anchor.parentFD(), preferred, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if fileType(st) == uint32(unix.S_IFDIR) && sameIdentity(identityOf(st), tx.stageIdentity) {
			return preferred, nil
		}
		return "", tx.residual([]string{preferred + ": expected directory name is occupied by foreign identity/type"})
	} else if !errors.Is(err, unix.ENOENT) {
		return "", fmt.Errorf("rollback inspect directory %q: %w", preferred, err)
	}
	entries, err := tx.opts.enumerate(tx.anchor.parentFD())
	if err != nil {
		return "", fmt.Errorf("rollback scan anchored parent: %w", err)
	}
	sort.Strings(entries)
	for _, name := range entries {
		if err := unix.Fstatat(tx.anchor.parentFD(), name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil && fileType(st) == uint32(unix.S_IFDIR) && sameIdentity(identityOf(st), tx.stageIdentity) {
			return name, nil
		}
	}
	return "", tx.residual([]string{preferred + ": owned directory identity not reachable beneath anchored parent"})
}

func (tx *bundleTransaction) cleanupOwnedEntries(c Contract) error {
	entries, err := tx.opts.enumerate(tx.stage.handle())
	if err != nil {
		return fmt.Errorf("cleanup enumerate stage: %w", err)
	}
	sort.Strings(entries)
	allow := make(map[string]struct{}, 5)
	for _, name := range c.Assets.Names() {
		allow[name] = struct{}{}
	}
	var errs []error
	var residual []string
	for _, name := range entries {
		if _, ok := allow[name]; !ok {
			residual = append(residual, name+": unexpected entry")
			continue
		}
		record, ok := tx.assetIDs[name]
		if !ok {
			residual = append(residual, name+": no immutable ownership record")
			continue
		}
		var st unix.Stat_t
		if err = unix.Fstatat(tx.stage.handle(), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			residual = append(residual, name+": cannot prove identity")
			continue
		}
		if !assetMetadataMatches(record, tx.stageIdentity, st) {
			residual = append(residual, name+": identity/type/nlink/mode changed")
			continue
		}
		errs = append(errs, contextual("unlink owned asset "+name, tx.opts.unlinkat(tx.stage.handle(), name, 0)))
	}
	if len(residual) != 0 {
		errs = append(errs, tx.residual(residual))
	}
	return orderedErrors(errs...)
}

func (tx *bundleTransaction) residual(items []string) error {
	if len(items) > 32 {
		items = append(items[:32], fmt.Sprintf("%d additional entries omitted", len(items)-32))
	}
	parentID, _ := identityForFD(tx.anchor.parentFD())
	safe := make([]string, len(items))
	for index, item := range items {
		safe[index] = sanitizeResidual(item)
	}
	return &residualDebtError{Stage: tx.stageIdentity, Parent: parentID, Items: safe}
}

func sanitizeResidual(value string) string {
	if len(value) > 160 {
		value = value[:160]
	}
	return strconv.QuoteToASCII(value)
}

func assetMetadataMatches(record *assetRecord, parent fileIdentity, st unix.Stat_t) bool {
	return record != nil && sameIdentity(record.parent, parent) && sameIdentity(record.identity, identityOf(st)) && fileType(st) == uint32(unix.S_IFREG) && linkCount(st) == 1 && filePermissions(st) == record.mode
}

func readExactAssets(dirFD int, c Contract, opts transactionOptions) (map[string][]byte, map[string]fileIdentity, error) {
	entries, err := opts.enumerate(dirFD)
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(entries)
	want := c.Assets.Names()
	sort.Strings(want)
	if strings.Join(entries, "\n") != strings.Join(want, "\n") {
		return nil, nil, errors.New("fd-relative release asset closure mismatch")
	}
	assets := map[string][]byte{}
	ids := map[string]fileIdentity{}
	for _, name := range c.Assets.Names() {
		fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, nil, err
		}
		owner := newFDOwner(fd, fdRoleVerifiedAsset, "verified asset "+name)
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			return nil, nil, orderedErrors(err, owner.closeOnce(opts, "close unverified asset "+name))
		}
		if fileType(st) != uint32(unix.S_IFREG) || filePermissions(st) != assetFileMode || linkCount(st) != 1 || st.Size < 0 || st.Size > c.Limits.MaxTotalBytes {
			return nil, nil, orderedErrors(fmt.Errorf("asset %q has unsafe metadata", name), owner.closeOnce(opts, "close unsafe asset "+name))
		}
		data := make([]byte, st.Size)
		_, readErr := io.ReadFull(fdReader{fd}, data)
		closeErr := owner.closeOnce(opts, "close verified asset "+name)
		if readErr != nil || closeErr != nil {
			return nil, nil, orderedErrors(readErr, closeErr)
		}
		assets[name], ids[name] = data, identityOf(st)
	}
	return assets, ids, nil
}

func enumerateDir(fd int, opts transactionOptions) ([]string, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	if _, err = unix.Seek(dup, 0, io.SeekStart); err != nil {
		return nil, orderedErrors(err, closeRaw(dup, fdRoleEnumeration, opts, "close enumeration dup"))
	}
	file := os.NewFile(uintptr(dup), "fd-relative-directory")
	owner := newFDOwnerWithClose(dup, fdRoleEnumeration, "directory enumeration", file.Close)
	names, readErr := file.Readdirnames(-1)
	closeErr := owner.closeOnce(opts, "close enumeration handle")
	if readErr != nil || closeErr != nil {
		return nil, orderedErrors(readErr, contextual("close enumeration handle", closeErr))
	}
	return names, nil
}

func (o *fdOwner) closeOnce(opts transactionOptions, operation string) error {
	if o == nil || o.fd < 0 || o.closed {
		return nil
	}
	fd := o.fd
	ownership := o.ownership
	o.closed = true
	o.fd = -1
	if err := opts.close(closeRequest{owner: ownership, fd: fd, close: o.close}); err != nil {
		return fmt.Errorf("%s (owner=%d role=%s resource=%s fd=%d): %w", operation, ownership.id, ownership.role, ownership.resource, fd, err)
	}
	return nil
}

func closeRaw(fd int, role fdRole, opts transactionOptions, operation string) error {
	owner := newFDOwner(fd, role, operation)
	return owner.closeOnce(opts, operation)
}

func identityForFD(fd int) (fileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileIdentity{}, err
	}
	return identityOf(st), nil
}
func identityOf(st unix.Stat_t) fileIdentity {
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}
}

func normalizedFileMode(st unix.Stat_t) uint32 { return uint32(st.Mode) }
func fileType(st unix.Stat_t) uint32           { return normalizedFileMode(st) & uint32(unix.S_IFMT) }
func filePermissions(st unix.Stat_t) uint32    { return normalizedFileMode(st) & 0o777 }
func linkCount(st unix.Stat_t) uint64          { return uint64(st.Nlink) }
func sameIdentity(a, b fileIdentity) bool      { return a.dev == b.dev && a.ino == b.ino }
func formatIdentity(id fileIdentity) string    { return fmt.Sprintf("dev=%d,ino=%d", id.dev, id.ino) }

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contextual(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func orderedErrors(errs ...error) error {
	nonNil := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			nonNil = append(nonNil, err)
		}
	}
	return errors.Join(nonNil...)
}

func joinRootCleanup(root, cleanup error) error {
	if cleanup == nil {
		return root
	}
	if root == nil {
		return fmt.Errorf("cleanup after successful operation: %w", cleanup)
	}
	return errors.Join(root, fmt.Errorf("cleanup: %w", cleanup))
}
