// SPDX-License-Identifier: AGPL-3.0-only

package releasecontract

import (
	"archive/tar"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type memberDescriptor struct {
	Path     string
	Typeflag byte
	Mode     int64
	Size     int64
	Linkname string
	UID      int
	GID      int
	Uname    string
	Gname    string
}

func gitMemberDescriptor(name, mode, objectType string, size int64) memberDescriptor {
	descriptor := memberDescriptor{Path: name, Typeflag: 'g', Mode: 0o644, Size: size}
	if objectType != "blob" {
		return descriptor
	}
	switch mode {
	case "100644":
		descriptor.Typeflag = tar.TypeReg
	case "100755":
		descriptor.Typeflag, descriptor.Mode = tar.TypeReg, 0o755
	case "120000":
		descriptor.Typeflag = tar.TypeSymlink
	}
	return descriptor
}

// validatePortableRelativePath applies slash-separated archive semantics. It
// intentionally does not use filepath: release names must mean the same thing
// on Linux, macOS, and Windows extraction targets.
func validatePortableRelativePath(name string, maxBytes int) error {
	if name == "" {
		return errors.New("archive path is empty")
	}
	if len(name) > maxBytes {
		return fmt.Errorf("archive path exceeds %d-byte bound", maxBytes)
	}
	if !utf8.ValidString(name) {
		return errors.New("archive path is not valid UTF-8")
	}
	if strings.ContainsRune(name, '\\') {
		return errors.New("archive path contains a Windows separator")
	}
	if strings.HasPrefix(name, "/") || path.IsAbs(name) {
		return errors.New("archive path is absolute")
	}
	if len(name) >= 2 && isASCIIAlpha(name[0]) && name[1] == ':' {
		return errors.New("archive path has a Windows drive prefix")
	}
	if strings.HasPrefix(name, "-") {
		return errors.New("archive path begins with an option marker")
	}
	if path.Clean(name) != name {
		return errors.New("archive path is not canonical")
	}
	segments := strings.Split(name, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("archive path contains an empty, dot, or parent segment")
		}
		if strings.ContainsRune(segment, ':') {
			return errors.New("archive path contains a Windows drive or stream separator")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return errors.New("archive path has a Windows-ambiguous trailing character")
		}
		base := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
		if windowsReservedName(base) {
			return fmt.Errorf("archive path contains reserved Windows name %q", segment)
		}
		if strings.EqualFold(segment, ".git") {
			return errors.New("archive path contains reserved .git segment")
		}
		for _, r := range segment {
			if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
				return errors.New("archive path contains a control character")
			}
			// Reject decomposed combining sequences. This gives a stable portable
			// collision domain without depending on host Unicode normalization.
			if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) {
				return errors.New("archive path contains a normalization-ambiguous combining mark")
			}
		}
	}
	return nil
}

func validateArchivePrefix(prefix string, maxBytes int) error {
	if !strings.HasSuffix(prefix, "/") || strings.Count(strings.TrimSuffix(prefix, "/"), "/") != 0 {
		return errors.New("archive prefix must be one exact top-level directory")
	}
	return validatePortableRelativePath(strings.TrimSuffix(prefix, "/"), maxBytes)
}

func archiveMemberRelative(fullName, prefix string, maxBytes int) (string, error) {
	if err := validateArchivePrefix(prefix, maxBytes); err != nil {
		return "", err
	}
	if !strings.HasPrefix(fullName, prefix) {
		return "", fmt.Errorf("archive member %q is outside exact prefix %q", fullName, prefix)
	}
	relative := strings.TrimPrefix(fullName, prefix)
	if err := validatePortableRelativePath(relative, maxBytes); err != nil {
		return "", fmt.Errorf("archive member %q: %w", fullName, err)
	}
	if fullName != prefix+relative {
		return "", errors.New("archive member prefix is ambiguous")
	}
	return relative, nil
}

func validateMemberTable(members []memberDescriptor, limits Limits) error {
	if len(members) == 0 {
		return errors.New("archive member table is empty")
	}
	if len(members) > limits.MaxFiles {
		return errors.New("archive member table exceeds count bound")
	}
	seenExact := make(map[string]struct{}, len(members))
	seenPortable := make(map[string]string, len(members))
	var total int64
	previous := ""
	for _, member := range members {
		if err := validatePortableRelativePath(member.Path, limits.MaxPathBytes); err != nil {
			return fmt.Errorf("unsafe archive member %q: %w", member.Path, err)
		}
		if _, exists := seenExact[member.Path]; exists {
			return fmt.Errorf("duplicate archive member %q", member.Path)
		}
		seenExact[member.Path] = struct{}{}
		if previous != "" && member.Path <= previous {
			return fmt.Errorf("archive member table is not strictly sorted at %q", member.Path)
		}
		previous = member.Path
		key := portableCollisionKey(member.Path)
		if previous, exists := seenPortable[key]; exists {
			return fmt.Errorf("portable archive path collision between %q and %q", previous, member.Path)
		}
		seenPortable[key] = member.Path
		if member.Typeflag != tar.TypeReg || member.Linkname != "" {
			return fmt.Errorf("unsupported archive member type %s for %q", strconv.QuoteRune(rune(member.Typeflag)), member.Path)
		}
		if member.UID != 0 || member.GID != 0 || member.Uname != "" || member.Gname != "" {
			return fmt.Errorf("archive ownership metadata is not normalized for %q", member.Path)
		}
		if member.Mode != 0o644 && member.Mode != 0o755 {
			return fmt.Errorf("unsupported archive mode %#o for %q", member.Mode, member.Path)
		}
		if member.Size < 0 || member.Size > limits.MaxFileBytes {
			return fmt.Errorf("archive member %q exceeds file-size bound", member.Path)
		}
		if member.Size > limits.MaxTotalBytes-total {
			return errors.New("archive member table exceeds total-size bound")
		}
		total += member.Size
	}
	return nil
}

func portableCollisionKey(name string) string { return strings.ToLower(name) }

func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func windowsReservedName(value string) bool {
	switch value {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	if len(value) == 4 && (strings.HasPrefix(value, "COM") || strings.HasPrefix(value, "LPT")) && value[3] >= '1' && value[3] <= '9' {
		return true
	}
	return false
}
