// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package releasecontract

import "golang.org/x/sys/unix"

func atomicRenameNoReplace(fromFD int, from string, toFD int, to string) error {
	return unix.Renameat2(fromFD, from, toFD, to, unix.RENAME_NOREPLACE)
}
