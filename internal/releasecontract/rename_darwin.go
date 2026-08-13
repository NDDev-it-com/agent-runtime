// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package releasecontract

import "golang.org/x/sys/unix"

func atomicRenameNoReplace(fromFD int, from string, toFD int, to string) error {
	return unix.RenameatxNp(fromFD, from, toFD, to, unix.RENAME_EXCL)
}
