// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package negativefixture

func linuxBypasses(fd int) {
	_ = fdOwner{fd: fd}
	_ = fdOwnership{resource: "legacy"}
	_ = closeRequest{fd: fd}
	_ = owner.ownership
	_ = owner.fd
	_ = unix.Close(fd)
}
