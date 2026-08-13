// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package negativefixture

func darwinBypasses() {
	_ = descriptor.resource
	_ = fdOwner{}
}
