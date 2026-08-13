// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package signatureverify

func platformAliasPolicy() aliasPolicy { return denyAliasPolicy{} }
