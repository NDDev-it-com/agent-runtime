// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package signatureverify

func platformAliasPolicy() aliasPolicy { return darwinCanonicalAliasPolicy{} }
