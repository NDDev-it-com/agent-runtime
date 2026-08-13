// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package releasecontract

import "errors"

var errSecurePublicationUnsupported = errors.New("secure no-replace release publication is unsupported")

func publishBundle(string, Contract, map[string][]byte) error { return errSecurePublicationUnsupported }
func readBundleSecure(string, Contract) (map[string][]byte, error) {
	return nil, errSecurePublicationUnsupported
}
