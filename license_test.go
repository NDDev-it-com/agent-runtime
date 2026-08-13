// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestLicenseMetadataParity(t *testing.T) {
	t.Parallel()
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(license), "GNU AFFERO GENERAL PUBLIC LICENSE") ||
		!strings.Contains(string(license), "Version 3, 19 November 2007") {
		t.Fatal("LICENSE is not the canonical GNU AGPL version 3 text")
	}
	if !strings.Contains(string(readme), "AGPL-3.0-only") {
		t.Fatal("README SPDX identifier is not AGPL-3.0-only")
	}
	if reference, err := os.ReadFile("../ci-workflows/LICENSE"); err == nil && !bytes.Equal(license, reference) {
		t.Fatal("LICENSE differs from canonical sibling public-module AGPL text")
	}
}
