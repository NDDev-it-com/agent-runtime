// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/NDDev-it-com/agent-runtime/internal/journalverify"
)

func main() {
	result, err := journalverify.Verify(".", journalverify.DefaultDirectory, journalverify.SchemaPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goal journal invalid:", err)
		os.Exit(1)
	}
	fmt.Printf("goal journals valid: %d tracked under %s, accepted by the Goal contract and the published schema\n",
		len(result.Journals), result.Directory)
}
