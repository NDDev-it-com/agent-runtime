// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NDDev-it-com/agent-runtime/internal/fuzzverify"
)

func main() {
	contract, err := fuzzverify.Load(filepath.Join("fuzz", "v1alpha1.json"))
	if err == nil {
		err = fuzzverify.Verify(context.Background(), ".", contract, os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fuzz verification failed:", err)
		os.Exit(1)
	}
	fmt.Printf("fuzz contract valid: %d exact targets, %s each\n", len(contract.Targets), contract.FuzzTime)
}
