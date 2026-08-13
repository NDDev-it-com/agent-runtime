// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/NDDev-it-com/agent-runtime/internal/modverify"
)

func main() {
	if err := modverify.Verify(context.Background(), ".", os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "module tidy verification failed:", err)
		os.Exit(1)
	}
	fmt.Println("module metadata is tidy")
}
