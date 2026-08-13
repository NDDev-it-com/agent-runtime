// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/NDDev-it-com/agent-runtime/internal/compilematrix"
)

func main() {
	if os.Getenv("AGENT_RUNTIME_COLD_COMPILE_WRAPPER") == "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		fail(err)
	}
	if err := compilematrix.Run(context.Background(), compilematrix.Options{
		Repository: ".", Wrapper: executable, Stdout: os.Stdout, Stderr: os.Stderr,
	}); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cold compile matrix failed:", err)
	os.Exit(1)
}
