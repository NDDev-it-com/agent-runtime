// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NDDev-it-com/agent-runtime/internal/releasecontract"
)

func main() {
	contractPath := flag.String("contract", "release/v1alpha1.json", "release contract path")
	build := flag.Bool("build", false, "build the deterministic release bundle")
	commit := flag.String("commit", "HEAD", "exact Git commit to build")
	out := flag.String("out", "", "empty output directory for the bundle")
	expectVersion := flag.String("expect-version", "", "required triggering tag version")
	flag.Parse()
	c, err := releasecontract.Load(*contractPath)
	if err != nil {
		fail(err)
	}
	root, err := filepath.Abs(".")
	if err != nil {
		fail(err)
	}
	if err := c.VerifyRepository(root); err != nil {
		fail(err)
	}
	if *expectVersion != "" && *expectVersion != c.Version {
		fail(fmt.Errorf("trigger version %q does not equal contract version %q", *expectVersion, c.Version))
	}
	if *build {
		if *out == "" {
			fail(fmt.Errorf("--out is required with --build"))
		}
		if err := releasecontract.Build(root, *commit, *out, c); err != nil {
			fail(err)
		}
		fmt.Printf("release bundle valid: %s from %s\n", c.Version, *commit)
		return
	}
	fmt.Printf("release contract valid: %s, five source/module assets, Go %s\n", c.Version, c.GoCompatibility)
}
func fail(err error) { fmt.Fprintln(os.Stderr, "release contract invalid:", err); os.Exit(1) }
