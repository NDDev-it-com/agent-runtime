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
	out := flag.String("out", "", "non-existent final leaf beneath an existing private parent")
	resultPath := flag.String("result", "", "exclusive path for the machine-readable build result")
	verifyResult := flag.String("verify-result", "", "validate a build result against --out")
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
		if *out == "" || *resultPath == "" {
			fail(fmt.Errorf("--out and --result are required with --build"))
		}
		result, err := releasecontract.BuildWithResult(root, *commit, *out, c)
		if err != nil {
			fail(err)
		}
		if err := releasecontract.WriteBuildResult(*resultPath, result); err != nil {
			fail(err)
		}
		fmt.Printf("release bundle valid: %s from %s\n", c.Version, *commit)
		return
	}
	if *verifyResult != "" {
		if *out == "" {
			fail(fmt.Errorf("--out is required with --verify-result"))
		}
		result, err := releasecontract.LoadBuildResult(*verifyResult)
		if err != nil {
			fail(err)
		}
		if err := releasecontract.ValidateBuildResult(result, *out, c); err != nil {
			fail(err)
		}
		fmt.Printf("release build result valid: %s\n", *verifyResult)
		return
	}
	fmt.Printf("release contract valid: %s, five source/module assets, Go %s\n", c.Version, c.GoCompatibility)
}
func fail(err error) { fmt.Fprintln(os.Stderr, "release contract invalid:", err); os.Exit(1) }
