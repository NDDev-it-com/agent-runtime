// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/NDDev-it-com/agent-runtime/internal/signatureverify"
)

func main() {
	repository := flag.String("repository", ".", "repository root")
	commit := flag.String("commit", "", "exact signed commit object SHA")
	tag := flag.String("tag", "", "exact signed annotated tag object SHA")
	expectedCommit := flag.String("expected-commit", "", "exact commit SHA required for a signed tag")
	flag.Parse()
	kind, object := signatureverify.Commit, *commit
	if *tag != "" {
		if *commit != "" {
			fail(fmt.Errorf("choose exactly one of --commit or --tag"))
		}
		kind, object = signatureverify.Tag, *tag
	}
	result, err := signatureverify.Verify(context.Background(), signatureverify.Request{
		Repository: *repository, Kind: kind, ObjectSHA: object, ExpectedCommit: *expectedCommit,
		Stdout: os.Stdout, Stderr: os.Stderr,
	})
	if err != nil {
		fail(err)
	}
	fmt.Printf("verified %s %s: principal=%s fingerprint=%s commit=%s\n", kind, result.ObjectSHA, result.Principal, result.Fingerprint, result.CommitSHA)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "signature verification failed:", err)
	os.Exit(1)
}
