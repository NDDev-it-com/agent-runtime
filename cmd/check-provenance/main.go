// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NDDev-it-com/agent-runtime/internal/provenance"
)

func main() {
	repository := flag.String("repository", ".", "repository root")
	commit := flag.String("integration", "", "exact protected-main integration commit SHA")
	pullRequest := flag.Int("pr", 0, "exact PR number; zero discovers the unique PR for the integration commit")
	contractPath := flag.String("contract", "provenance/v1alpha1.json", "repository-relative provenance contract")
	flag.Parse()

	contract, err := provenance.Load(filepath.Join(*repository, *contractPath))
	if err != nil {
		fail(err)
	}
	result, err := provenance.VerifyIntegration(context.Background(), provenance.VerifyRequest{
		RepositoryRoot: *repository,
		Contract:       contract,
		CommitSHA:      *commit,
		PullRequest:    *pullRequest,
		Token:          os.Getenv("GH_TOKEN"),
		APIBaseURL:     "https://api.github.com",
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
	})
	if err != nil {
		fail(err)
	}
	fmt.Printf("verified integration %s: pr=%d base=%s head=%s tree=%s source_commits=%d checks=%d\n", result.IntegrationSHA, result.PullRequest, result.BaseSHA, result.HeadSHA, result.TreeSHA, len(result.SourceCommits), len(result.CheckRuns))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "provenance verification failed:", err)
	os.Exit(1)
}
