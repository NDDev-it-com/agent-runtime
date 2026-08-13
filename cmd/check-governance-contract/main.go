// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/NDDev-it-com/agent-runtime/internal/governance"
)

func main() {
	contractPath := flag.String("contract", "governance/main-v1alpha1.json", "governance contract path")
	workflowPath := flag.String("workflow", ".github/workflows/ci.yml", "CI workflow path")
	snapshotPath := flag.String("snapshot", "", "optional live-state snapshot path")
	printRuleset := flag.Bool("print-ruleset", false, "print the canonical GitHub ruleset request")
	flag.Parse()
	contract, err := governance.Load(*contractPath)
	if err != nil {
		fail(err)
	}
	workflow, err := os.ReadFile(*workflowPath)
	if err != nil {
		fail(err)
	}
	if err := governance.VerifyCIWorkflow(contract, workflow); err != nil {
		fail(err)
	}
	if *snapshotPath != "" {
		snapshot, err := governance.LoadSnapshot(*snapshotPath)
		if err != nil {
			fail(err)
		}
		if err := governance.VerifySnapshot(contract, snapshot); err != nil {
			fail(err)
		}
	}
	if *printRuleset {
		data, err := governance.MarshalDesiredRuleset(contract)
		if err != nil {
			fail(err)
		}
		fmt.Println(string(data))
		return
	}
	fmt.Printf("governance contract valid: %d exact checks, strict PR-only main, zero approvals\n", len(contract.RequiredChecks))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "governance contract invalid:", err)
	os.Exit(1)
}
