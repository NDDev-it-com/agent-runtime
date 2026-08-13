// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/NDDev-it-com/agent-runtime/internal/cicontract"
)

func main() {
	contract, err := cicontract.Load("security-tools.json")
	if err != nil {
		fail(err)
	}
	workflow, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		fail(err)
	}
	if err := cicontract.VerifyWorkflow(contract, workflow); err != nil {
		fail(err)
	}
	fmt.Printf("CI contract valid: compatibility Go %s; %s@%s requires Go >= %s\n", contract.CompatibilityGo, contract.Govulncheck.Module, contract.Govulncheck.Version, contract.Govulncheck.MinimumGo)
}
func fail(err error) { fmt.Fprintln(os.Stderr, "CI contract invalid:", err); os.Exit(1) }
