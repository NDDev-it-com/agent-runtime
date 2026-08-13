// SPDX-License-Identifier: AGPL-3.0-only

// Package provenance verifies the typed source, integration, and release-tag graph.
package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	SchemaVersion      = "v1alpha1"
	IntegrationCommand = "go run ./cmd/check-provenance --integration"
)

type Contract struct {
	SchemaVersion                 string          `json:"schema_version"`
	Repository                    string          `json:"repository"`
	OwnerLogin                    string          `json:"owner_login"`
	OwnerSSHAllowedSigners        string          `json:"owner_ssh_allowed_signers"`
	IntegrationOpenPGPKey         string          `json:"integration_openpgp_key"`
	IntegrationOpenPGPFingerprint string          `json:"integration_openpgp_fingerprint"`
	IntegrationOpenPGPSHA256      string          `json:"integration_openpgp_sha256"`
	IntegrationOpenPGPStatus      string          `json:"integration_openpgp_status"`
	TrustUpdatePolicy             string          `json:"trust_update_policy"`
	MergeMethod                   string          `json:"merge_method"`
	RequiredChecks                []RequiredCheck `json:"required_checks"`
}

type RequiredCheck struct {
	Context    string `json:"context"`
	AppID      int64  `json:"app_id"`
	WorkflowID int64  `json:"workflow_id"`
	Event      string `json:"event"`
}

func Load(path string) (Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Contract{}, fmt.Errorf("read provenance contract: %w", err)
	}
	var contract Contract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode provenance contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Contract{}, errors.New("provenance contract must contain one JSON value")
	}
	if err := contract.Validate(); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

func (contract Contract) Validate() error {
	if contract.SchemaVersion != SchemaVersion || contract.Repository != "NDDev-it-com/agent-runtime" || contract.OwnerLogin != "rldyourmnd" {
		return errors.New("provenance schema, repository, and owner identity are canonical")
	}
	if contract.OwnerSSHAllowedSigners != ".github/release-allowed-signers" || contract.IntegrationOpenPGPKey != ".github/github-web-flow.asc" {
		return errors.New("provenance trust paths are canonical")
	}
	if contract.IntegrationOpenPGPFingerprint != "968479A1AFF927E37D1A566BB5690EEEBB952194" || contract.IntegrationOpenPGPSHA256 != "40ce89d21fb075092d256f9fbf62a1c19299d3282cb913d3e61d08235d0c491a" || contract.IntegrationOpenPGPStatus != "active" || contract.TrustUpdatePolicy != "reviewed-contract-change" || contract.MergeMethod != "merge" {
		return errors.New("integration identity and merge method are canonical")
	}
	want := []RequiredCheck{
		{Context: "Analyze (go)", AppID: 15368, WorkflowID: 333214507, Event: "dynamic"},
		{Context: "govulncheck", AppID: 15368, WorkflowID: 333214464, Event: "pull_request"},
		{Context: "test (macos-latest)", AppID: 15368, WorkflowID: 333214464, Event: "pull_request"},
		{Context: "test (ubuntu-latest)", AppID: 15368, WorkflowID: 333214464, Event: "pull_request"},
	}
	checks := append([]RequiredCheck(nil), contract.RequiredChecks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].Context < checks[j].Context })
	if len(checks) != len(want) {
		return errors.New("provenance requires exactly four checks")
	}
	for index := range want {
		if checks[index] != want[index] || strings.TrimSpace(checks[index].Context) != checks[index].Context {
			return errors.New("provenance check identity, app, workflow, event, or order drifted")
		}
	}
	return nil
}
