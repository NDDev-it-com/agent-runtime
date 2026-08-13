// SPDX-License-Identifier: AGPL-3.0-only

package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/NDDev-it-com/agent-runtime/internal/signatureverify"
)

const maxAPIBytes = 8 << 20

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

type VerifyRequest struct {
	RepositoryRoot string
	Contract       Contract
	CommitSHA      string
	PullRequest    int
	Token          string
	APIBaseURL     string
	HTTPClient     *http.Client
	Stdout         io.Writer
	Stderr         io.Writer
}

type Result struct {
	IntegrationSHA string
	BaseSHA        string
	HeadSHA        string
	TreeSHA        string
	PullRequest    int
	SourceCommits  []string
	CheckRuns      map[string]int64
	CheckSuites    map[string]int64
}

type githubClient struct {
	base, repository, token string
	http                    *http.Client
}

type pullResponse struct {
	ID             int64     `json:"id"`
	NodeID         string    `json:"node_id"`
	Number         int       `json:"number"`
	State          string    `json:"state"`
	Merged         bool      `json:"merged"`
	MergeCommitSHA string    `json:"merge_commit_sha"`
	MergedAt       time.Time `json:"merged_at"`
	MergedBy       apiActor  `json:"merged_by"`
	Base           apiRef    `json:"base"`
	Head           apiRef    `json:"head"`
	Commits        int       `json:"commits"`
}
type apiActor struct {
	Login  string `json:"login"`
	ID     int64  `json:"id"`
	NodeID string `json:"node_id"`
	Type   string `json:"type"`
}
type apiRef struct {
	Ref        string        `json:"ref"`
	SHA        string        `json:"sha"`
	Repository apiRepository `json:"repo"`
}
type apiRepository struct {
	ID     int64  `json:"id"`
	NodeID string `json:"node_id"`
}
type apiCommitListItem struct {
	SHA string `json:"sha"`
}
type commitResponse struct {
	SHA       string      `json:"sha"`
	NodeID    string      `json:"node_id"`
	Author    apiActor    `json:"author"`
	Committer apiActor    `json:"committer"`
	Parents   []apiRef    `json:"parents"`
	Commit    commitBlock `json:"commit"`
}
type commitBlock struct {
	Tree         apiRef          `json:"tree"`
	Verification apiVerification `json:"verification"`
}
type apiVerification struct {
	Verified   bool      `json:"verified"`
	Reason     string    `json:"reason"`
	Signature  string    `json:"signature"`
	Payload    string    `json:"payload"`
	VerifiedAt time.Time `json:"verified_at"`
}
type checksResponse struct {
	TotalCount int        `json:"total_count"`
	CheckRuns  []checkRun `json:"check_runs"`
}
type checkRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	DetailsURL string `json:"details_url"`
	App        struct {
		ID     int64  `json:"id"`
		NodeID string `json:"node_id"`
		Slug   string `json:"slug"`
	} `json:"app"`
	CheckSuite struct {
		ID int64 `json:"id"`
	} `json:"check_suite"`
	CompletedAt time.Time `json:"completed_at"`
}
type workflowRun struct {
	ID         int64     `json:"id"`
	RunAttempt int       `json:"run_attempt"`
	Event      string    `json:"event"`
	HeadSHA    string    `json:"head_sha"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	WorkflowID int64     `json:"workflow_id"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type commitPull struct {
	Number int `json:"number"`
}

func VerifyIntegration(ctx context.Context, request VerifyRequest) (Result, error) {
	if err := request.Contract.Validate(); err != nil {
		return Result{}, err
	}
	if !fullSHA.MatchString(request.CommitSHA) || request.PullRequest < 0 {
		return Result{}, errors.New("integration verification requires an exact commit SHA")
	}
	if strings.TrimSpace(request.Token) == "" {
		return Result{}, errors.New("integration verification requires explicit read-only GitHub token")
	}
	if request.Stdout == nil || request.Stderr == nil {
		return Result{}, errors.New("integration verification output writers are required")
	}
	root, err := filepath.Abs(request.RepositoryRoot)
	if err != nil {
		return Result{}, err
	}
	client := githubClient{base: strings.TrimSuffix(request.APIBaseURL, "/"), repository: request.Contract.Repository, token: request.Token, http: request.HTTPClient}
	if client.base == "" {
		client.base = "https://api.github.com"
	}
	if client.http == nil {
		client.http = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("GitHub API redirects are forbidden")
		}}
	}
	if request.PullRequest == 0 {
		var pulls []commitPull
		if err := client.get(ctx, "/repos/"+client.repository+"/commits/"+request.CommitSHA+"/pulls", &pulls); err != nil {
			return Result{}, err
		}
		if len(pulls) != 1 || pulls[0].Number < 1 {
			return Result{}, errors.New("integration commit must map to exactly one PR")
		}
		request.PullRequest = pulls[0].Number
	}
	var pull pullResponse
	if err := client.get(ctx, fmt.Sprintf("/repos/%s/pulls/%d", client.repository, request.PullRequest), &pull); err != nil {
		return Result{}, err
	}
	if err := validatePullIdentity(request.Contract, request, pull); err != nil {
		return Result{}, err
	}
	var integration commitResponse
	if err := client.get(ctx, "/repos/"+client.repository+"/commits/"+request.CommitSHA, &integration); err != nil {
		return Result{}, err
	}
	if err := validateIntegrationIdentity(request.Contract, pull, integration); err != nil {
		return Result{}, err
	}
	localPayload, localSignature, err := readSignedCommit(ctx, root, request.CommitSHA)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(localPayload, []byte(integration.Commit.Verification.Payload)) || !bytes.Equal(localSignature, []byte(integration.Commit.Verification.Signature)) {
		return Result{}, errors.New("GitHub verification payload/signature differs from local commit object")
	}
	if !integration.Commit.Verification.Verified || integration.Commit.Verification.Reason != "valid" || integration.Commit.Verification.VerifiedAt.IsZero() {
		return Result{}, errors.New("integration signature API evidence is absent, partial, or invalid")
	}
	if err := verifyOpenPGP(root, request.Contract, localPayload, localSignature, pull.MergedAt); err != nil {
		return Result{}, err
	}
	var sourceItems []apiCommitListItem
	if err := client.get(ctx, fmt.Sprintf("/repos/%s/pulls/%d/commits?per_page=100", client.repository, pull.Number), &sourceItems); err != nil {
		return Result{}, err
	}
	if len(sourceItems) != pull.Commits {
		return Result{}, errors.New("PR source commit enumeration is incomplete")
	}
	sources := make([]string, len(sourceItems))
	for index, item := range sourceItems {
		if !fullSHA.MatchString(item.SHA) {
			return Result{}, errors.New("PR source commit SHA is malformed")
		}
		if _, err := signatureverify.Verify(ctx, signatureverify.Request{Repository: root, Kind: signatureverify.Commit, ObjectSHA: item.SHA, Stdout: request.Stdout, Stderr: request.Stderr}); err != nil {
			return Result{}, fmt.Errorf("verify owner source commit %s: %w", item.SHA, err)
		}
		sources[index] = item.SHA
	}
	if sources[len(sources)-1] != pull.Head.SHA {
		return Result{}, errors.New("PR source enumeration does not end at reviewed head")
	}
	checks, suites, err := verifyChecks(ctx, client, request.Contract, pull.Head.SHA, pull.MergedAt)
	if err != nil {
		return Result{}, err
	}
	return Result{IntegrationSHA: integration.SHA, BaseSHA: pull.Base.SHA, HeadSHA: pull.Head.SHA, TreeSHA: integration.Commit.Tree.SHA, PullRequest: pull.Number, SourceCommits: sources, CheckRuns: checks, CheckSuites: suites}, nil
}

func validateIntegrationIdentity(contract Contract, pull pullResponse, commit commitResponse) error {
	if contract.MergeMethod != "merge" {
		return errors.New("integration contract does not require a two-parent merge")
	}
	if commit.SHA != pull.MergeCommitSHA || len(commit.Parents) != 2 || commit.Parents[0].SHA != pull.Base.SHA || commit.Parents[1].SHA != pull.Head.SHA || !fullSHA.MatchString(commit.Commit.Tree.SHA) {
		return errors.New("integration SHA, parent order, PR base/head, or tree identity differs")
	}
	if commit.Committer.Login != contract.IntegrationSignerLogin || commit.Committer.ID != contract.IntegrationSignerDatabaseID || commit.Committer.NodeID != contract.IntegrationSignerNodeID || commit.Committer.Type != "User" {
		return errors.New("integration signer account identity differs from the pinned provider role")
	}
	return nil
}

func validatePullIdentity(contract Contract, request VerifyRequest, pull pullResponse) error {
	checks := []struct {
		valid bool
		field string
	}{
		{pull.ID > 0 && pull.NodeID != "", "pull_request.id"},
		{pull.Number == request.PullRequest, "pull_request.number"},
		{pull.State == "closed" && pull.Merged, "pull_request.state"},
		{!pull.MergedAt.IsZero(), "pull_request.merged_at"},
		{pull.MergeCommitSHA == request.CommitSHA, "pull_request.merge_commit_sha"},
		{pull.MergedBy.Login == contract.OwnerLogin && pull.MergedBy.ID == contract.OwnerDatabaseID && pull.MergedBy.NodeID == contract.OwnerNodeID && pull.MergedBy.Type == "User", "pull_request.merged_by"},
		{pull.Base.Ref == "main" && fullSHA.MatchString(pull.Base.SHA), "pull_request.base"},
		{pull.Head.Ref != "" && fullSHA.MatchString(pull.Head.SHA), "pull_request.head"},
		{pull.Base.Repository.ID == contract.RepositoryDatabaseID && pull.Base.Repository.NodeID == contract.RepositoryNodeID, "pull_request.base.repository"},
		{pull.Head.Repository.ID == contract.RepositoryDatabaseID && pull.Head.Repository.NodeID == contract.RepositoryNodeID, "pull_request.head.repository"},
		{pull.Commits >= 1 && pull.Commits <= 64, "pull_request.commits"},
	}
	for _, check := range checks {
		if !check.valid {
			return fmt.Errorf("integration provenance field %s is invalid", check.field)
		}
	}
	return nil
}

func verifyChecks(ctx context.Context, client githubClient, contract Contract, head string, mergedAt time.Time) (map[string]int64, map[string]int64, error) {
	var response checksResponse
	if err := client.get(ctx, "/repos/"+client.repository+"/commits/"+head+"/check-runs?per_page=100", &response); err != nil {
		return nil, nil, err
	}
	if response.TotalCount != len(response.CheckRuns) || response.TotalCount > 100 {
		return nil, nil, errors.New("check-run enumeration is incomplete or exceeds the bounded page")
	}
	want := make(map[string]RequiredCheck, len(contract.RequiredChecks))
	for _, check := range contract.RequiredChecks {
		want[check.Context] = check
	}
	found := make(map[string]int64, len(want))
	suites := make(map[string]int64, len(want))
	for _, check := range response.CheckRuns {
		required, ok := want[check.Name]
		if !ok {
			continue
		}
		if _, duplicate := found[check.Name]; duplicate {
			return nil, nil, fmt.Errorf("required check %q is ambiguous", check.Name)
		}
		if check.HeadSHA != head || check.App.ID != required.AppID || check.App.NodeID != required.AppNodeID || check.App.Slug != required.AppSlug || check.CheckSuite.ID < 1 || check.Status != "completed" || check.Conclusion != "success" || check.CompletedAt.IsZero() || check.CompletedAt.After(mergedAt) {
			return nil, nil, fmt.Errorf("required check %q identity, suite, or result is invalid", check.Name)
		}
		runID, err := actionRunID(check.DetailsURL)
		if err != nil {
			return nil, nil, err
		}
		var run workflowRun
		if err := client.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d", client.repository, runID), &run); err != nil {
			return nil, nil, err
		}
		if run.ID != runID || run.RunAttempt != 1 || run.HeadSHA != head || run.WorkflowID != required.WorkflowID || run.Event != required.Event || run.Status != "completed" || run.Conclusion != "success" || run.UpdatedAt.IsZero() || run.UpdatedAt.After(mergedAt) {
			return nil, nil, fmt.Errorf("required check %q workflow run is stale, rerun, or substituted", check.Name)
		}
		found[check.Name] = check.ID
		suites[check.Name] = check.CheckSuite.ID
	}
	if len(found) != len(want) || mergedAt.IsZero() {
		return nil, nil, errors.New("required exact-head check evidence is incomplete")
	}
	return found, suites, nil
}

func actionRunID(details string) (int64, error) {
	parsed, err := url.Parse(details)
	if err != nil {
		return 0, err
	}
	if parsed.Scheme != "https" || parsed.Host != "github.com" {
		return 0, errors.New("check details URL is not canonical GitHub HTTPS")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index := range parts {
		if parts[index] == "runs" && index+1 < len(parts) {
			id, err := strconv.ParseInt(parts[index+1], 10, 64)
			if err == nil && id > 0 {
				return id, nil
			}
		}
	}
	return 0, errors.New("check details URL has no canonical Actions run ID")
}

func readSignedCommit(ctx context.Context, root, sha string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/git", "cat-file", "commit", sha)
	command.Dir = root
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_COUNT=0", "GIT_NO_REPLACE_OBJECTS=1"}
	raw, err := command.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("read integration commit object: %w", err)
	}
	return splitCommitSignature(raw)
}

func splitCommitSignature(raw []byte) ([]byte, []byte, error) {
	lines := bytes.SplitAfter(raw, []byte("\n"))
	var payload, signature bytes.Buffer
	inSignature := false
	found := false
	for _, framed := range lines {
		line := bytes.TrimSuffix(framed, []byte("\n"))
		if len(framed) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("gpgsig ")) {
			if found {
				return nil, nil, errors.New("commit contains multiple signatures")
			}
			found, inSignature = true, true
			signature.Write(bytes.TrimPrefix(line, []byte("gpgsig ")))
			if bytes.HasSuffix(framed, []byte("\n")) {
				signature.WriteByte('\n')
			}
			continue
		}
		if inSignature && len(line) > 0 && line[0] == ' ' {
			signature.Write(line[1:])
			if bytes.HasSuffix(framed, []byte("\n")) {
				signature.WriteByte('\n')
			}
			continue
		}
		inSignature = false
		payload.Write(framed)
	}
	if !found || !bytes.HasPrefix(signature.Bytes(), []byte("-----BEGIN PGP SIGNATURE-----\n")) {
		return nil, nil, errors.New("integration commit must contain exactly one OpenPGP signature")
	}
	return payload.Bytes(), signature.Bytes(), nil
}

func verifyOpenPGP(root string, contract Contract, payload, signature []byte, at time.Time) error {
	keyPath := filepath.Join(root, contract.IntegrationOpenPGPKey)
	before, err := os.Lstat(keyPath)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return errors.New("integration OpenPGP trust file type or mode is unsafe")
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	after, err := os.Lstat(keyPath)
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return errors.New("integration OpenPGP trust file changed during verification")
	}
	digest := sha256.Sum256(keyData)
	if hex.EncodeToString(digest[:]) != contract.IntegrationOpenPGPSHA256 || contract.IntegrationOpenPGPStatus != "active" {
		return errors.New("integration OpenPGP trust data or status differs from reviewed contract")
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil || len(keyring) != 1 {
		return errors.New("integration OpenPGP trust must contain exactly one valid public entity")
	}
	entity := keyring[0]
	fingerprint := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	if fingerprint != contract.IntegrationOpenPGPFingerprint {
		return errors.New("integration OpenPGP fingerprint differs from contract")
	}
	if entity.PrivateKey != nil || entity.Revoked(at) {
		return errors.New("integration OpenPGP key is private or revoked")
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(payload), bytes.NewReader(signature), nil)
	if err != nil {
		return fmt.Errorf("verify native integration OpenPGP signature: %w", err)
	}
	if signer != entity {
		return errors.New("integration signature used an uncontracted OpenPGP entity")
	}
	return nil
}

func (client githubClient) get(ctx context.Context, path string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.base+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("GitHub API GET %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIBytes))
		return fmt.Errorf("GitHub API GET %s returned %s", path, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil {
		return fmt.Errorf("read GitHub API %s: %w", path, err)
	}
	if len(data) > maxAPIBytes {
		return errors.New("GitHub API response exceeds the byte bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode GitHub API %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("GitHub API returned trailing or oversized JSON")
	}
	return nil
}
