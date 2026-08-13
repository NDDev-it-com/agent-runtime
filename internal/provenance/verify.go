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
	"sort"
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
	ID     int64  `json:"id"`
	NodeID string `json:"node_id"`
	Number int    `json:"number"`
	State  string `json:"state"`
	Merged bool   `json:"merged"`
	// MergeCommitSHA is retained as diagnostic REST evidence only. GitHub
	// documents its value as state- and merge-method-dependent; attribution is
	// instead bound by the GraphQL merged relation and REST/local commit object.
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
	Author       apiGitIdentity  `json:"author"`
	Committer    apiGitIdentity  `json:"committer"`
	Tree         apiRef          `json:"tree"`
	Verification apiVerification `json:"verification"`
}
type apiGitIdentity struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
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

type graphPullResponse struct {
	Data struct {
		Repository struct {
			ID         string `json:"id"`
			DatabaseID int64  `json:"databaseId"`
			Pull       struct {
				ID         string    `json:"id"`
				DatabaseID int64     `json:"databaseId"`
				Number     int       `json:"number"`
				State      string    `json:"state"`
				Merged     bool      `json:"merged"`
				MergedAt   time.Time `json:"mergedAt"`
				BaseRef    string    `json:"baseRefName"`
				BaseOID    string    `json:"baseRefOid"`
				HeadRef    string    `json:"headRefName"`
				HeadOID    string    `json:"headRefOid"`
				MergedBy   struct {
					Login      string `json:"login"`
					ID         string `json:"id"`
					DatabaseID int64  `json:"databaseId"`
				} `json:"mergedBy"`
				MergeCommit struct {
					OID  string `json:"oid"`
					Tree struct {
						OID string `json:"oid"`
					} `json:"tree"`
					Parents struct {
						Nodes []struct {
							OID string `json:"oid"`
						} `json:"nodes"`
					} `json:"parents"`
				} `json:"mergeCommit"`
			} `json:"pullRequest"`
		} `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
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
	pull, graph, err := selectIntegrationPull(ctx, client, request)
	if err != nil {
		return Result{}, err
	}
	var integration commitResponse
	if err := client.get(ctx, "/repos/"+client.repository+"/commits/"+request.CommitSHA, &integration); err != nil {
		return Result{}, err
	}
	if err := validateIntegrationIdentity(request.Contract, pull, graph, integration); err != nil {
		return Result{}, err
	}
	localPayload, localSignature, err := readSignedCommit(ctx, root, request.CommitSHA)
	if err != nil {
		return Result{}, err
	}
	if err := verifyIntegrationSignatureEvidence(root, request.Contract, integration.Commit.Verification, localPayload, localSignature, pull.MergedAt); err != nil {
		return Result{}, err
	}
	if err := validateLocalCommitIdentity(localPayload, integration); err != nil {
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

func verifyIntegrationSignatureEvidence(root string, contract Contract, verification apiVerification, localPayload, localSignature []byte, mergedAt time.Time) error {
	if !verification.Verified || verification.Reason != "valid" || verification.VerifiedAt.IsZero() || verification.VerifiedAt.Before(mergedAt) {
		return errors.New("integration signature API evidence is absent, partial, stale, or invalid")
	}
	providerPayload := []byte(verification.Payload)
	providerSignature := []byte(verification.Signature)
	if len(providerPayload) == 0 || len(providerPayload) > maxAPIBytes || len(providerSignature) == 0 || len(providerSignature) > 64<<10 {
		return errors.New("integration signature API payload is missing or unbounded")
	}
	if !bytes.Equal(localPayload, providerPayload) {
		return errors.New("GitHub signed payload differs from the normative local commit payload")
	}
	if err := verifyOpenPGP(root, contract, providerPayload, providerSignature, mergedAt); err != nil {
		return fmt.Errorf("verify provider integration signature evidence: %w", err)
	}
	if err := verifyOpenPGP(root, contract, localPayload, localSignature, mergedAt); err != nil {
		return fmt.Errorf("verify local integration signature embedding: %w", err)
	}
	return nil
}

func validateLocalCommitIdentity(payload []byte, commit commitResponse) error {
	headers, _, ok := bytes.Cut(payload, []byte("\n\n"))
	if !ok {
		return errors.New("local commit payload has no header/message boundary")
	}
	var tree string
	var parents []string
	var author, committer apiGitIdentity
	for _, line := range strings.Split(string(headers), "\n") {
		switch {
		case strings.HasPrefix(line, "tree "):
			tree = strings.TrimPrefix(line, "tree ")
		case strings.HasPrefix(line, "parent "):
			parents = append(parents, strings.TrimPrefix(line, "parent "))
		case strings.HasPrefix(line, "author "):
			var err error
			author, err = parseGitIdentity(strings.TrimPrefix(line, "author "))
			if err != nil {
				return err
			}
		case strings.HasPrefix(line, "committer "):
			var err error
			committer, err = parseGitIdentity(strings.TrimPrefix(line, "committer "))
			if err != nil {
				return err
			}
		}
	}
	if tree != commit.Commit.Tree.SHA || len(parents) != len(commit.Parents) {
		return errors.New("local commit tree or parent closure differs from REST")
	}
	for index := range parents {
		if parents[index] != commit.Parents[index].SHA {
			return errors.New("local commit parent order differs from REST")
		}
	}
	if !equalGitIdentity(author, commit.Commit.Author) || !equalGitIdentity(committer, commit.Commit.Committer) {
		return errors.New("local commit author or committer identity differs from REST")
	}
	return nil
}

func equalGitIdentity(a, b apiGitIdentity) bool {
	return a.Name == b.Name && a.Email == b.Email && !a.Date.IsZero() && a.Date.Equal(b.Date)
}

func parseGitIdentity(value string) (apiGitIdentity, error) {
	endEmail := strings.LastIndex(value, "> ")
	startEmail := strings.LastIndex(value[:maxInt(endEmail, 0)], " <")
	if endEmail < 0 || startEmail < 1 {
		return apiGitIdentity{}, errors.New("local commit identity is malformed")
	}
	fields := strings.Fields(value[endEmail+2:])
	if len(fields) != 2 || len(fields[1]) != 5 || (fields[1][0] != '+' && fields[1][0] != '-') {
		return apiGitIdentity{}, errors.New("local commit identity timestamp is malformed")
	}
	epoch, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return apiGitIdentity{}, errors.New("local commit identity epoch is malformed")
	}
	hours, errH := strconv.Atoi(fields[1][1:3])
	minutes, errM := strconv.Atoi(fields[1][3:5])
	if errH != nil || errM != nil || hours > 23 || minutes > 59 {
		return apiGitIdentity{}, errors.New("local commit identity timezone is malformed")
	}
	offset := (hours*60 + minutes) * 60
	if fields[1][0] == '-' {
		offset = -offset
	}
	return apiGitIdentity{Name: value[:startEmail], Email: value[startEmail+2 : endEmail], Date: time.Unix(epoch, 0).In(time.FixedZone("git", offset))}, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func validateIntegrationIdentity(contract Contract, pull pullResponse, graph graphPullResponse, commit commitResponse) error {
	if contract.MergeMethod != "merge" {
		return errors.New("integration contract does not require a two-parent merge")
	}
	if len(commit.Parents) != 2 || commit.Parents[0].SHA != pull.Base.SHA || commit.Parents[1].SHA != pull.Head.SHA || !fullSHA.MatchString(commit.Commit.Tree.SHA) {
		return errors.New("integration SHA, parent order, PR base/head, or tree identity differs")
	}
	relation := graph.Data.Repository.Pull.MergeCommit
	if relation.OID != commit.SHA || relation.Tree.OID != commit.Commit.Tree.SHA || len(relation.Parents.Nodes) != 2 || relation.Parents.Nodes[0].OID != commit.Parents[0].SHA || relation.Parents.Nodes[1].OID != commit.Parents[1].SHA {
		return errors.New("GraphQL PR integration relation differs from the REST and local commit graph")
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

func selectIntegrationPull(ctx context.Context, client githubClient, request VerifyRequest) (pullResponse, graphPullResponse, error) {
	candidates := []commitPull{{Number: request.PullRequest}}
	if request.PullRequest == 0 {
		if err := client.get(ctx, "/repos/"+client.repository+"/commits/"+request.CommitSHA+"/pulls", &candidates); err != nil {
			return pullResponse{}, graphPullResponse{}, err
		}
	}
	if len(candidates) == 0 || len(candidates) > 32 {
		return pullResponse{}, graphPullResponse{}, errors.New("integration PR candidate set is missing or exceeds the bound")
	}
	type match struct {
		pull  pullResponse
		graph graphPullResponse
	}
	matches := make([]match, 0, 1)
	rejections := make([]string, 0, len(candidates))
	seen := make(map[int]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Number < 1 {
			rejections = append(rejections, "invalid-number")
			continue
		}
		if _, duplicate := seen[candidate.Number]; duplicate {
			return pullResponse{}, graphPullResponse{}, fmt.Errorf("integration PR candidate %d is duplicated", candidate.Number)
		}
		seen[candidate.Number] = struct{}{}
		var pull pullResponse
		if err := client.get(ctx, fmt.Sprintf("/repos/%s/pulls/%d", client.repository, candidate.Number), &pull); err != nil {
			return pullResponse{}, graphPullResponse{}, err
		}
		candidateRequest := request
		candidateRequest.PullRequest = candidate.Number
		if err := validatePullIdentity(request.Contract, candidateRequest, pull); err != nil {
			rejections = append(rejections, fmt.Sprintf("pr-%d:%s", candidate.Number, err))
			continue
		}
		graph, err := client.graphPull(ctx, candidate.Number)
		if err != nil {
			return pullResponse{}, graphPullResponse{}, err
		}
		if err := validateGraphPullIdentity(request.Contract, candidateRequest, pull, graph); err != nil {
			rejections = append(rejections, fmt.Sprintf("pr-%d:%s", candidate.Number, err))
			continue
		}
		matches = append(matches, match{pull: pull, graph: graph})
	}
	if len(matches) != 1 {
		sort.Strings(rejections)
		return pullResponse{}, graphPullResponse{}, fmt.Errorf("integration commit has %d uniquely attributable PRs; candidates=%d rejections=%s", len(matches), len(candidates), strings.Join(rejections, ";"))
	}
	return matches[0].pull, matches[0].graph, nil
}

func validateGraphPullIdentity(contract Contract, request VerifyRequest, rest pullResponse, graph graphPullResponse) error {
	if len(graph.Errors) != 0 {
		return errors.New("GraphQL integration evidence contains errors")
	}
	repository := graph.Data.Repository
	pull := repository.Pull
	checks := []struct {
		valid bool
		field string
	}{
		{repository.ID == contract.RepositoryNodeID && repository.DatabaseID == contract.RepositoryDatabaseID, "repository"},
		{pull.ID == rest.NodeID && pull.DatabaseID == rest.ID && pull.Number == rest.Number, "pull_request.identity"},
		{pull.State == "MERGED" && pull.Merged && pull.MergedAt.Equal(rest.MergedAt), "pull_request.state"},
		{pull.MergedBy.Login == contract.OwnerLogin && pull.MergedBy.ID == contract.OwnerNodeID && pull.MergedBy.DatabaseID == contract.OwnerDatabaseID, "pull_request.merged_by"},
		{pull.BaseRef == rest.Base.Ref && pull.BaseOID == rest.Base.SHA, "pull_request.base"},
		{pull.HeadRef == rest.Head.Ref && pull.HeadOID == rest.Head.SHA, "pull_request.head"},
		{pull.MergeCommit.OID == request.CommitSHA, "pull_request.merge_commit"},
		{fullSHA.MatchString(pull.MergeCommit.Tree.OID), "pull_request.merge_tree"},
		{len(pull.MergeCommit.Parents.Nodes) == 2 && pull.MergeCommit.Parents.Nodes[0].OID == rest.Base.SHA && pull.MergeCommit.Parents.Nodes[1].OID == rest.Head.SHA, "pull_request.merge_parents"},
	}
	for _, check := range checks {
		if !check.valid {
			return fmt.Errorf("GraphQL integration provenance field %s is invalid", check.field)
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
			content := line[1:]
			if len(content) == 0 && bytes.HasSuffix(signature.Bytes(), []byte("-----END PGP SIGNATURE-----\n")) {
				inSignature = false
				continue
			}
			signature.Write(content)
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
	return client.doJSON(ctx, http.MethodGet, path, nil, output)
}

func (client githubClient) graphPull(ctx context.Context, number int) (graphPullResponse, error) {
	parts := strings.Split(client.repository, "/")
	if len(parts) != 2 || number < 1 {
		return graphPullResponse{}, errors.New("GraphQL PR request identity is invalid")
	}
	const query = `query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){id databaseId pullRequest(number:$number){id databaseId number state merged mergedAt baseRefName baseRefOid headRefName headRefOid mergedBy{login ... on User{id databaseId}} mergeCommit{oid tree{oid} parents(first:3){nodes{oid}}}}}}`
	body, err := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"owner": parts[0], "name": parts[1], "number": number}})
	if err != nil {
		return graphPullResponse{}, err
	}
	var response graphPullResponse
	if err := client.doJSON(ctx, http.MethodPost, "/graphql", bytes.NewReader(body), &response); err != nil {
		return graphPullResponse{}, err
	}
	return response, nil
}

func (client githubClient) doJSON(ctx context.Context, method, path string, body io.Reader, output any) error {
	request, err := http.NewRequestWithContext(ctx, method, client.base+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("GitHub API %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIBytes))
		return fmt.Errorf("GitHub API %s %s returned %s", method, path, response.Status)
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
