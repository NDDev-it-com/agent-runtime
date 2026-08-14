// SPDX-License-Identifier: AGPL-3.0-only

// Package signatureverify verifies Git SSH signatures against the repository trust anchor.
package signatureverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	AllowedSignersPath   = ".github/release-allowed-signers"
	gitExecutable        = "/usr/bin/git"
	sshKeygenExecutable  = "/usr/bin/ssh-keygen"
	maxAllowlistBytes    = 16 << 10
	CanonicalPrincipal   = "danilsilantyevwork@gmail.com"
	CanonicalFingerprint = "SHA256:3L6V7EKdHGQyLcr4NPsFC86EYbi3/7f2X6kMni7LmNI"
)

var (
	fullSHA           = regexp.MustCompile(`^[0-9a-f]{40}$`)
	principalPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]{0,253}$`)
	verificationLine  = regexp.MustCompile(`^Good "git" signature for ([^ ]+) with ([A-Z0-9-]+) key (SHA256:[A-Za-z0-9+/]+={0,2})$`)
	supportedKeyTypes = map[string]string{"ssh-ed25519": "ED25519", "ecdsa-sha2-nistp256": "ECDSA"}
)

type Kind string

const (
	Commit Kind = "commit"
	Tag    Kind = "tag"
)

type Request struct {
	Repository     string
	Kind           Kind
	ObjectSHA      string
	ExpectedCommit string
	Stdout         io.Writer
	Stderr         io.Writer
}

type Result struct {
	ObjectSHA   string
	CommitSHA   string
	Principal   string
	Fingerprint string
}

type trustAnchor struct {
	contents    []byte
	principal   string
	keyType     string
	fingerprint string
}

type trustPolicy struct {
	principal   string
	keyType     string
	fingerprint string
}

var canonicalTrustPolicy = trustPolicy{
	principal: CanonicalPrincipal, keyType: "ED25519", fingerprint: CanonicalFingerprint,
}

type runner interface {
	run(context.Context, string, []string, string, []string) ([]byte, []byte, error)
}

type verifyOptions struct {
	commands     runner
	snapshot     snapshotOperations
	beforeVerify func(string) error
}

type execRunner struct{}

func (execRunner) run(ctx context.Context, path string, args []string, dir string, env []string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Dir = dir
	command.Env = env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func Verify(ctx context.Context, request Request) (Result, error) {
	return verifyWithOptions(ctx, request, canonicalTrustPolicy, verifyOptions{commands: execRunner{}, snapshot: defaultSnapshotOperations()})
}

func verifyWithPolicy(ctx context.Context, request Request, commands runner, policy trustPolicy) (Result, error) {
	return verifyWithOptions(ctx, request, policy, verifyOptions{commands: commands, snapshot: defaultSnapshotOperations()})
}

func verifyWithOptions(ctx context.Context, request Request, policy trustPolicy, options verifyOptions) (result Result, rootErr error) {
	if !fullSHA.MatchString(request.ObjectSHA) {
		return Result{}, errors.New("signature verification requires an exact lowercase 40-hex object SHA")
	}
	if request.Kind != Commit && request.Kind != Tag {
		return Result{}, fmt.Errorf("unsupported signed object kind %q", request.Kind)
	}
	if request.Kind == Tag && !fullSHA.MatchString(request.ExpectedCommit) {
		return Result{}, errors.New("tag verification requires an exact expected commit SHA")
	}
	if request.Kind == Commit && request.ExpectedCommit != "" && request.ExpectedCommit != request.ObjectSHA {
		return Result{}, errors.New("commit object SHA differs from expected commit SHA")
	}
	if request.Stdout == nil || request.Stderr == nil {
		return Result{}, errors.New("signature verification output writers are required")
	}
	root, err := canonicalRepositoryRoot(request.Repository)
	if err != nil {
		return Result{}, err
	}
	repository, err := captureRepositoryIdentity(root)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		rootErr = errors.Join(rootErr, repository.close())
		if rootErr != nil {
			result = Result{}
		}
	}()
	commands := identityBoundRunner{delegate: options.commands, repository: repository}
	anchor, err := loadTrustAnchor(root)
	if err != nil {
		return Result{}, err
	}
	if anchor.principal != policy.principal || anchor.keyType != policy.keyType || anchor.fingerprint != policy.fingerprint {
		return Result{}, errors.New("repository allowed signers differs from the canonical principal and public-key fingerprint")
	}
	snapshot, err := createTrustSnapshot(anchor.contents, options.snapshot)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		rootErr = errors.Join(rootErr, snapshot.cleanup())
		if rootErr != nil {
			result = Result{}
		}
	}()

	objectType, err := gitOutput(ctx, commands, root, []string{"cat-file", "-t", request.ObjectSHA}, request.Stdout, request.Stderr)
	if err != nil {
		return Result{}, fmt.Errorf("resolve signed object type: %w", err)
	}
	if strings.TrimSpace(string(objectType)) != string(request.Kind) {
		return Result{}, fmt.Errorf("object %s has type %q, want %q", request.ObjectSHA, strings.TrimSpace(string(objectType)), request.Kind)
	}
	commitForTrust := request.ObjectSHA
	if request.Kind == Tag {
		commitForTrust = request.ExpectedCommit
	}
	trackedTrust, err := gitOutput(ctx, commands, root, []string{"show", commitForTrust + ":" + AllowedSignersPath}, request.Stdout, request.Stderr)
	if err != nil {
		return Result{}, fmt.Errorf("read signed commit trust anchor: %w", err)
	}
	if !bytes.Equal(trackedTrust, anchor.contents) {
		return Result{}, errors.New("working trust anchor differs from the exact signed commit")
	}
	if err := snapshot.revalidate(); err != nil {
		return Result{}, err
	}
	if options.beforeVerify != nil {
		if err := options.beforeVerify(snapshot.path); err != nil {
			return Result{}, fmt.Errorf("before signature verification: %w", err)
		}
	}
	if err := snapshot.revalidate(); err != nil {
		return Result{}, err
	}
	verifyArgs := []string{
		"-c", "gpg.format=ssh",
		"-c", "gpg.ssh.allowedSignersFile=" + snapshot.path,
		"-c", "gpg.ssh.program=" + sshKeygenExecutable,
		"-c", "gpg.ssh.revocationFile=" + os.DevNull,
		"-c", "gpg.minTrustLevel=fully",
		"verify-" + string(request.Kind), "--raw", request.ObjectSHA,
	}
	stdout, stderr, runErr := commands.run(ctx, "git", verifyArgs, root, isolatedGitEnvironment())
	stdoutErr := writeEvidence(request.Stdout, stdout, "signature verifier stdout")
	stderrErr := writeEvidence(request.Stderr, stderr, "signature verifier stderr")
	if err := errors.Join(runErr, stdoutErr, stderrErr); err != nil {
		return Result{}, fmt.Errorf("verify %s SSH signature: %w", request.Kind, err)
	}
	if err := snapshot.revalidate(); err != nil {
		return Result{}, err
	}
	principal, keyType, fingerprint, err := parseVerificationOutput(stderr)
	if err != nil {
		return Result{}, err
	}
	if principal != anchor.principal || keyType != anchor.keyType || fingerprint != anchor.fingerprint {
		return Result{}, fmt.Errorf("verified signer differs from repository trust anchor: principal=%q key_type=%q fingerprint=%q", principal, keyType, fingerprint)
	}
	commitSHA := request.ObjectSHA
	if request.Kind == Tag {
		peeled, peelErr := gitOutput(ctx, commands, root, []string{"rev-parse", request.ObjectSHA + "^{commit}"}, request.Stdout, request.Stderr)
		if peelErr != nil {
			return Result{}, fmt.Errorf("peel signed tag commit: %w", peelErr)
		}
		commitSHA = strings.TrimSpace(string(peeled))
		if commitSHA != request.ExpectedCommit {
			return Result{}, fmt.Errorf("signed tag commit %s differs from expected %s", commitSHA, request.ExpectedCommit)
		}
	}
	return Result{ObjectSHA: request.ObjectSHA, CommitSHA: commitSHA, Principal: principal, Fingerprint: fingerprint}, nil
}

func canonicalRepositoryRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("repository root is empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	clean := filepath.Clean(abs)
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("inspect repository root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("repository root must be a non-symlink directory")
	}
	return clean, nil
}

func loadTrustAnchor(root string) (anchor trustAnchor, rootErr error) {
	githubDirectory := filepath.Join(root, ".github")
	parent, err := os.Lstat(githubDirectory)
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return trustAnchor{}, errors.New("repository .github trust directory must be a non-symlink directory")
	}
	path := filepath.Join(githubDirectory, "release-allowed-signers")
	before, err := os.Lstat(path)
	if err != nil {
		return trustAnchor{}, fmt.Errorf("inspect repository allowed signers: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maxAllowlistBytes {
		return trustAnchor{}, errors.New("repository allowed signers must be a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return trustAnchor{}, fmt.Errorf("open repository allowed signers: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			rootErr = errors.Join(rootErr, fmt.Errorf("close repository allowed signers: %w", err))
		}
	}()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return trustAnchor{}, errors.New("repository allowed signers identity changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxAllowlistBytes+1))
	if err != nil || len(contents) > maxAllowlistBytes {
		return trustAnchor{}, errors.New("read bounded repository allowed signers")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Mode()&os.ModeSymlink != 0 {
		return trustAnchor{}, errors.New("repository allowed signers identity changed while reading")
	}
	return parseTrustAnchor(contents)
}

func parseTrustAnchor(contents []byte) (trustAnchor, error) {
	if len(contents) == 0 || !bytes.HasSuffix(contents, []byte("\n")) || bytes.ContainsRune(contents, 0) {
		return trustAnchor{}, errors.New("allowed signers must be one newline-terminated text record")
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) != 1 {
		return trustAnchor{}, errors.New("allowed signers must contain exactly one record")
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 3 || !principalPattern.MatchString(fields[0]) {
		return trustAnchor{}, errors.New("allowed signer record has an invalid principal or shape")
	}
	wantKeyType, ok := supportedKeyTypes[fields[1]]
	if !ok {
		return trustAnchor{}, fmt.Errorf("unsupported allowed signer key type %q", fields[1])
	}
	keyBlob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(keyBlob) < 16 || base64.StdEncoding.EncodeToString(keyBlob) != fields[2] {
		return trustAnchor{}, errors.New("allowed signer public key is not canonical base64")
	}
	if len(keyBlob) < 4 {
		return trustAnchor{}, errors.New("allowed signer public key blob is truncated")
	}
	keyTypeLength := int(keyBlob[0])<<24 | int(keyBlob[1])<<16 | int(keyBlob[2])<<8 | int(keyBlob[3])
	if keyTypeLength < 1 || 4+keyTypeLength > len(keyBlob) || string(keyBlob[4:4+keyTypeLength]) != fields[1] {
		return trustAnchor{}, errors.New("allowed signer public key blob type differs from its record")
	}
	digest := sha256.Sum256(keyBlob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	return trustAnchor{contents: append([]byte(nil), contents...), principal: fields[0], keyType: wantKeyType, fingerprint: fingerprint}, nil
}

// ValidateTrustAnchor verifies the canonical repository signer record.
func ValidateTrustAnchor(contents []byte) error {
	anchor, err := parseTrustAnchor(contents)
	if err != nil {
		return err
	}
	if anchor.principal != canonicalTrustPolicy.principal || anchor.keyType != canonicalTrustPolicy.keyType || anchor.fingerprint != canonicalTrustPolicy.fingerprint {
		return errors.New("allowed signers differs from the canonical principal and public-key fingerprint")
	}
	return nil
}

func parseVerificationOutput(stderr []byte) (string, string, string, error) {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	if len(lines) != 1 {
		return "", "", "", errors.New("Git signature status must contain exactly one canonical line")
	}
	match := verificationLine.FindStringSubmatch(lines[0])
	if match == nil {
		return "", "", "", fmt.Errorf("Git did not emit a canonical good SSH signature status: %q", lines[0])
	}
	return match[1], match[2], match[3], nil
}

func gitOutput(ctx context.Context, commands runner, root string, args []string, stdout, stderr io.Writer) ([]byte, error) {
	out, diagnostic, err := commands.run(ctx, "git", args, root, isolatedGitEnvironment())
	diagnosticErr := writeEvidence(stderr, diagnostic, "Git diagnostic output")
	if err != nil {
		stdoutErr := writeEvidence(stdout, out, "Git stdout")
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), errors.Join(err, diagnosticErr, stdoutErr))
	}
	if diagnosticErr != nil {
		return nil, diagnosticErr
	}
	return out, nil
}

func writeEvidence(writer io.Writer, data []byte, description string) error {
	if len(data) == 0 {
		return nil
	}
	written, err := writer.Write(data)
	if err != nil {
		return fmt.Errorf("write %s: %w", description, err)
	}
	if written != len(data) {
		return fmt.Errorf("write %s: %w", description, io.ErrShortWrite)
	}
	return nil
}

func isolatedGitEnvironment() []string {
	environment := []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_COUNT=0",
		"GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_PAGER=cat", "PAGER=cat", "LC_ALL=C", "LANG=C",
		"PATH=/usr/bin:/bin",
	}
	return environment
}
