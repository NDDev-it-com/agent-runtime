// SPDX-License-Identifier: AGPL-3.0-only

package signatureverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalTrustAnchorIdentity(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", AllowedSignersPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustAnchor(data); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignedCommitAndTagWithRepositoryTrust(t *testing.T) {
	t.Parallel()
	fixture := newSignedRepository(t)
	runGit(t, fixture.repository, "config", "gpg.format", "openpgp")
	runGit(t, fixture.repository, "config", "gpg.ssh.allowedSignersFile", filepath.Join(t.TempDir(), "ambient-attacker-signers"))
	for name, request := range map[string]Request{
		"commit": {Repository: fixture.repository, Kind: Commit, ObjectSHA: fixture.commit},
		"tag":    {Repository: fixture.repository, Kind: Tag, ObjectSHA: fixture.tag, ExpectedCommit: fixture.commit},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			request.Stdout, request.Stderr = &stdout, &stderr
			result, err := verifyWithPolicy(context.Background(), request, execRunner{}, fixture.policy(t))
			if err != nil {
				t.Fatalf("verify: %v\nstdout=%s\nstderr=%s", err, stdout.Bytes(), stderr.Bytes())
			}
			if result.Principal != fixture.principal || result.Fingerprint == "" || result.CommitSHA != fixture.commit {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestVerifyFailsClosedOnTrustAndIdentityDrift(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*testing.T, signedRepository) Request{
		"wrong exact SHA": func(_ *testing.T, f signedRepository) Request {
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: strings.Repeat("0", 40)}
		},
		"wrong tag commit": func(_ *testing.T, f signedRepository) Request {
			return Request{Repository: f.repository, Kind: Tag, ObjectSHA: f.tag, ExpectedCommit: strings.Repeat("0", 40)}
		},
		"wrong principal": func(t *testing.T, f signedRepository) Request {
			writeAllowlist(t, f.repository, "other@example.com", f.publicKey)
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: f.commit}
		},
		"wrong key": func(t *testing.T, f signedRepository) Request {
			other := generateKey(t, t.TempDir(), "other")
			writeAllowlist(t, f.repository, f.principal, readPublicKey(t, other+".pub"))
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: f.commit}
		},
		"malformed allowlist": func(t *testing.T, f signedRepository) Request {
			writeRaw(t, filepath.Join(f.repository, AllowedSignersPath), []byte("not an allowed signer\n"))
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: f.commit}
		},
		"missing allowlist": func(t *testing.T, f signedRepository) Request {
			if err := os.Remove(filepath.Join(f.repository, AllowedSignersPath)); err != nil {
				t.Fatal(err)
			}
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: f.commit}
		},
		"symlink allowlist": func(t *testing.T, f signedRepository) Request {
			path := filepath.Join(f.repository, AllowedSignersPath)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "signers")
			writeRaw(t, target, []byte(f.principal+" "+f.publicKey+"\n"))
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: f.commit}
		},
		"unsigned commit": func(t *testing.T, f signedRepository) Request {
			writeRaw(t, filepath.Join(f.repository, "unsigned"), []byte("unsigned\n"))
			runGit(t, f.repository, "add", "unsigned")
			runGit(t, f.repository, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "commit", "--no-gpg-sign", "-m", "unsigned")
			return Request{Repository: f.repository, Kind: Commit, ObjectSHA: strings.TrimSpace(runGit(t, f.repository, "rev-parse", "HEAD"))}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newSignedRepository(t)
			request := mutate(t, fixture)
			request.Stdout, request.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
			if _, err := verifyWithPolicy(context.Background(), request, execRunner{}, fixture.policy(t)); err == nil {
				t.Fatal("invalid signature or trust state accepted")
			}
		})
	}
}

func TestVerifierUsesCommandLocalTrustAndPreservesCommandFailure(t *testing.T) {
	t.Parallel()
	fixture := newSignedRepository(t)
	rootFailure := errors.New("Git unavailable")
	commands := &recordingRunner{failureAt: 3, failure: rootFailure, trackedTrust: []byte(fixture.principal + " " + fixture.publicKey + "\n")}
	var stdout, stderr bytes.Buffer
	_, err := verifyWithPolicy(context.Background(), Request{Repository: fixture.repository, Kind: Commit, ObjectSHA: fixture.commit, Stdout: &stdout, Stderr: &stderr}, commands, fixture.policy(t))
	if !errors.Is(err, rootFailure) {
		t.Fatalf("root command failure lost: %v", err)
	}
	if stdout.String() != "stdout evidence\n" || stderr.String() != "stderr evidence\n" {
		t.Fatalf("command diagnostics changed: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if len(commands.calls) != 3 {
		t.Fatalf("calls=%d", len(commands.calls))
	}
	verifyCall := commands.calls[2]
	joined := strings.Join(verifyCall.args, " ")
	if !strings.Contains(joined, "-c gpg.format=ssh -c gpg.ssh.allowedSignersFile=") ||
		!strings.Contains(joined, "-c gpg.ssh.program="+sshKeygenExecutable) ||
		!strings.Contains(joined, "-c gpg.ssh.revocationFile="+os.DevNull) ||
		!strings.Contains(joined, "-c gpg.minTrustLevel=fully") ||
		strings.Contains(joined, filepath.Join(fixture.repository, AllowedSignersPath)) {
		t.Fatalf("verification did not use isolated command-local trust: %q", joined)
	}
	for _, environment := range verifyCall.env {
		if environment == "GIT_CONFIG_GLOBAL="+os.DevNull || environment == "GIT_CONFIG_COUNT=0" || environment == "GIT_CONFIG_NOSYSTEM=1" {
			continue
		}
		if strings.HasPrefix(environment, "GIT_CONFIG_") {
			t.Fatalf("ambient Git config variable survived: %q", environment)
		}
	}
}

func TestVerifierFailsClosedWhenDiagnosticOutputCannotBePreserved(t *testing.T) {
	t.Parallel()
	fixture := newSignedRepository(t)
	outputFailure := errors.New("diagnostic writer failed")
	request := Request{
		Repository: fixture.repository,
		Kind:       Commit,
		ObjectSHA:  fixture.commit,
		Stdout:     io.Discard,
		Stderr:     failingWriter{err: outputFailure},
	}
	_, err := verifyWithPolicy(context.Background(), request, execRunner{}, fixture.policy(t))
	if !errors.Is(err, outputFailure) {
		t.Fatalf("diagnostic writer failure was lost: %v", err)
	}
}

func TestIsolatedGitEnvironmentRejectsAmbientOverrideChannels(t *testing.T) {
	for _, variable := range []string{
		"GIT_CONFIG_PARAMETERS", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_DIR", "GIT_WORK_TREE",
		"GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CEILING_DIRECTORIES",
		"GIT_SSH", "GIT_SSH_COMMAND", "GIT_EDITOR", "GIT_PAGER", "PAGER", "LC_ALL", "LANG",
	} {
		t.Setenv(variable, "attacker-controlled")
	}
	environment := isolatedGitEnvironment()
	joined := "\n" + strings.Join(environment, "\n") + "\n"
	for _, forbidden := range []string{
		"GIT_CONFIG_PARAMETERS=", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "GIT_DIR=", "GIT_WORK_TREE=",
		"GIT_INDEX_FILE=", "GIT_OBJECT_DIRECTORY=", "GIT_ALTERNATE_OBJECT_DIRECTORIES=", "GIT_CEILING_DIRECTORIES=",
		"GIT_SSH=", "GIT_SSH_COMMAND=", "GIT_EDITOR=",
	} {
		if strings.Contains(joined, "\n"+forbidden) {
			t.Fatalf("ambient override survived: %s", forbidden)
		}
	}
	for _, required := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_COUNT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_PAGER=cat", "PAGER=cat", "LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"} {
		if !strings.Contains(joined, "\n"+required+"\n") {
			t.Fatalf("missing isolated environment setting %q: %q", required, environment)
		}
	}
}

func TestVerificationStatusParserRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	valid := "Good \"git\" signature for fixture@example.com with ED25519 key SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, _, err := parseVerificationOutput([]byte(valid + "\n")); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "localized status", valid + "\nwarning", "Good signature"} {
		if _, _, _, err := parseVerificationOutput([]byte(invalid)); err == nil {
			t.Fatalf("ambiguous status accepted: %q", invalid)
		}
	}
}

func TestRepositorySurfacesUseOnlyCanonicalSignatureVerifier(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	surfaces := map[string]struct {
		path     string
		required []string
		count    int
	}{
		"CI": {
			path: filepath.Join(root, ".github", "workflows", "ci.yml"),
			required: []string{
				`go run ./cmd/check-signature --commit "$EXPECTED_COMMIT"`,
				`${{ github.event.pull_request.head.sha || github.sha }}`,
				"fetch-depth: 0",
			},
			count: 1,
		},
		"release": {
			path: filepath.Join(root, ".github", "workflows", "release.yml"),
			required: []string{
				`go run ./cmd/check-signature --tag "$tag_object" --expected-commit "$tag_commit"`,
				`tag_object="$(git rev-parse "$RELEASE_TAG^{tag}")"`,
			},
			count: 1,
		},
		"docs": {
			path: filepath.Join(root, "docs", "releasing.md"),
			required: []string{
				"go run ./cmd/check-signature --commit",
				"go run ./cmd/check-signature --tag",
			},
			count: 2,
		},
	}
	for name, surface := range surfaces {
		data, err := os.ReadFile(surface.path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Count(text, "go run ./cmd/check-signature") != surface.count {
			t.Errorf("%s canonical verifier count drifted", name)
		}
		for _, required := range surface.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing canonical verifier token %q", name, required)
			}
		}
		if strings.Contains(text, "git config gpg.ssh") || strings.Contains(text, "git verify-commit") || strings.Contains(text, "git verify-tag") {
			t.Errorf("%s contains an ambient/direct signature verification fork", name)
		}
	}
}

func TestTrustAnchorParserIsStrictAndDeterministic(t *testing.T) {
	t.Parallel()
	fixture := newSignedRepository(t)
	valid := []byte(fixture.principal + " " + fixture.publicKey + "\n")
	first, err := parseTrustAnchor(valid)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseTrustAnchor(valid)
	if err != nil {
		t.Fatal(err)
	}
	if first.fingerprint != second.fingerprint || !strings.HasPrefix(first.fingerprint, "SHA256:") {
		t.Fatal("fingerprint is not deterministic")
	}
	for name, value := range map[string][]byte{"empty": {}, "no newline": bytes.TrimSuffix(valid, []byte("\n")), "two records": append(valid, valid...), "options": []byte("cert-authority " + string(valid)), "unknown key": []byte(fixture.principal + " ssh-rsa AAAA\n")} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTrustAnchor(value); err == nil {
				t.Fatal("malformed trust anchor accepted")
			}
		})
	}
}

type signedRepository struct{ repository, principal, publicKey, commit, tag string }

func (fixture signedRepository) policy(t *testing.T) trustPolicy {
	t.Helper()
	anchor, err := parseTrustAnchor([]byte(fixture.principal + " " + fixture.publicKey + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return trustPolicy{principal: anchor.principal, keyType: anchor.keyType, fingerprint: anchor.fingerprint}
}

func newSignedRepository(t *testing.T) signedRepository {
	t.Helper()
	root := t.TempDir()
	return newSignedRepositoryIn(t, root, "repository")
}

func newSignedRepositoryIn(t *testing.T, root, name string) signedRepository {
	t.Helper()
	repository := filepath.Join(root, name)
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	key := generateKey(t, root, name+"-signing-key")
	publicKey := readPublicKey(t, key+".pub")
	principal := "fixture@example.com"
	runGit(t, repository, "init", "-q")
	writeAllowlist(t, repository, principal, publicKey)
	writeRaw(t, filepath.Join(repository, "content"), []byte("signed\n"))
	runGit(t, repository, "add", ".")
	runGit(t, repository, "-c", "user.name=Fixture", "-c", "user.email="+principal, "-c", "gpg.format=ssh", "-c", "user.signingKey="+key, "commit", "-S", "-m", "signed fixture")
	commit := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD"))
	runGit(t, repository, "-c", "user.name=Fixture", "-c", "user.email="+principal, "-c", "gpg.format=ssh", "-c", "user.signingKey="+key, "tag", "-s", "v0.0.1", "-m", "signed fixture tag")
	tag := strings.TrimSpace(runGit(t, repository, "rev-parse", "v0.0.1^{tag}"))
	return signedRepository{repository, principal, publicKey, commit, tag}
}

func generateKey(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate ephemeral test key: %v: %s", err, output)
	}
	return path
}
func readPublicKey(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatal("generated public key is malformed")
	}
	return fields[0] + " " + fields[1]
}
func writeAllowlist(t *testing.T, repository, principal, publicKey string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repository, ".github"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, filepath.Join(repository, AllowedSignersPath), []byte(principal+" "+publicKey+"\n"))
}
func writeRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func runGit(t *testing.T, repository string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = repository
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

type recordedCall struct{ args, env []string }
type recordingRunner struct {
	calls        []recordedCall
	failureAt    int
	failure      error
	trackedTrust []byte
}

func (r *recordingRunner) run(_ context.Context, _ string, args []string, _ string, environment []string) ([]byte, []byte, error) {
	r.calls = append(r.calls, recordedCall{append([]string(nil), args...), append([]string(nil), environment...)})
	if len(r.calls) == r.failureAt {
		return []byte("stdout evidence\n"), []byte("stderr evidence\n"), r.failure
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, " cat-file -t ") {
		return []byte("commit\n"), nil, nil
	}
	if strings.Contains(joined, " show ") {
		return append([]byte(nil), r.trackedTrust...), nil, nil
	}
	return nil, nil, fmt.Errorf("unexpected call %q", args)
}

type failingWriter struct {
	err error
}

func (writer failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}
