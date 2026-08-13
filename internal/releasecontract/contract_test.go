// SPDX-License-Identifier: AGPL-3.0-only

package releasecontract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRepositoryReleaseContract(t *testing.T) {
	t.Parallel()
	c, err := Load(filepath.Join("..", "..", "release", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyRepository(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
}

func TestContractRejectsSemanticDrift(t *testing.T) {
	t.Parallel()
	mutations := []func(*Contract){
		func(c *Contract) { c.SchemaVersion = "v2" }, func(c *Contract) { c.Version = "0.1.0" },
		func(c *Contract) { c.ModulePath = "example.invalid/fork" }, func(c *Contract) { c.GoCompatibility = "1.25" }, func(c *Contract) { c.License = "MIT" },
		func(c *Contract) { c.Assets.Archive = "binary.zip" }, func(c *Contract) { c.Limits.MaxFiles = 0 },
		func(c *Contract) { c.Dependencies = nil },
		func(c *Contract) { c.Dependencies = append(c.Dependencies, c.Dependencies[0]) },
		func(c *Contract) { c.Dependencies[0].ModulePath = "example.invalid/dependency" },
		func(c *Contract) { c.Dependencies[0].Version = "v0.39.0" },
		func(c *Contract) { c.Dependencies[0].License = "NOASSERTION" },
		func(c *Contract) { c.Actions.Checkout = "actions/checkout@v7" }, func(c *Contract) { c.Actions.Checkout = "evil/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" }, func(c *Contract) { c.Workflow = "other.yml" },
	}
	for i, mutate := range mutations {
		i, mutate := i, mutate
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			t.Parallel()
			c := testContract()
			mutate(&c)
			if c.Validate() == nil && c.verifyGoMod([]byte(canonicalGoMod(testContract()))) == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestSBOMRejectsDependencyAndRelationshipDrift(t *testing.T) {
	t.Parallel()
	c := testContract()
	files := []gitFile{{Mode: "100644", Path: "go.mod", Data: []byte("module " + c.ModulePath + "\n")}}
	stamp := time.Unix(1, 0).UTC()
	manifest := newManifest(c, strings.Repeat("a", 40), stamp, "https://example.invalid/sbom", nil)
	data, err := sbomBytes(files, c, manifest.SourceCommit, stamp, manifest.SBOMNamespace)
	if err != nil {
		t.Fatal(err)
	}
	var canonical spdxDocument
	if err := strictJSON(data, &canonical); err != nil {
		t.Fatal(err)
	}
	archiveFiles := map[string]string{"go.mod": digest("go.mod", files[0].Data).SHA256}
	mutations := []struct {
		name   string
		mutate func(*spdxDocument)
	}{
		{"missing dependency", func(doc *spdxDocument) { doc.Packages = doc.Packages[:1] }},
		{"extra dependency", func(doc *spdxDocument) { doc.Packages = append(doc.Packages, doc.Packages[1]) }},
		{"duplicate dependency", func(doc *spdxDocument) { doc.Packages[1] = doc.Packages[0] }},
		{"malformed purl", func(doc *spdxDocument) { doc.Packages[1].ExternalRefs[0].ReferenceLocator = "pkg:golang/invalid" }},
		{"malformed download", func(doc *spdxDocument) { doc.Packages[1].DownloadLocation = "https://example.invalid/module.zip" }},
		{"missing relationship", func(doc *spdxDocument) { doc.Relationships = doc.Relationships[:len(doc.Relationships)-1] }},
		{"duplicate relationship", func(doc *spdxDocument) {
			doc.Relationships = append(doc.Relationships, doc.Relationships[len(doc.Relationships)-1])
		}},
		{"reordered relationships", func(doc *spdxDocument) {
			doc.Relationships[0], doc.Relationships[1] = doc.Relationships[1], doc.Relationships[0]
		}},
		{"wrong relationship", func(doc *spdxDocument) { doc.Relationships[len(doc.Relationships)-1].RelationshipType = "CONTAINS" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			doc := canonical
			doc.Packages = append([]spdxPackage{}, canonical.Packages...)
			for index := range doc.Packages {
				doc.Packages[index].ExternalRefs = append([]externalRef{}, canonical.Packages[index].ExternalRefs...)
			}
			doc.Relationships = append([]relationship{}, canonical.Relationships...)
			tc.mutate(&doc)
			mutated, marshalErr := canonicalJSON(doc)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if verifySBOMBytes(mutated, c, manifest, archiveFiles) == nil {
				t.Fatal("invalid SBOM accepted")
			}
		})
	}
}

func TestContractJSONFailsClosed(t *testing.T) {
	t.Parallel()
	valid, err := json.Marshal(testContract())
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{
		{}, []byte("null"), []byte(`{"schema_version":"v1alpha1"}`),
		bytes.Replace(valid, []byte(`"max_files":4096`), []byte(`"max_files":"4096"`), 1),
		append(append([]byte(nil), valid...), []byte(` {}`)...),
		bytes.Replace(valid, []byte(`"schema_version":"v1alpha1"`), []byte(`"schema_version":"v1alpha1","unknown":true`), 1),
	}
	for i, input := range inputs {
		i, input := i, input
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), "contract.json")
			mustWrite(t, p, input)
			if _, err := Load(p); err == nil {
				t.Fatal("invalid contract JSON accepted")
			}
		})
	}
}

func TestGoModuleSemanticContractAcceptsCanonicalTidyAndRejectsDrift(t *testing.T) {
	t.Parallel()
	c := testContract()
	canonical := canonicalGoMod(c)
	reversed := append([]Dependency(nil), c.Dependencies...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	accepted := []string{canonical, strings.Replace(canonical, "go 1.24.0", "go 1.24", 1), goModFromDependencies(c, reversed)}
	for _, input := range accepted {
		if err := c.verifyGoMod([]byte(input)); err != nil {
			t.Fatalf("canonical module rejected: %v", err)
		}
	}
	mutations := []string{
		strings.Replace(canonical, c.ModulePath, "example.invalid/fork", 1),
		strings.Replace(canonical, "go 1.24.0", "go 1.25.0", 1),
		strings.Replace(canonical, "\tgolang.org/x/sys v0.40.0\n", "", 1),
		strings.Replace(canonical, ")\n", "\tgolang.org/x/text v0.1.0\n)\n", 1),
		strings.Replace(canonical, "golang.org/x/sys v0.40.0", "golang.org/x/sys v0.39.0", 1),
		canonical + "replace golang.org/x/sys => ../sys\n",
		canonical + "exclude golang.org/x/sys v0.40.0\n",
		canonical + "toolchain go1.24.1\n",
		canonical + "tool golang.org/x/mod/cmd/gofix\n",
	}
	for _, input := range mutations {
		if c.verifyGoMod([]byte(input)) == nil {
			t.Fatalf("semantic drift accepted:\n%s", input)
		}
	}
}

func TestGoSumSemanticContractRejectsClosureAndDigestDrift(t *testing.T) {
	t.Parallel()
	c := testContract()
	valid := canonicalGoSum(c)
	if err := c.verifyGoSum([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		strings.Replace(valid, strings.Split(valid, "\n")[0]+"\n", "", 1),
		valid + strings.Split(valid, "\n")[0] + "\n",
		strings.Replace(valid, "golang.org/x/sys", "example.invalid/sys", 1),
		strings.Replace(valid, "h1:AAAA", "h2:AAAA", 1),
		strings.Replace(valid, "h1:AAAA", "h1:not-base64", 1),
		strings.Replace(valid, "golang.org/x/mod v0.27.0", "golang.org/x/sys v0.40.0", 1),
	}
	for _, input := range invalid {
		if c.verifyGoSum([]byte(input)) == nil {
			t.Fatal("invalid go.sum accepted")
		}
	}
}

func TestDependencyDownloadIdentityUsesGoProxyEscaping(t *testing.T) {
	t.Parallel()
	dependency := testContract().Dependencies[0]
	got := newDependencySPDXPackage(dependency, 0)
	if got.DownloadLocation != "https://proxy.golang.org/github.com/!proton!mail/go-crypto/@v/v1.4.1.zip" {
		t.Fatalf("download location=%q", got.DownloadLocation)
	}
	if got.ExternalRefs[0].ReferenceLocator != "pkg:golang/github.com/ProtonMail/go-crypto@v1.4.1" {
		t.Fatalf("purl=%q", got.ExternalRefs[0].ReferenceLocator)
	}
}

func TestWorkflowRejectsPublicationWeakening(t *testing.T) {
	t.Parallel()
	c := testContract()
	data, err := os.ReadFile(filepath.Join("..", "..", c.Workflow))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name string
		edit func(string) string
	}{
		{"missing tag trigger", func(s string) string { return strings.Replace(s, "    tags: ['v*.*.*']\n", "", 1) }},
		{"PR publication", func(s string) string { return strings.Replace(s, "  push:\n", "  pull_request:\n  push:\n", 1) }},
		{"unpinned action", func(s string) string { return strings.Replace(s, c.Actions.Checkout, "actions/checkout@v7", 1) }},
		{"missing OIDC", func(s string) string { return strings.Replace(s, "      id-token: write\n", "", 1) }},
		{"clobber", func(s string) string { return s + "\n# --clobber\n" }},
		{"rerun", func(s string) string { return strings.Replace(s, "    if: github.run_attempt == 1\n", "", 1) }},
		{"ambient Git trust", func(s string) string { return s + "\n# git config gpg.ssh.allowedSignersFile attacker\n" }},
		{"direct Git verifier", func(s string) string { return s + "\n# git verify-tag v0.1.0\n" }},
	}
	for _, tc := range mutations {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if c.VerifyWorkflow([]byte(tc.edit(string(data)))) == nil {
				t.Fatal("unsafe workflow accepted")
			}
		})
	}
}

func TestBuildIsDeterministicClosedAndCanonical(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	c := testContract()
	a := filepath.Join(t.TempDir(), "a")
	b := filepath.Join(t.TempDir(), "b")
	if err := Build(root, "HEAD", a, c); err != nil {
		t.Fatal(err)
	}
	if err := Build(root, "HEAD", b, c); err != nil {
		t.Fatal(err)
	}
	for _, name := range c.Assets.Names() {
		left, err := os.ReadFile(filepath.Join(a, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(b, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("%s is nondeterministic", name)
		}
	}
	archive, err := os.Open(filepath.Join(a, c.Assets.Archive))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || h.Uid != 0 || h.Gid != 0 || !strings.HasPrefix(h.Name, c.ArchivePrefix) {
			t.Fatalf("unsafe header %#v", h)
		}
		names = append(names, h.Name)
	}
	if !reflect.DeepEqual(names, []string{c.ArchivePrefix + "CHANGELOG.md", c.ArchivePrefix + "LICENSE", c.ArchivePrefix + "go.mod", c.ArchivePrefix + "go.sum", c.ArchivePrefix + "main.go"}) {
		t.Fatalf("archive names=%v", names)
	}
	sbomData, err := os.ReadFile(filepath.Join(a, c.Assets.SBOM))
	if err != nil {
		t.Fatal(err)
	}
	var sbom spdxDocument
	if err := strictJSON(sbomData, &sbom); err != nil {
		t.Fatal(err)
	}
	if sbom.SPDXVersion != "SPDX-2.3" || len(sbom.Files) != 5 || sbom.Packages[0].LicenseDeclared != CanonicalLicense {
		t.Fatalf("invalid SBOM %#v", sbom)
	}
}

func TestBuildResultBindsCanonicalArtifactClosure(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	c := testContract()
	parent := t.TempDir()
	out := filepath.Join(parent, "bundle")
	result, err := BuildWithResult(root, "HEAD", out, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBuildResult(result, out, c); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != BuildResultSchemaVersion || len(result.Assets) != len(c.Assets.Names()) {
		t.Fatalf("unexpected result: %#v", result)
	}
	for i, name := range c.Assets.Names() {
		if result.Assets[i].Name != name {
			t.Fatalf("asset order drift: %#v", result.Assets)
		}
	}
	mutations := []struct {
		name string
		edit func(*BuildResult)
	}{
		{"missing", func(r *BuildResult) { r.Assets = r.Assets[1:] }},
		{"extra", func(r *BuildResult) { r.Assets = append(r.Assets, r.Assets[0]) }},
		{"duplicate", func(r *BuildResult) { r.Assets[1] = r.Assets[0] }},
		{"traversal", func(r *BuildResult) { r.Assets[0].Name = "../escape" }},
		{"digest drift", func(r *BuildResult) { r.Assets[0].SHA256 = strings.Repeat("0", 64) }},
		{"relocated output", func(r *BuildResult) { r.ArtifactRoot = filepath.Join(parent, "elsewhere") }},
		{"empty license", func(r *BuildResult) { r.License = "" }},
		{"wrong license", func(r *BuildResult) { r.License = "MIT" }},
		{"deprecated license", func(r *BuildResult) { r.License = "AGPL-3.0-or-later" }},
		{"schema drift", func(r *BuildResult) { r.SchemaVersion = "v1alpha0" }},
	}
	for _, tc := range mutations {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			candidate := result
			candidate.Assets = append([]AssetDigest(nil), result.Assets...)
			tc.edit(&candidate)
			if reflect.DeepEqual(candidate, result) {
				t.Fatal("mutation did not change candidate")
			}
			if ValidateBuildResult(candidate, out, c) == nil {
				t.Fatal("invalid build result accepted")
			}
		})
	}
}

func TestCanonicalOutputPathUsesHostSemantics(t *testing.T) {
	t.Parallel()
	sep := string(filepath.Separator)
	for _, tc := range []struct {
		name, root, leaf, want string
	}{
		{"trailing separator", sep + "tmp" + sep, "bundle", filepath.Join(sep+"tmp", "bundle")},
		{"multiple separators", sep + sep + "tmp" + sep + sep, "bundle", filepath.Join(sep+"tmp", "bundle")},
		{"filesystem root", sep, "bundle", filepath.Join(sep, "bundle")},
		{"spaces and metacharacters", filepath.Join(sep, "tmp", "space $;[]"), "release (one)", filepath.Join(sep, "tmp", "space $;[]", "release (one)")},
		{"darwin var alias lexical root", filepath.Join(sep, "var", "folders"), "bundle", filepath.Join(sep, "var", "folders", "bundle")},
		{"linux tmp", filepath.Join(sep, "tmp"), "bundle", filepath.Join(sep, "tmp", "bundle")},
		{"foreign temp root", filepath.Join(sep, "foreign", "tmp"), "bundle", filepath.Join(sep, "foreign", "tmp", "bundle")},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalOutputPath(tc.root, tc.leaf)
			if err != nil || got != tc.want || filepath.Clean(got) != got {
				t.Fatalf("got=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct{ root, leaf string }{{"", "bundle"}, {"relative", "bundle"}, {sep + "tmp", ""}, {sep + "tmp", ".."}, {sep + "tmp", "../escape"}, {sep + "tmp", "nested/bundle"}, {sep + "tmp", `nested\bundle`}} {
		if got, err := CanonicalOutputPath(tc.root, tc.leaf); err == nil {
			t.Fatalf("unsafe path accepted: root=%q leaf=%q got=%q", tc.root, tc.leaf, got)
		}
	}
}

func TestBuildResultRejectsMissingAndNullLicense(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	c := testContract()
	out := filepath.Join(t.TempDir(), "bundle")
	result, err := BuildWithResult(root, "HEAD", out, c)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing", func(v map[string]any) { delete(v, "license") }},
		{"null", func(v map[string]any) { v["license"] = nil }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			candidate := maps.Clone(object)
			tc.edit(candidate)
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadBuildResult(path)
			if err != nil {
				t.Fatal(err)
			}
			if ValidateBuildResult(loaded, out, c) == nil {
				t.Fatal("license omission accepted")
			}
		})
	}
}

func TestBuildResultRejectsSymlinkAssetAndResidue(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	c := testContract()
	out := filepath.Join(t.TempDir(), "bundle")
	result, err := BuildWithResult(root, "HEAD", out, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(c.Assets.Archive, filepath.Join(out, "unexpected")); err != nil {
		t.Fatal(err)
	}
	if ValidateBuildResult(result, out, c) == nil {
		t.Fatal("unexpected symlink residue accepted")
	}
}

func TestTreeRejectsUnsafeMembersAndBounds(t *testing.T) {
	t.Parallel()
	limits := testContract().Limits
	data, err := os.ReadFile(filepath.Join("testdata", "archive-negative-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion string   `json:"schema_version"`
		InvalidPaths  []string `json:"invalid_paths"`
		UnsafeTypes   []string `json:"unsafe_types"`
	}
	if err := strictJSON(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "v1alpha1" || len(fixture.UnsafeTypes) != 7 {
		t.Fatal("negative fixture identity drift")
	}
	for _, p := range append(fixture.InvalidPaths, "-option", strings.Repeat("a", limits.MaxPathBytes+1)) {
		if validatePortableRelativePath(p, limits.MaxPathBytes) == nil {
			t.Fatalf("unsafe path accepted %q", p)
		}
	}
	for _, p := range []string{"README.md", "docs/releasing.md", "unicode/café.md", "a-b_c.1/file.go"} {
		if err := validatePortableRelativePath(p, limits.MaxPathBytes); err != nil {
			t.Fatalf("canonical path %q: %v", p, err)
		}
	}
	root := fixtureRepo(t)
	if err := os.Symlink("main.go", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "link")
	gitRun(t, root, "commit", "-m", "symlink")
	if _, err := readTree(root, "HEAD", limits); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestTreeRejectsGitlinkAndFileBounds(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	head := strings.TrimSpace(gitOutput(t, root, "rev-parse", "HEAD"))
	gitRun(t, root, "update-index", "--add", "--cacheinfo", "160000,"+head+",nested-module")
	gitRun(t, root, "commit", "-q", "-m", "gitlink")
	if _, err := readTree(root, "HEAD", testContract().Limits); err == nil {
		t.Fatal("gitlink accepted")
	}
	root = fixtureRepo(t)
	limits := testContract().Limits
	limits.MaxFileBytes = 4
	if _, err := readTree(root, "HEAD", limits); err == nil {
		t.Fatal("oversized member accepted")
	}
}

func TestArchiveVerifierRejectsUnsafeContainerShapes(t *testing.T) {
	t.Parallel()
	c := testContract()
	tests := []struct {
		name    string
		headers []*tar.Header
	}{
		{"traversal", []*tar.Header{{Name: c.ArchivePrefix + "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}}},
		{"symlink", []*tar.Header{{Name: c.ArchivePrefix + "link", Mode: 0o644, Typeflag: tar.TypeSymlink, Linkname: "target"}}},
		{"hardlink", []*tar.Header{{Name: c.ArchivePrefix + "link", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "target"}}},
		{"character device", []*tar.Header{{Name: c.ArchivePrefix + "device", Mode: 0o644, Typeflag: tar.TypeChar}}},
		{"block device", []*tar.Header{{Name: c.ArchivePrefix + "device", Mode: 0o644, Typeflag: tar.TypeBlock}}},
		{"fifo", []*tar.Header{{Name: c.ArchivePrefix + "pipe", Mode: 0o644, Typeflag: tar.TypeFifo}}},
		{"socket", []*tar.Header{{Name: c.ArchivePrefix + "socket", Mode: 0o644, Typeflag: 's'}}},
		{"prefix confusable", []*tar.Header{{Name: "agent-runtime-v0.1.0-evil/file", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}}},
		{"duplicate", []*tar.Header{{Name: c.ArchivePrefix + "a", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}, {Name: c.ArchivePrefix + "a", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}}},
		{"unsorted", []*tar.Header{{Name: c.ArchivePrefix + "b", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}, {Name: c.ArchivePrefix + "a", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := verifyArchiveBytes(archiveFixtureBytes(t, tc.headers), c); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestMemberTableRejectsPortableCollisionsAndBounds(t *testing.T) {
	t.Parallel()
	regular := func(name string, size int64) memberDescriptor {
		return memberDescriptor{Path: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: size}
	}
	tests := []struct {
		name    string
		members []memberDescriptor
		limits  Limits
	}{
		{"case collision", []memberDescriptor{regular("A", 1), regular("a", 1)}, testContract().Limits},
		{"duplicate", []memberDescriptor{regular("a", 1), regular("a", 1)}, testContract().Limits},
		{"count", []memberDescriptor{regular("a", 1), regular("b", 1)}, Limits{MaxFiles: 1, MaxFileBytes: 10, MaxTotalBytes: 10, MaxPathBytes: 512}},
		{"member size", []memberDescriptor{regular("a", 11)}, Limits{MaxFiles: 1, MaxFileBytes: 10, MaxTotalBytes: 20, MaxPathBytes: 512}},
		{"total size", []memberDescriptor{regular("a", 6), regular("b", 6)}, Limits{MaxFiles: 2, MaxFileBytes: 10, MaxTotalBytes: 10, MaxPathBytes: 512}},
		{"owner metadata", []memberDescriptor{{Path: "a", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, UID: 1}}, testContract().Limits},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if validateMemberTable(tc.members, tc.limits) == nil {
				t.Fatal("unsafe table accepted")
			}
		})
	}
}

func TestBuildFailureLeavesNoPartialOutput(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	if err := os.Remove(filepath.Join(root, "CHANGELOG.md")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "-u")
	gitRun(t, root, "commit", "-q", "-m", "remove changelog")
	out := filepath.Join(t.TempDir(), "release")
	if err := Build(root, "HEAD", out, testContract()); err == nil {
		t.Fatal("invalid source built")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial output exists: %v", err)
	}
}

func TestBundleRejectsMissingUnexpectedMalformedAndMismatched(t *testing.T) {
	t.Parallel()
	root := fixtureRepo(t)
	c := testContract()
	base := filepath.Join(t.TempDir(), "base")
	if err := Build(root, "HEAD", base, c); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(string)
	}{
		{"missing", func(d string) { mustRemove(t, filepath.Join(d, c.Assets.SBOM)) }},
		{"unexpected", func(d string) { mustWrite(t, filepath.Join(d, "extra"), []byte("x")) }},
		{"malformed manifest", func(d string) { mustWrite(t, filepath.Join(d, c.Assets.Manifest), []byte("{}")) }},
		{"wrong digest", func(d string) { mustWrite(t, filepath.Join(d, c.Assets.Archive), []byte("changed")) }},
		{"oversized checksum shape", func(d string) { mustWrite(t, filepath.Join(d, c.Assets.Checksums), []byte(strings.Repeat("a", 10000))) }},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := filepath.Join(t.TempDir(), "bundle")
			copyDir(t, base, d)
			tc.mutate(d)
			if VerifyBundle(d, c) == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

func TestArchiveBytesDoNotAliasInput(t *testing.T) {
	t.Parallel()
	files := []gitFile{{Mode: "100644", Path: "x", Data: []byte("before")}}
	stamp := time.Unix(1, 0).UTC()
	first, err := archiveBytes(files, "p/", stamp, testContract().Limits)
	if err != nil {
		t.Fatal(err)
	}
	files[0].Data[0] = 'X'
	second, err := archiveBytes([]gitFile{{Mode: "100644", Path: "x", Data: []byte("before")}}, "p/", stamp, testContract().Limits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("archive aliased caller data")
	}
}

func FuzzReleasePath(f *testing.F) {
	for _, s := range []string{"a/b.go", "../x", "/x", "a\\b", "-x", "C:/x", "a//b", "café.md"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _ = validatePortableRelativePath(s, 512) })
}
func FuzzReleaseContractJSON(f *testing.F) {
	data, _ := json.Marshal(testContract())
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Contract
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if d.Decode(&c) == nil {
			_ = c.Validate()
		}
	})
}

func testContract() Contract {
	data, err := os.ReadFile(filepath.Join("..", "..", "release", "v1alpha1.json"))
	if err != nil {
		panic(err)
	}
	var contract Contract
	if err := json.Unmarshal(data, &contract); err != nil {
		panic(err)
	}
	return contract
}

func canonicalGoMod(contract Contract) string {
	return goModFromDependencies(contract, canonicalDependencies(contract.Dependencies))
}

func goModFromDependencies(contract Contract, dependencies []Dependency) string {
	var direct, indirect strings.Builder
	for _, dependency := range dependencies {
		line := "\t" + dependency.ModulePath + " " + dependency.Version
		if dependency.Indirect {
			indirect.WriteString(line + " // indirect\n")
		} else {
			direct.WriteString(line + "\n")
		}
	}
	result := "module " + contract.ModulePath + "\n\ngo 1.24.0\n\nrequire (\n" + direct.String() + ")\n"
	if indirect.Len() != 0 {
		result += "\nrequire (\n" + indirect.String() + ")\n"
	}
	return result
}

func canonicalGoSum(contract Contract) string {
	const digest = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	var result strings.Builder
	for _, dependency := range canonicalDependencies(contract.Dependencies) {
		result.WriteString(dependency.ModulePath + " " + dependency.Version + " " + digest + "\n")
		result.WriteString(dependency.ModulePath + " " + dependency.Version + "/go.mod " + digest + "\n")
	}
	return result.String()
}

func fixtureRepo(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	gitRun(t, d, "init", "-q")
	gitRun(t, d, "config", "user.name", "Test")
	gitRun(t, d, "config", "user.email", "test@example.com")
	mustWrite(t, filepath.Join(d, "go.mod"), []byte(canonicalGoMod(testContract())))
	mustWrite(t, filepath.Join(d, "go.sum"), []byte(canonicalGoSum(testContract())))
	mustWrite(t, filepath.Join(d, "main.go"), []byte("package agentruntime\n"))
	mustWrite(t, filepath.Join(d, "LICENSE"), []byte("AGPL-3.0-only\n"))
	mustWrite(t, filepath.Join(d, "CHANGELOG.md"), []byte("# Changelog\n\n## [0.1.0] - 2026-08-13\n\n### Added\n\n- Initial source release.\n"))
	gitRun(t, d, "add", ".")
	gitRun(t, d, "commit", "-q", "-m", "fixture")
	return d
}
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}
func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(dst, e.Name()), b)
	}
}
func writeArchive(t *testing.T, p string, headers []*tar.Header) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func archiveFixtureBytes(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
