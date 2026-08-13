// SPDX-License-Identifier: AGPL-3.0-only

package releasecontract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type gitFile struct {
	Mode string
	OID  string
	Path string
	Data []byte
}

type AssetDigest struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion    string        `json:"schema_version"`
	Version          string        `json:"version"`
	SourceTag        string        `json:"source_tag"`
	SourceCommit     string        `json:"source_commit"`
	SourceCommitTime string        `json:"source_commit_time"`
	ModulePath       string        `json:"module_path"`
	GoCompatibility  string        `json:"go_compatibility"`
	License          string        `json:"license"`
	Dependencies     []Dependency  `json:"dependencies"`
	Workflow         string        `json:"workflow"`
	Actions          Actions       `json:"actions"`
	SBOMNamespace    string        `json:"sbom_namespace"`
	ContentAssets    []AssetDigest `json:"content_assets"`
	RequiredAssets   []string      `json:"required_assets"`
}

type spdxDocument struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Files             []spdxFile     `json:"files"`
	Relationships     []relationship `json:"relationships"`
}
type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}
type checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type spdxFile struct {
	FileName         string     `json:"fileName"`
	SPDXID           string     `json:"SPDXID"`
	Checksums        []checksum `json:"checksums"`
	LicenseConcluded string     `json:"licenseConcluded"`
	CopyrightText    string     `json:"copyrightText"`
}
type spdxPackage struct {
	Name             string        `json:"name"`
	SPDXID           string        `json:"SPDXID"`
	VersionInfo      string        `json:"versionInfo"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	CopyrightText    string        `json:"copyrightText"`
	ExternalRefs     []externalRef `json:"externalRefs"`
}
type externalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}
type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func Build(root, commit, out string, c Contract) error {
	if err := c.Validate(); err != nil {
		return err
	}
	resolved, err := git(root, "rev-parse", "--verify", commit+"^{commit}")
	if err != nil {
		return fmt.Errorf("resolve source commit: %w", err)
	}
	resolved = strings.TrimSpace(resolved)
	commitTimeRaw, err := git(root, "show", "-s", "--format=%ct", resolved)
	if err != nil {
		return err
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(commitTimeRaw), 10, 64)
	if err != nil {
		return fmt.Errorf("parse commit time: %w", err)
	}
	files, err := readTree(root, resolved, c.Limits)
	if err != nil {
		return err
	}
	assets, err := buildBundleData(files, resolved, time.Unix(epoch, 0).UTC(), c)
	if err != nil {
		return err
	}
	return publishBundle(out, c, assets)
}

func buildBundleData(files []gitFile, resolved string, commitTime time.Time, c Contract) (map[string][]byte, error) {
	archive, err := archiveBytes(files, c.ArchivePrefix, commitTime, c.Limits)
	if err != nil {
		return bundleBuildError(err)
	}
	notes, err := releaseNotes(files, strings.TrimPrefix(c.Version, "v"))
	if err != nil {
		return bundleBuildError(err)
	}
	namespace := fmt.Sprintf("https://github.com/NDDev-it-com/agent-runtime/releases/tag/%s#spdx-%s", c.Version, resolved)
	sbom, err := sbomBytes(files, c, resolved, commitTime, namespace)
	if err != nil {
		return bundleBuildError(err)
	}
	content := []struct {
		name string
		data []byte
	}{{c.Assets.Archive, archive}, {c.Assets.SBOM, sbom}, {c.Assets.Notes, notes}}
	digests := make([]AssetDigest, 0, len(content))
	for _, item := range content {
		digests = append(digests, digest(item.name, item.data))
	}
	manifest := newManifest(c, resolved, commitTime, namespace, digests)
	manifestData, err := canonicalJSON(manifest)
	if err != nil {
		return bundleBuildError(err)
	}
	content = append(content, struct {
		name string
		data []byte
	}{c.Assets.Manifest, manifestData})
	var sums strings.Builder
	for _, item := range content {
		fmt.Fprintf(&sums, "%s  %s\n", digest(item.name, item.data).SHA256, item.name)
	}
	content = append(content, struct {
		name string
		data []byte
	}{c.Assets.Checksums, []byte(sums.String())})
	assets := make(map[string][]byte, len(content))
	for _, item := range content {
		assets[item.name] = item.data
	}
	if err := verifyBundleData(assets, c); err != nil {
		return nil, err
	}
	return assets, nil
}

func bundleBuildError(err error) (map[string][]byte, error) {
	return nil, err
}

func newManifest(c Contract, commit string, commitTime time.Time, namespace string, assets []AssetDigest) Manifest {
	return Manifest{
		SchemaVersion: SchemaVersion, Version: c.Version, SourceTag: c.Version,
		SourceCommit: commit, SourceCommitTime: commitTime.Format(time.RFC3339),
		ModulePath: c.ModulePath, GoCompatibility: c.GoCompatibility, License: c.License,
		Dependencies: append([]Dependency{}, c.Dependencies...), Workflow: c.Workflow,
		Actions: c.Actions, SBOMNamespace: namespace,
		ContentAssets: append([]AssetDigest{}, assets...), RequiredAssets: append([]string{}, c.Assets.Names()...),
	}
}

func readTree(root, commit string, limits Limits) ([]gitFile, error) {
	raw, err := gitBytes(root, "ls-tree", "-r", "-z", "-l", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	records := bytes.Split(raw, []byte{0})
	files := make([]gitFile, 0, len(records))
	type treeEntry struct {
		mode, objectType, oid, path string
		size                        int64
	}
	entries := make([]treeEntry, 0, len(records))
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		meta, name, ok := bytes.Cut(record, []byte{'\t'})
		if !ok {
			return nil, errors.New("malformed git tree record")
		}
		parts := strings.Fields(string(meta))
		if len(parts) != 4 {
			return nil, errors.New("malformed git tree metadata")
		}
		p := string(name)
		size, sizeErr := strconv.ParseInt(parts[3], 10, 64)
		if sizeErr != nil {
			size = -1
		}
		entries = append(entries, treeEntry{mode: parts[0], objectType: parts[1], oid: parts[2], path: p, size: size})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	descriptors := make([]memberDescriptor, 0, len(entries))
	for _, entry := range entries {
		descriptors = append(descriptors, gitMemberDescriptor(entry.path, entry.mode, entry.objectType, entry.size))
	}
	if err := validateMemberTable(descriptors, limits); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		p := entry.path
		data, err := gitBytes(root, "cat-file", "blob", entry.oid)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != entry.size {
			return nil, fmt.Errorf("tracked member %q size changed while reading", p)
		}
		files = append(files, gitFile{Mode: entry.mode, OID: entry.oid, Path: p, Data: data})
	}
	if len(files) == 0 {
		return nil, errors.New("source tree is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func archiveBytes(files []gitFile, prefix string, modTime time.Time, limits Limits) ([]byte, error) {
	if err := validateArchivePrefix(prefix, limits.MaxPathBytes); err != nil {
		return nil, err
	}
	descriptors := make([]memberDescriptor, 0, len(files))
	for _, f := range files {
		descriptors = append(descriptors, gitMemberDescriptor(f.Path, f.Mode, "blob", int64(len(f.Data))))
	}
	if err := validateMemberTable(descriptors, limits); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	gz.Header.ModTime = modTime
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	for _, f := range files {
		mode := int64(0o644)
		if f.Mode == "100755" {
			mode = 0o755
		}
		h := &tar.Header{Name: prefix + f.Path, Mode: mode, Size: int64(len(f.Data)), ModTime: modTime, AccessTime: time.Time{}, ChangeTime: time.Time{}, Uid: 0, Gid: 0, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func releaseNotes(files []gitFile, version string) ([]byte, error) {
	var data []byte
	for _, f := range files {
		if f.Path == "CHANGELOG.md" {
			data = f.Data
			break
		}
	}
	if data == nil {
		return nil, errors.New("CHANGELOG.md missing from source tree")
	}
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "## ["+version+"]") {
			if start >= 0 {
				return nil, errors.New("duplicate changelog release section")
			}
			start = i
		}
	}
	if start < 0 {
		return nil, errors.New("release changelog section missing")
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## [") {
			end = i
			break
		}
	}
	notes := strings.TrimSpace(strings.Join(lines[start:end], "\n")) + "\n"
	if len(notes) < 32 {
		return nil, errors.New("release notes are empty")
	}
	return []byte(notes), nil
}

func sbomBytes(files []gitFile, c Contract, commit string, created time.Time, namespace string) ([]byte, error) {
	descriptors := make([]memberDescriptor, 0, len(files))
	for _, f := range files {
		descriptors = append(descriptors, gitMemberDescriptor(f.Path, f.Mode, "blob", int64(len(f.Data))))
	}
	if err := validateMemberTable(descriptors, c.Limits); err != nil {
		return nil, err
	}
	spdxFiles := make([]spdxFile, 0, len(files))
	rels := make([]relationship, 0, len(files)+1)
	for i, f := range files {
		id := fmt.Sprintf("SPDXRef-File-%d", i+1)
		sum := sha256.Sum256(f.Data)
		spdxFiles = append(spdxFiles, spdxFile{FileName: sbomFileName(f.Path), SPDXID: id, Checksums: []checksum{{Algorithm: "SHA256", ChecksumValue: hex.EncodeToString(sum[:])}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"})
		rels = append(rels, relationship{SPDXElementID: "SPDXRef-Package", RelationshipType: "CONTAINS", RelatedSPDXElement: id})
	}
	rels = append([]relationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package"}}, rels...)
	packages := []spdxPackage{newMainSPDXPackage(c)}
	for index, dependency := range c.Dependencies {
		pkg := newDependencySPDXPackage(dependency, index)
		packages = append(packages, pkg)
		rels = append(rels, relationship{SPDXElementID: "SPDXRef-Package", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: pkg.SPDXID})
	}
	doc := spdxDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "agent-runtime-" + c.Version, DocumentNamespace: namespace, CreationInfo: creationInfo{Created: created.Format(time.RFC3339), Creators: []string{"Tool: agent-runtime-release-v1alpha1"}}, Packages: packages, Files: spdxFiles, Relationships: rels}
	_ = commit
	return canonicalJSON(doc)
}

func newMainSPDXPackage(c Contract) spdxPackage {
	return spdxPackage{
		Name: c.ModulePath, SPDXID: "SPDXRef-Package", VersionInfo: c.Version,
		DownloadLocation: "https://github.com/NDDev-it-com/agent-runtime/archive/refs/tags/" + c.Version + ".tar.gz",
		FilesAnalyzed:    true, LicenseConcluded: c.License, LicenseDeclared: c.License,
		CopyrightText: "NOASSERTION", ExternalRefs: []externalRef{newPURL(c.ModulePath, c.Version)},
	}
}

func newDependencySPDXPackage(dependency Dependency, index int) spdxPackage {
	return spdxPackage{
		Name: dependency.ModulePath, SPDXID: fmt.Sprintf("SPDXRef-Dependency-%d", index+1), VersionInfo: dependency.Version,
		DownloadLocation: "https://proxy.golang.org/" + dependency.ModulePath + "/@v/" + dependency.Version + ".zip",
		FilesAnalyzed:    false, LicenseConcluded: dependency.License, LicenseDeclared: dependency.License,
		CopyrightText: "NOASSERTION", ExternalRefs: []externalRef{newPURL(dependency.ModulePath, dependency.Version)},
	}
}

func newPURL(modulePath, version string) externalRef {
	return externalRef{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/" + modulePath + "@" + version}
}

func VerifyBundle(dir string, c Contract) error {
	assets, err := readBundleSecure(dir, c)
	if err != nil {
		return err
	}
	return verifyBundleData(assets, c)
}

func verifyBundleData(assets map[string][]byte, c Contract) error {
	names := make([]string, 0, len(assets))
	for name := range assets {
		names = append(names, name)
	}
	sort.Strings(names)
	want := append([]string(nil), c.Assets.Names()...)
	sort.Strings(want)
	if strings.Join(names, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("release asset closure mismatch: %v", names)
	}
	manifestData := assets[c.Assets.Manifest]
	var m Manifest
	if err := strictJSON(manifestData, &m); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	if m.SchemaVersion != SchemaVersion || m.Version != c.Version || m.SourceTag != c.Version || m.SourceCommit == "" || m.ModulePath != c.ModulePath || m.GoCompatibility != c.GoCompatibility || m.License != c.License || !equalDependencies(m.Dependencies, c.Dependencies) || m.Workflow != c.Workflow || m.Actions != c.Actions || m.SBOMNamespace == "" || len(m.ContentAssets) != 3 || !equalNames(m.RequiredAssets, c.Assets.Names()) {
		return errors.New("release manifest identity is inconsistent")
	}
	wantContent := []string{c.Assets.Archive, c.Assets.SBOM, c.Assets.Notes}
	for i, d := range m.ContentAssets {
		if d.Name != wantContent[i] {
			return errors.New("release manifest content asset order/identity drift")
		}
		data := assets[d.Name]
		got := digest(d.Name, data)
		if got != d {
			return fmt.Errorf("asset digest mismatch for %s", d.Name)
		}
	}
	archiveFiles, err := verifyArchiveBytes(assets[c.Assets.Archive], c)
	if err != nil {
		return err
	}
	if err := verifySBOMBytes(assets[c.Assets.SBOM], c, m, archiveFiles); err != nil {
		return err
	}
	notes := assets[c.Assets.Notes]
	if !bytes.HasPrefix(notes, []byte("## ["+strings.TrimPrefix(c.Version, "v")+"]")) {
		return errors.New("canonical release notes heading is missing")
	}
	sums := assets[c.Assets.Checksums]
	lines := strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n")
	if len(lines) != 4 {
		return errors.New("SHA256SUMS must cover exactly four non-self assets")
	}
	wantChecksums := []string{c.Assets.Archive, c.Assets.SBOM, c.Assets.Notes, c.Assets.Manifest}
	for index, line := range lines {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || len(parts[0]) != 64 || parts[1] != wantChecksums[index] {
			return errors.New("malformed SHA256SUMS")
		}
		data := assets[parts[1]]
		if digest(parts[1], data).SHA256 != parts[0] {
			return fmt.Errorf("checksum mismatch for %s", parts[1])
		}
	}
	return nil
}

func verifyArchiveBytes(data []byte, c Contract) (map[string]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("archive gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	result := map[string]string{}
	descriptors := make([]memberDescriptor, 0)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive tar: %w", err)
		}
		name, pathErr := archiveMemberRelative(h.Name, c.ArchivePrefix, c.Limits.MaxPathBytes)
		if pathErr != nil {
			return nil, pathErr
		}
		descriptors = append(descriptors, memberDescriptor{Path: name, Typeflag: h.Typeflag, Mode: h.Mode, Size: h.Size, Linkname: h.Linkname, UID: h.Uid, GID: h.Gid, Uname: h.Uname, Gname: h.Gname})
		if h.Size < 0 || h.Size > c.Limits.MaxFileBytes || h.Size > c.Limits.MaxTotalBytes-total {
			return nil, errors.New("archive member size exceeds bound")
		}
		total += h.Size
		sum := sha256.New()
		if _, err := io.Copy(sum, tr); err != nil {
			return nil, err
		}
		result[name] = hex.EncodeToString(sum.Sum(nil))
	}
	if err := validateMemberTable(descriptors, c.Limits); err != nil {
		return nil, err
	}
	return result, nil
}

func verifySBOMBytes(data []byte, c Contract, m Manifest, archiveFiles map[string]string) error {
	var doc spdxDocument
	if err := strictJSON(data, &doc); err != nil {
		return fmt.Errorf("SBOM: %w", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.SPDXID != "SPDXRef-DOCUMENT" || doc.DocumentNamespace != m.SBOMNamespace || len(doc.Packages) != 1+len(c.Dependencies) || !equalSPDXPackage(doc.Packages[0], newMainSPDXPackage(c)) {
		return errors.New("SBOM identity is inconsistent")
	}
	for index, dependency := range c.Dependencies {
		if !equalSPDXPackage(doc.Packages[index+1], newDependencySPDXPackage(dependency, index)) {
			return errors.New("SBOM dependency identity is inconsistent")
		}
	}
	if len(doc.Files) != len(archiveFiles) {
		return errors.New("SBOM file closure differs from archive")
	}
	seen := map[string]bool{}
	wantRelationships := []relationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package"}}
	for index, f := range doc.Files {
		name, nameErr := sbomRelativePath(f.FileName, c.Limits.MaxPathBytes)
		expectedID := fmt.Sprintf("SPDXRef-File-%d", index+1)
		if nameErr != nil || seen[name] || f.SPDXID != expectedID || f.LicenseConcluded != "NOASSERTION" || f.CopyrightText != "NOASSERTION" || len(f.Checksums) != 1 || f.Checksums[0].Algorithm != "SHA256" || archiveFiles[name] != f.Checksums[0].ChecksumValue {
			return fmt.Errorf("SBOM file entry differs from archive: %q", f.FileName)
		}
		seen[name] = true
		wantRelationships = append(wantRelationships, relationship{SPDXElementID: "SPDXRef-Package", RelationshipType: "CONTAINS", RelatedSPDXElement: expectedID})
	}
	for index := range c.Dependencies {
		wantRelationships = append(wantRelationships, relationship{SPDXElementID: "SPDXRef-Package", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: fmt.Sprintf("SPDXRef-Dependency-%d", index+1)})
	}
	if !equalRelationships(doc.Relationships, wantRelationships) {
		return errors.New("SBOM relationship closure/order is inconsistent")
	}
	return nil
}

func sbomFileName(relative string) string { return "./" + relative }

func sbomRelativePath(name string, maxBytes int) (string, error) {
	if !strings.HasPrefix(name, "./") || strings.HasPrefix(name, ".//") {
		return "", errors.New("SBOM fileName lacks one canonical ./ prefix")
	}
	relative := strings.TrimPrefix(name, "./")
	if err := validatePortableRelativePath(relative, maxBytes); err != nil {
		return "", err
	}
	if name != sbomFileName(relative) {
		return "", errors.New("SBOM fileName is not canonical")
	}
	return relative, nil
}

func digest(name string, data []byte) AssetDigest {
	sum := sha256.Sum256(data)
	return AssetDigest{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}
func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func equalDependencies(a, b []Dependency) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func equalSPDXPackage(actual, expected spdxPackage) bool {
	if actual.Name != expected.Name || actual.SPDXID != expected.SPDXID || actual.VersionInfo != expected.VersionInfo || actual.DownloadLocation != expected.DownloadLocation || actual.FilesAnalyzed != expected.FilesAnalyzed || actual.LicenseConcluded != expected.LicenseConcluded || actual.LicenseDeclared != expected.LicenseDeclared || actual.CopyrightText != expected.CopyrightText || len(actual.ExternalRefs) != len(expected.ExternalRefs) {
		return false
	}
	for index := range actual.ExternalRefs {
		if actual.ExternalRefs[index] != expected.ExternalRefs[index] {
			return false
		}
	}
	return true
}

func equalRelationships(actual, expected []relationship) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
func canonicalJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func strictJSON(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var x any
	if err := d.Decode(&x); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}
func git(root string, args ...string) (string, error) {
	b, err := gitBytes(root, args...)
	return string(b), err
}
func gitBytes(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}
