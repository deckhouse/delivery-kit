package nativegate

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// gitLocatorRegexp is the Yarn 1 spelling of a Git dependency pinned to a commit: a
// transport this adapter understands and a full commit as the fragment. A ref name, a
// short commit or a locator without a fragment pins no bytes and is not accepted.
var gitLocatorRegexp = regexp.MustCompile(`^git\+(https|ssh)://[^\s#]+#([0-9a-f]{40})$`)

// gitCommitRegexp is a commit as this adapter takes one: full, lowercase hex.
var gitCommitRegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)

// gitTreeEntryRegexp splits the textual head of a tree entry, `<mode> <name>`. Old git
// versions wrote a leading zero and the group-writable file mode, so the octal spelling
// is read as a number and normalized rather than matched literally.
var gitTreeEntryRegexp = regexp.MustCompile(`^([0-7]{5,6}) (.+)$`)

// Modes as git writes them in a tree object, normalized.
const (
	gitModeTree          = "40000"
	gitModeBlob          = "100644"
	gitModeExecutable    = "100755"
	gitModeGroupWritable = "100664"
	gitModeSymlink       = "120000"
	gitModeGitlink       = "160000"
)

// gitLifecycleHooks are the package.json scripts an install or a publish of the package
// runs: whatever they write into the installed tree is theirs, not the commit's, so it
// is never listed. The same list is the whitelist of the Node reader of the manifest.
var gitLifecycleHooks = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack"}

// gitTreeDepthLimit bounds a tree walk that a crafted object graph could otherwise make
// unbounded; no real package tree comes anywhere near it.
const gitTreeDepthLimit = 64

// gitMirrorHostRegexp is a bare host, optionally with a port: what a mirror is named by.
// Credentials, a transport and a path are not part of a host and are refused here, so
// that no access token can be written into the configuration of a mirror.
var gitMirrorHostRegexp = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]+)?$`)

// gitMirrorPrefixRegexp is the path under the mirror host that the mirrored repositories
// stand below, without a leading or trailing slash.
var gitMirrorPrefixRegexp = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// GitMirror states that the repositories of UpstreamHost are served, under PathPrefix of
// Host, with the same owner and repository name below that prefix.
//
// It is an explicit statement of the project's own configuration, never a discovered
// one: a host nothing lists stays a different repository, as before. What a listed
// mirror buys is where the objects may be fetched from and nothing else - the commit and
// every object below it are verified by hash exactly as they are for a repository
// fetched from the host the lockfile names.
type GitMirror struct {
	Host         string
	PathPrefix   string
	UpstreamHost string
}

// CheckGitMirrors holds a configured allowlist to what a mirror entry can say: a bare
// host, the path of that host the mirrored repositories stand under, and the host whose
// repositories those are. A malformed entry is refused rather than ignored, because an
// entry nothing can match silently narrows what is accepted.
func CheckGitMirrors(mirrors []GitMirror) error {
	listed := map[string]bool{}
	for i, mirror := range mirrors {
		for _, field := range []struct{ name, value string }{{"host", mirror.Host}, {"upstreamHost", mirror.UpstreamHost}} {
			if !gitMirrorHostRegexp.MatchString(field.value) {
				return fmt.Errorf("gitMirror %d: %s %q is not a bare host", i, field.name, field.value)
			}
		}
		if !gitMirrorPrefixRegexp.MatchString(mirror.PathPrefix) || slices.ContainsFunc(strings.Split(mirror.PathPrefix, "/"), func(segment string) bool {
			return segment == "." || segment == ".."
		}) {
			return fmt.Errorf("gitMirror %d: pathPrefix %q is not a path of the mirror host", i, mirror.PathPrefix)
		}
		prefix := strings.ToLower(mirror.Host) + "/" + mirror.PathPrefix
		if listed[prefix] {
			return fmt.Errorf("gitMirror %d: %s is listed more than once", i, prefix)
		}
		listed[prefix] = true
	}

	return nil
}

// gitUpstreamRepository answers the repository whose objects a fetched one serves: a
// listed mirror stands for the upstream repository it carries at the same owner and
// name below its prefix, and every other remote stands for itself.
func gitUpstreamRepository(mirrors []GitMirror, fetched string) (string, bool, error) {
	if err := CheckGitMirrors(mirrors); err != nil {
		return "", false, fmt.Errorf("invalid: %w", err)
	}
	for _, mirror := range mirrors {
		repository, served := strings.CutPrefix(fetched, strings.ToLower(mirror.Host)+"/"+mirror.PathPrefix+"/")
		if !served || repository == "" {
			continue
		}

		return strings.ToLower(mirror.UpstreamHost) + "/" + repository, true, nil
	}

	return fetched, false, nil
}

// gitRemoteWithoutCredentials answers the remote as it may be recorded: whatever the
// fetch authenticated itself with is the build's, never part of the evidence.
func gitRemoteWithoutCredentials(remote string) string {
	if !strings.Contains(remote, "://") {
		host, repository, scp := strings.Cut(remote, ":")
		if _, user, found := strings.Cut(host, "@"); scp && found {
			return user + ":" + repository
		}

		return remote
	}
	parsed, err := url.Parse(remote)
	if err != nil {
		return ""
	}
	parsed.User = nil

	return parsed.String()
}

// GitOriginalRequest states which commit of which repository a Node package was
// installed from, as the caller's own declaration. Nothing here is read back from the
// built image, a ref or a worktree.
type GitOriginalRequest struct {
	// GitDir is the directory holding the object database DK fetched the mapping into.
	GitDir string
	// RemoteURL is the remote the mapping was fetched from, as git itself spells it.
	RemoteURL string
	// Commit is the commit the mapping is pinned to, full lowercase hex.
	Commit string
	// Locator is the lockfile `resolved` value, verbatim.
	Locator string
	// PackageName and PackageVersion are the identity the lock entry carries; the
	// package.json of the verified commit must hold exactly these.
	PackageName    string
	PackageVersion string
	// Mirrors are the mirrors the project's configuration accepts in place of the host
	// the locator names. Nothing that is not listed here is accepted.
	Mirrors []GitMirror
	// InstalledRoot is the absolute path the package is installed at in the observed
	// stage, that is `<…>/node_modules/<name>` for a dependency and the project root
	// itself for the project.
	InstalledRoot string
	// Project marks the stage's own sources rather than a dependency of them. A
	// project is not a dependency of itself, so no lockfile names it: its identity is
	// the package.json of the verified commit and its locator is spelled from the
	// mapping remote. Nothing under a node_modules directory of it is its own.
	Project bool
}

// GitOriginal is one verified Git-backed Node original: the component the commit
// identifies and the installed files whose bytes are the commit's own.
type GitOriginal struct {
	Component shared.BuildComponent
	Files     []GitOriginalFile
	// Lifecycle names the install hooks the verified package.json defines. Their
	// outputs are not the commit's bytes and are never listed as files.
	Lifecycle []string
	// Mirror is the remote the objects were really fetched from, without credentials,
	// when that was a listed mirror rather than the repository the locator names. It is
	// evidence about this build, not part of the component's identity.
	Mirror string
}

// GitOriginalFile binds an installed path to the digest of the blob the commit serves at
// the same package-relative path. The digest is the blob's, and it is recorded only
// because the installed bytes were found byte-identical to it.
type GitOriginalFile struct {
	Path   string
	SHA256 string
}

// VerifyGitOriginal proves that a Git mapping DK fetched is the distribution a lockfile
// pins, and answers which installed files of the observed stage carry that commit's own
// bytes.
//
// The commit is the only root of trust: every object is read by hash from the commit id
// down and rehashed here, so neither a ref, an image label nor a worktree takes part. A
// mismatch of the pinned repository, of the commit, or of the identity the commit's
// package.json carries is a refusal rather than a narrower answer.
//
// SHA-1 is collision-prone, so a commit id proves no more than that the object graph is
// the one the lockfile already named when it was written: it is reported verbatim as
// `git-commit:sha1:<commit>` and never restated as a stronger pin.
func VerifyGitOriginal(ctx context.Context, request GitOriginalRequest, observed *shippedscope.FileIndex) (*GitOriginal, error) {
	if observed == nil || observed.Incomplete || observed.Files == nil {
		return nil, fmt.Errorf("no-data: a Git original needs the complete observed file index of the target")
	}
	if err := namespacePath(request.InstalledRoot); err != nil {
		return nil, fmt.Errorf("installed %w", err)
	}
	mappedRepository, err := gitRepositoryIdentity(request.RemoteURL)
	if err != nil {
		return nil, fmt.Errorf("invalid: mapping remote %q: %w", request.RemoteURL, err)
	}
	upstreamRepository, mirrored, err := gitUpstreamRepository(request.Mirrors, mappedRepository)
	if err != nil {
		return nil, err
	}
	request, err = resolvedGitRequest(request, upstreamRepository)
	if err != nil {
		return nil, err
	}

	match := gitLocatorRegexp.FindStringSubmatch(request.Locator)
	if match == nil {
		return nil, fmt.Errorf("invalid: %q is not a Git locator pinned to a full commit", request.Locator)
	}
	commit := match[2]
	if request.Commit != commit {
		return nil, fmt.Errorf("invalid: the mapping is pinned to %q, the locator to %q", request.Commit, commit)
	}
	locatorRepository, err := gitRepositoryIdentity(strings.TrimSuffix(strings.TrimPrefix(request.Locator, "git+"), "#"+commit))
	if err != nil {
		return nil, fmt.Errorf("invalid: locator %q: %w", request.Locator, err)
	}
	if locatorRepository != upstreamRepository {
		if mirrored {
			return nil, fmt.Errorf("invalid: the mapping fetches %s, which serves %s, the locator pins %s", mappedRepository, upstreamRepository, locatorRepository)
		}

		return nil, fmt.Errorf("invalid: the mapping fetches %s, the locator pins %s", mappedRepository, locatorRepository)
	}

	blobs, manifest, err := verifiedGitTree(ctx, request.GitDir, commit)
	if err != nil {
		return nil, err
	}
	lifecycle, err := checkGitPackageIdentity(manifest, &request)
	if err != nil {
		return nil, err
	}

	original := &GitOriginal{
		Component: shared.BuildComponent{
			ID:      gitComponentID(request, commit),
			Name:    request.PackageName,
			Version: request.PackageVersion,
			Source:  shared.BuildSource{Kind: "node", Locator: request.Locator, Checksum: "git-commit:sha1:" + commit},
		},
		Files:     []GitOriginalFile{},
		Lifecycle: lifecycle,
	}
	if mirrored {
		original.Mirror = gitRemoteWithoutCredentials(request.RemoteURL)
	}
	for _, relative := range slices.Sorted(maps.Keys(blobs)) {
		// A project vendors its dependencies under its own root, and what stands
		// there is the installer's doing rather than the commit's - even where the
		// commit happens to carry a file of the same name. A repository that tracks
		// its node_modules is no exception: those files are listed by nothing here
		// and stay no-data, to be answered for by the lockfile that installed them
		// or not at all.
		if request.Project && gitVendored(relative) {
			continue
		}
		installed := path.Join(request.InstalledRoot, relative)
		file, shipped := observed.Files[installed]
		if !shipped || file.Digest != blobs[relative] {
			continue
		}
		original.Files = append(original.Files, GitOriginalFile{Path: installed, SHA256: file.Digest})
	}

	return original, nil
}

// gitVendored reports whether a package-relative path lies under a node_modules
// directory, at the root of the tree or anywhere below it.
func gitVendored(relative string) bool {
	return relative == "node_modules" || strings.HasPrefix(relative, "node_modules/") || strings.Contains(relative, "/node_modules/")
}

// resolvedGitRequest fills in what a project declares by not declaring it.
//
// A dependency is named by the lockfile that pins it, and every one of those facts is
// the caller's to state. A project is named by nothing outside itself: its locator is
// spelled here from the repository the mapping fetches - the upstream one, where that
// mapping is a listed mirror of it - in the one spelling this adapter reads back, and
// its identity is left to the package.json of the commit.
func resolvedGitRequest(request GitOriginalRequest, repository string) (GitOriginalRequest, error) {
	if !request.Project {
		if request.PackageName == "" || request.PackageVersion == "" {
			return request, fmt.Errorf("invalid: the declared package identity of %s is incomplete", request.Locator)
		}

		return request, nil
	}
	if request.Locator != "" || request.PackageName != "" || request.PackageVersion != "" {
		return request, fmt.Errorf("invalid: a project original is named by its own commit, not by a lock entry")
	}
	if !gitCommitRegexp.MatchString(request.Commit) {
		return request, fmt.Errorf("invalid: %q is not a full commit", request.Commit)
	}
	request.Locator = "git+https://" + repository + ".git#" + request.Commit

	return request, nil
}

// gitComponentID spells the identity of a Git-backed distribution the way the Node
// resolver spells a registry one: the pinned facts, hashed.
func gitComponentID(request GitOriginalRequest, commit string) string {
	data, _ := json.Marshal([]string{request.PackageName, request.PackageVersion, request.Locator, "git-commit:sha1:" + commit})
	sum := sha256.Sum256(data)

	return "node:" + hex.EncodeToString(sum[:])
}

// checkGitPackageIdentity holds the commit to the identity the lock entry claims for it:
// the package.json of the commit is the manifest of that very distribution, so a commit
// carrying another package, or another version of it, is not the pinned one.
func checkGitPackageIdentity(content []byte, request *GitOriginalRequest) ([]string, error) {
	if content == nil {
		return nil, fmt.Errorf("invalid: commit %s carries no package.json", request.Commit)
	}
	var manifest struct {
		Name    string                     `json:"name"`
		Version string                     `json:"version"`
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return nil, fmt.Errorf("invalid: package.json of commit %s is malformed: %w", request.Commit, err)
	}
	// A project has no lock entry to be held against, so the identity of the commit
	// is its identity - but it must have one.
	if request.Project {
		if manifest.Name == "" || manifest.Version == "" {
			return nil, fmt.Errorf("invalid: package.json of commit %s names no package", request.Commit)
		}
		request.PackageName, request.PackageVersion = manifest.Name, manifest.Version
	}
	if manifest.Name != request.PackageName || manifest.Version != request.PackageVersion {
		return nil, fmt.Errorf("invalid: commit %s holds %s@%s, not %s@%s", request.Commit, manifest.Name, manifest.Version, request.PackageName, request.PackageVersion)
	}

	var lifecycle []string
	for _, hook := range gitLifecycleHooks {
		if _, defined := manifest.Scripts[hook]; defined {
			lifecycle = append(lifecycle, hook)
		}
	}

	return lifecycle, nil
}

// verifiedGitTree reads the commit and the whole tree below it by hash, and answers the
// digest of every blob it serves, by package-relative path.
//
// Entries that are not plain file content — symlinks, submodule gitlinks — serve no
// bytes an installed file could be proven against and are left out, so a path they hold
// stays unknown rather than being bound to something else.
//
// The package.json at the root of the tree is also returned as its verified bytes: it is
// the manifest of the distribution itself, never one of a nested directory.
func verifiedGitTree(ctx context.Context, gitDir, commit string) (map[string]string, []byte, error) {
	repository, err := git.PlainOpen(gitDir)
	if err != nil {
		return nil, nil, fmt.Errorf("no-data: the object database of %s is unreadable: %w", gitDir, err)
	}
	objects := repository.Storer

	hash := plumbing.NewHash(commit)
	content, err := readVerifiedGitObject(objects, hash, plumbing.CommitObject)
	if err != nil {
		return nil, nil, err
	}
	tree, err := gitCommitTree(content, commit)
	if err != nil {
		return nil, nil, err
	}

	walk := gitTreeWalk{objects: objects, blobs: map[string]string{}}
	if err := walk.descend(ctx, tree, "", 0); err != nil {
		return nil, nil, err
	}

	return walk.blobs, walk.manifest, nil
}

type gitTreeWalk struct {
	objects  storer.EncodedObjectStorer
	blobs    map[string]string
	manifest []byte
}

func (walk *gitTreeWalk) descend(ctx context.Context, tree plumbing.Hash, prefix string, depth int) error {
	objects := walk.objects
	blobs := walk.blobs
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > gitTreeDepthLimit {
		return fmt.Errorf("invalid: tree %s nests deeper than %d levels", tree, gitTreeDepthLimit)
	}
	content, err := readVerifiedGitObject(objects, tree, plumbing.TreeObject)
	if err != nil {
		return err
	}
	entries, err := gitTreeEntries(content, tree)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := path.Join(prefix, entry.name)
		switch entry.mode {
		case gitModeTree:
			if err := walk.descend(ctx, entry.hash, name, depth+1); err != nil {
				return err
			}
		case gitModeBlob, gitModeExecutable, gitModeGroupWritable:
			blob, err := readVerifiedGitObject(objects, entry.hash, plumbing.BlobObject)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(blob)
			blobs[name] = "sha256:" + hex.EncodeToString(sum[:])
			if name == "package.json" {
				walk.manifest = blob
			}
		case gitModeSymlink, gitModeGitlink:
		default:
			return fmt.Errorf("invalid: tree %s holds %q with the unsupported mode %s", tree, name, entry.mode)
		}
	}

	return nil
}

type gitTreeEntry struct {
	mode string
	name string
	hash plumbing.Hash
}

// gitTreeEntries parses the binary tree object itself, `<mode> <name>\x00<20 raw bytes>`
// per entry, so that what is walked is what the verified bytes hold.
func gitTreeEntries(content []byte, tree plumbing.Hash) ([]gitTreeEntry, error) {
	var entries []gitTreeEntry
	for len(content) > 0 {
		end := bytes.IndexByte(content, 0)
		if end < 0 || len(content) < end+1+len(plumbing.ZeroHash) {
			return nil, fmt.Errorf("invalid: tree %s is truncated", tree)
		}
		head := gitTreeEntryRegexp.FindStringSubmatch(string(content[:end]))
		if head == nil {
			return nil, fmt.Errorf("invalid: tree %s holds a malformed entry", tree)
		}
		var hash plumbing.Hash
		copy(hash[:], content[end+1:end+1+len(hash)])
		entry := gitTreeEntry{mode: strings.TrimLeft(head[1], "0"), name: head[2], hash: hash}
		if entry.name == "." || entry.name == ".." || strings.ContainsRune(entry.name, '/') {
			return nil, fmt.Errorf("invalid: tree %s holds the unusable name %q", tree, entry.name)
		}
		entries = append(entries, entry)
		content = content[end+1+len(hash):]
	}

	return entries, nil
}

// gitCommitTree reads the tree of a commit from the commit object's own header, which
// git writes first and exactly once.
func gitCommitTree(content []byte, commit string) (plumbing.Hash, error) {
	head, _, _ := bytes.Cut(content, []byte("\n"))
	value, found := strings.CutPrefix(string(head), "tree ")
	if !found || len(value) != 2*len(plumbing.ZeroHash) {
		return plumbing.ZeroHash, fmt.Errorf("invalid: commit %s names no tree", commit)
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("invalid: commit %s names a malformed tree", commit)
	}
	var tree plumbing.Hash
	copy(tree[:], raw)

	return tree, nil
}

// readVerifiedGitObject reads one object and checks that its content is the content the
// hash names: the git object hash is recomputed over `<type> <length>\x00<content>` here,
// because an object store answers by file name and pack index, not by proof.
func readVerifiedGitObject(objects storer.EncodedObjectStorer, hash plumbing.Hash, expected plumbing.ObjectType) ([]byte, error) {
	object, err := objects.EncodedObject(plumbing.AnyObject, hash)
	if err != nil {
		return nil, fmt.Errorf("no-data: object %s is missing: %w", hash, err)
	}
	reader, err := object.Reader()
	if err != nil {
		return nil, fmt.Errorf("no-data: object %s is unreadable: %w", hash, err)
	}
	content, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("no-data: object %s is unreadable: %w", hash, err)
	}

	digest := sha1.New()
	digest.Write([]byte(object.Type().String() + " " + strconv.Itoa(len(content)) + "\x00"))
	digest.Write(content)
	if !bytes.Equal(digest.Sum(nil), hash[:]) {
		return nil, fmt.Errorf("invalid: object %s does not hash to its name", hash)
	}
	if object.Type() != expected {
		return nil, fmt.Errorf("invalid: object %s is a %s where a %s is pinned", hash, object.Type(), expected)
	}

	return content, nil
}

// gitRepositoryIdentity reduces a remote to the repository it names, `host/owner/repo`,
// so that the same repository fetched over another transport is recognized as the same
// one. Only transport spelling is normalized: a different host, owner or repository name
// stays a different repository, and so does a fork of it.
func gitRepositoryIdentity(remote string) (string, error) {
	if remote == "" {
		return "", fmt.Errorf("no remote is given")
	}
	if !strings.Contains(remote, "://") {
		host, repository, scp := strings.Cut(remote, ":")
		if !scp || strings.Contains(host, "/") || repository == "" {
			return "", fmt.Errorf("unsupported remote spelling")
		}
		if _, user, found := strings.Cut(host, "@"); found {
			host = user
		}

		return gitRepositoryKey(host, repository)
	}
	parsed, err := url.Parse(remote)
	if err != nil {
		return "", fmt.Errorf("unparsable remote")
	}
	switch parsed.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return "", fmt.Errorf("unsupported transport %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if port := parsed.Port(); port != "" && !gitDefaultPort(parsed.Scheme, port) {
		host += ":" + port
	}

	return gitRepositoryKey(host, parsed.Path)
}

func gitDefaultPort(scheme, port string) bool {
	return map[string]string{"https": "443", "http": "80", "ssh": "22", "git": "9418"}[scheme] == port
}

func gitRepositoryKey(host, repository string) (string, error) {
	host = strings.ToLower(host)
	repository = strings.Trim(repository, "/")
	repository = strings.TrimSuffix(repository, ".git")
	if host == "" || repository == "" || strings.Contains(repository, "//") {
		return "", fmt.Errorf("names no repository")
	}

	return host + "/" + repository, nil
}
