package nativegate

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// gitFixtureCommand runs git in one directory of a fixture, with the environment of a
// repository nobody else configured.
func gitFixtureCommand(dir string) func(input string, args ...string) string {
	return func(input string, args ...string) string {
		ginkgo.GinkgoHelper()
		command := exec.Command("git", args...)
		command.Dir = dir
		command.Stdin = strings.NewReader(input)
		command.Env = append(os.Environ(),
			"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_AUTHOR_DATE=2020-01-01T00:00:00Z",
			"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid", "GIT_COMMITTER_DATE=2020-01-01T00:00:00Z",
		)
		out, err := command.CombinedOutput()
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

		return strings.TrimSpace(string(out))
	}
}

// gitFixtureWorktree builds a repository with a package tree at one commit and answers
// its directory and that commit.
func gitFixtureWorktree(manifest string, files map[string]string) (string, string) {
	ginkgo.GinkgoHelper()
	work := filepath.Join(ginkgo.GinkgoT().TempDir(), "work")
	gomega.Expect(os.MkdirAll(work, 0o755)).To(gomega.Succeed())
	run := gitFixtureCommand(work)
	run("", "init", "-q", "-b", "main", ".")
	writeFixtureFile(filepath.Join(work, "package.json"), manifest)
	for name, body := range files {
		writeFixtureFile(filepath.Join(work, name), body)
	}
	gomega.Expect(os.Symlink("index.js", filepath.Join(work, "link.js"))).To(gomega.Succeed())
	run("", "add", "-A")
	// A gitlink without a submodule checkout: the entry is all the tree holds anyway.
	run("", "update-index", "--add", "--cacheinfo", "160000,0123456789abcdef0123456789abcdef01234567,vendor")
	run("", "commit", "-q", "-m", "fixture")

	return work, run("", "rev-parse", "HEAD")
}

// gitFixtureRepository answers the bare clone of such a repository, which is what DK
// fetches a mapping into, plus the commit.
func gitFixtureRepository(manifest string, files map[string]string) (string, string) {
	ginkgo.GinkgoHelper()
	work, commit := gitFixtureWorktree(manifest, files)
	bare := filepath.Join(filepath.Dir(work), "bare.git")
	gitFixtureCommand(filepath.Dir(work))("", "clone", "-q", "--bare", work, bare)

	return bare, commit
}

func writeFixtureFile(name, body string) {
	ginkgo.GinkgoHelper()
	gomega.Expect(os.MkdirAll(filepath.Dir(name), 0o755)).To(gomega.Succeed())
	gomega.Expect(os.WriteFile(name, []byte(body), 0o644)).To(gomega.Succeed())
}

// rewriteLooseObject replaces the content a loose object file holds, leaving the name it
// is stored under alone: the store answers with bytes that are not the ones the hash names.
func rewriteLooseObject(gitDir, hash, content string) {
	ginkgo.GinkgoHelper()
	name := filepath.Join(gitDir, "objects", hash[:2], hash[2:])
	gomega.Expect(name).To(gomega.BeAnExistingFile())
	var packed bytes.Buffer
	writer := zlib.NewWriter(&packed)
	_, err := fmt.Fprintf(writer, "blob %d\x00%s", len(content), content)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	// git stores loose objects read-only, as the content-addressed files they are.
	gomega.Expect(os.Chmod(name, 0o644)).To(gomega.Succeed())
	gomega.Expect(os.WriteFile(name, packed.Bytes(), 0o644)).To(gomega.Succeed())
}

func gitFixtureBlob(gitDir, commit, name string) string {
	ginkgo.GinkgoHelper()
	command := exec.Command("git", "--git-dir", gitDir, "rev-parse", commit+":"+name)
	out, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

	return strings.TrimSpace(string(out))
}

func originalPaths(original *GitOriginal) []string {
	paths := []string{}
	for _, file := range original.Files {
		paths = append(paths, file.Path)
	}

	return paths
}

const gitFixtureManifest = `{"name":"argo-ui","version":"1.0.0","scripts":{"prepare":"tsc","test":"jest"}}`

var _ = ginkgo.Describe("Verifying a Git-pinned Node original", func() {
	fixtureRequest := func(bare, commit string) GitOriginalRequest {
		return GitOriginalRequest{
			GitDir:         bare,
			RemoteURL:      "https://github.com/argoproj/argo-ui.git",
			Commit:         commit,
			Locator:        "git+https://github.com/argoproj/argo-ui.git#" + commit,
			PackageName:    "argo-ui",
			PackageVersion: "1.0.0",
			InstalledRoot:  "/app/node_modules/argo-ui",
		}
	}

	ginkgo.It("lists the installed files the commit serves, and nothing it cannot hold to a blob", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{
			"index.js":     "module.exports = 1;\n",
			"src/app.tsx":  "export const app = 1;\n",
			"src/only.tsx": "shipped by the repository\n",
			"README.md":    "not installed at all\n",
		})
		observed := fixtureIndex(map[string]string{
			"/app/node_modules/argo-ui/package.json": gitFixtureManifest,
			"/app/node_modules/argo-ui/index.js":     "module.exports = 1;\n",
			"/app/node_modules/argo-ui/src/app.tsx":  "export const app = 1;\n",
			// The target the tree records for the symlink, as a file of its own.
			"/app/node_modules/argo-ui/link.js": "index.js",
			// A gitlink, an install-script output, bytes rewritten after the
			// checkout, and a path the commit does not hold at all.
			"/app/node_modules/argo-ui/vendor":       "whatever a submodule left",
			"/app/node_modules/argo-ui/dist/app.js":  "built by the install script",
			"/app/node_modules/argo-ui/src/only.tsx": "rewritten after the checkout\n",
			"/app/node_modules/argo-ui/src/edit.tsx": "export const app = 1;\n",
		})

		original, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.Files).To(gomega.Equal([]GitOriginalFile{
			{Path: "/app/node_modules/argo-ui/index.js", SHA256: digest([]byte("module.exports = 1;\n"))},
			{Path: "/app/node_modules/argo-ui/package.json", SHA256: digest([]byte(gitFixtureManifest))},
			{Path: "/app/node_modules/argo-ui/src/app.tsx", SHA256: digest([]byte("export const app = 1;\n"))},
		}))
		gomega.Expect(original.Lifecycle).To(gomega.Equal([]string{"prepare"}))
		gomega.Expect(original.Component).To(gomega.Equal(shared.BuildComponent{
			ID: original.Component.ID, Name: "argo-ui", Version: "1.0.0",
			Source: shared.BuildSource{Kind: "node", Locator: "git+https://github.com/argoproj/argo-ui.git#" + commit, Checksum: "git-commit:sha1:" + commit},
		}))
		gomega.Expect(original.Component.ID).To(gomega.HavePrefix("node:"))
	})

	ginkgo.It("reads a tree written with the legacy octal modes", func(ctx ginkgo.SpecContext) {
		work := filepath.Join(ginkgo.GinkgoT().TempDir(), "work")
		gomega.Expect(os.MkdirAll(work, 0o755)).To(gomega.Succeed())
		run := gitFixtureCommand(work)
		run("", "init", "-q", "-b", "main", ".")
		blob := func(body string) []byte {
			raw, err := hex.DecodeString(run(body, "hash-object", "-w", "-t", "blob", "--stdin"))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			return raw
		}
		tree := func(entries []byte) []byte {
			raw, err := hex.DecodeString(run(string(entries), "hash-object", "-w", "-t", "tree", "--literally", "--stdin"))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			return raw
		}
		// Git before 1.6 wrote a directory as 040000 and a group-writable file as
		// 100664; both still occur in the history of long-lived repositories.
		sub := tree(append([]byte("100664 app.tsx\x00"), blob("export const app = 1;\n")...))
		root := append(append([]byte("100664 index.js\x00"), blob("module.exports = 1;\n")...), append([]byte("100644 package.json\x00"), blob(gitFixtureManifest)...)...)
		root = append(root, append([]byte("040000 src\x00"), sub...)...)
		commit := run("", "commit-tree", "-m", "legacy", hex.EncodeToString(tree(root)))
		run("", "update-ref", "refs/heads/main", commit)
		bare := filepath.Join(filepath.Dir(work), "legacy.git")
		gitFixtureCommand(filepath.Dir(work))("", "clone", "-q", "--bare", work, bare)
		observed := fixtureIndex(map[string]string{
			"/app/node_modules/argo-ui/package.json": gitFixtureManifest,
			"/app/node_modules/argo-ui/index.js":     "module.exports = 1;\n",
			"/app/node_modules/argo-ui/src/app.tsx":  "export const app = 1;\n",
		})

		original, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originalPaths(original)).To(gomega.Equal([]string{
			"/app/node_modules/argo-ui/index.js",
			"/app/node_modules/argo-ui/package.json",
			"/app/node_modules/argo-ui/src/app.tsx",
		}))
	})

	ginkgo.It("reads the commit out of a pack, deltas included", func(ctx ginkgo.SpecContext) {
		base := strings.Repeat("export const line = 1;\n", 400)
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{
			"index.js":   base,
			"variant.js": base + "export const extra = 2;\n",
		})
		run := gitFixtureCommand(bare)
		run("", "repack", "-ad", "--window=10", "--depth=50")
		run("", "prune-packed")
		loose, err := filepath.Glob(filepath.Join(bare, "objects", "??", "*"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(loose).To(gomega.BeEmpty(), "every object must be read out of the pack")
		index, err := filepath.Glob(filepath.Join(bare, "objects", "pack", "*.idx"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index).To(gomega.HaveLen(1))
		gomega.Expect(run("", "verify-pack", "-v", index[0])).To(gomega.ContainSubstring("delta"))
		observed := fixtureIndex(map[string]string{
			"/app/node_modules/argo-ui/index.js":   base,
			"/app/node_modules/argo-ui/variant.js": base + "export const extra = 2;\n",
		})

		original, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originalPaths(original)).To(gomega.Equal([]string{
			"/app/node_modules/argo-ui/index.js",
			"/app/node_modules/argo-ui/variant.js",
		}))
	})

	ginkgo.It("reads a shallow mirror fetched at the pinned commit", func(ctx ginkgo.SpecContext) {
		work, commit := gitFixtureWorktree(gitFixtureManifest, map[string]string{"index.js": "module.exports = 1;\n"})
		shallow := filepath.Join(filepath.Dir(work), "shallow.git")
		// A local clone hardlinks the whole object database, so the mirror is
		// fetched over a transport that honors the depth.
		gitFixtureCommand(filepath.Dir(work))("", "clone", "-q", "--depth", "1", "--bare", "file://"+work, shallow)
		gomega.Expect(filepath.Join(shallow, "shallow")).To(gomega.BeAnExistingFile())
		observed := fixtureIndex(map[string]string{
			"/app/node_modules/argo-ui/package.json": gitFixtureManifest,
			"/app/node_modules/argo-ui/index.js":     "module.exports = 1;\n",
		})

		original, err := VerifyGitOriginal(ctx, fixtureRequest(shallow, commit), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originalPaths(original)).To(gomega.Equal([]string{
			"/app/node_modules/argo-ui/index.js",
			"/app/node_modules/argo-ui/package.json",
		}))
	})

	ginkgo.It("accepts the same repository fetched over another transport", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{"index.js": "body\n"})
		observed := fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"})
		for _, remote := range []string{
			"ssh://git@github.com/argoproj/argo-ui.git",
			"git@github.com:argoproj/argo-ui.git",
			"https://user:token@github.com/argoproj/argo-ui",
		} {
			request := fixtureRequest(bare, commit)
			request.RemoteURL = remote
			original, err := VerifyGitOriginal(ctx, request, observed)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), remote)
			gomega.Expect(original.Files).To(gomega.HaveLen(1), remote)
		}
	})

	ginkgo.It("refuses another repository, however it is spelled", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{"index.js": "body\n"})
		observed := fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"})
		for _, remote := range []string{
			"https://github.com/fork-owner/argo-ui.git",
			"https://github.com/argoproj/argo-ui-fork.git",
			"https://gitlab.example/argoproj/argo-ui.git",
			"https://github.com:8443/argoproj/argo-ui.git",
		} {
			request := fixtureRequest(bare, commit)
			request.RemoteURL = remote
			_, err := VerifyGitOriginal(ctx, request, observed)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: the mapping fetches")), remote)
		}
	})

	ginkgo.It("refuses a mapping pinned to another commit and a locator pinning no commit", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{"index.js": "body\n"})
		observed := fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"})

		other := fixtureRequest(bare, commit)
		other.Commit = strings.Repeat("a", 40)
		_, err := VerifyGitOriginal(ctx, other, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: the mapping is pinned to")))

		for _, locator := range []string{
			"git+https://github.com/argoproj/argo-ui.git#" + commit[:8],
			"git+https://github.com/argoproj/argo-ui.git#" + strings.ToUpper(commit),
			"git+https://github.com/argoproj/argo-ui.git#main",
			"git+https://github.com/argoproj/argo-ui.git",
			"https://github.com/argoproj/argo-ui.git#" + commit,
		} {
			request := fixtureRequest(bare, commit)
			request.Locator = locator
			_, err := VerifyGitOriginal(ctx, request, observed)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not a Git locator pinned to a full commit")), locator)
		}
	})

	ginkgo.It("records every install and publish hook the verified manifest defines", func(ctx ginkgo.SpecContext) {
		manifest := `{"name":"argo-ui","version":"1.0.0","scripts":{"test":"jest","postpack":"c","prepublish":"a","install":"i","prepack":"b","preinstall":"p","prepare":"t","postinstall":"o"}}`
		bare, commit := gitFixtureRepository(manifest, map[string]string{"index.js": "body\n"})

		original, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"}))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.Lifecycle).To(gomega.Equal([]string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack"}))
	})

	ginkgo.It("refuses a commit whose own package.json carries another identity", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(`{"name":"argo-ui","version":"1.0.1"}`, map[string]string{"index.js": "body\n"})
		observed := fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"})

		_, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("holds argo-ui@1.0.1, not argo-ui@1.0.0")))
	})

	ginkgo.It("refuses an object the store does not hold the named bytes for", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{"index.js": "module.exports = 1;\n"})
		observed := fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "module.exports = 2;\n"})
		blob := gitFixtureBlob(bare, commit, "index.js")
		rewriteLooseObject(bare, blob, "module.exports = 2;\n")

		_, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(fmt.Sprintf("invalid: object %s does not hash to its name", blob))))
	})

	ginkgo.It("refuses an incomplete observation and an unfetched object database", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{"index.js": "body\n"})
		observed := fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"})

		_, err := VerifyGitOriginal(ctx, fixtureRequest(bare, commit), &shippedscope.FileIndex{Incomplete: true})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: a Git original needs the complete observed file index")))

		empty := fixtureRequest(bare, commit)
		empty.GitDir = ginkgo.GinkgoT().TempDir()
		_, err = VerifyGitOriginal(ctx, empty, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: the object database")))
	})
})

var _ = ginkgo.Describe("Verifying the stage's own sources as a Git original", func() {
	const manifest = `{"name":"redoc","version":"2.4.0","scripts":{"prepare":"husky install","build":"webpack"}}`

	projectRequest := func(bare, commit string) GitOriginalRequest {
		return GitOriginalRequest{
			GitDir:    bare,
			RemoteURL: "git@github.com:Redocly/redoc.git",
			Commit:    commit,
			// A project names itself: no locator, no identity of its own.
			InstalledRoot: "/app",
			Project:       true,
		}
	}

	ginkgo.It("takes its identity from the commit and spells its locator from the mapping", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(manifest, map[string]string{
			"src/index.ts": "export const app = 1;\n",
		})
		observed := fixtureIndex(map[string]string{
			"/app/package.json": manifest,
			"/app/src/index.ts": "export const app = 1;\n",
		})

		original, err := VerifyGitOriginal(ctx, projectRequest(bare, commit), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.Component).To(gomega.Equal(shared.BuildComponent{
			ID: original.Component.ID, Name: "redoc", Version: "2.4.0",
			Source: shared.BuildSource{
				Kind: "node",
				// The ssh remote of the mapping, spelled as the one locator this
				// adapter reads back, with the owner's own case kept.
				Locator:  "git+https://github.com/Redocly/redoc.git#" + commit,
				Checksum: "git-commit:sha1:" + commit,
			},
		}))
		gomega.Expect(originalPaths(original)).To(gomega.Equal([]string{"/app/package.json", "/app/src/index.ts"}))
		gomega.Expect(original.Lifecycle).To(gomega.Equal([]string{"prepare"}))
	})

	// What a project vendors under its own root is the installer's, even where the
	// commit happens to carry a file of that very name and those very bytes.
	ginkgo.It("lists nothing a node_modules directory of the project holds", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(manifest, map[string]string{
			"src/index.ts":                   "export const app = 1;\n",
			"node_modules/left/index.js":     "committed by mistake\n",
			"src/node_modules/deep/index.js": "committed deeper\n",
		})
		observed := fixtureIndex(map[string]string{
			"/app/package.json":                   manifest,
			"/app/src/index.ts":                   "export const app = 1;\n",
			"/app/node_modules/left/index.js":     "committed by mistake\n",
			"/app/src/node_modules/deep/index.js": "committed deeper\n",
		})

		original, err := VerifyGitOriginal(ctx, projectRequest(bare, commit), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originalPaths(original)).To(gomega.Equal([]string{"/app/package.json", "/app/src/index.ts"}))
	})

	ginkgo.It("refuses a project that names itself by a lock entry", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(manifest, map[string]string{"src/index.ts": "export const app = 1;\n"})
		observed := fixtureIndex(map[string]string{"/app/package.json": manifest})

		for _, named := range []func(GitOriginalRequest) GitOriginalRequest{
			func(r GitOriginalRequest) GitOriginalRequest {
				r.Locator = "git+https://github.com/Redocly/redoc.git#" + commit
				return r
			},
			func(r GitOriginalRequest) GitOriginalRequest { r.PackageName = "redoc"; return r },
			func(r GitOriginalRequest) GitOriginalRequest { r.PackageVersion = "2.4.0"; return r },
		} {
			_, err := VerifyGitOriginal(ctx, named(projectRequest(bare, commit)), observed)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("a project original is named by its own commit, not by a lock entry")))
		}
	})

	ginkgo.It("refuses a commit whose package.json names no package", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(`{"private":true}`, map[string]string{"src/index.ts": "export const app = 1;\n"})
		observed := fixtureIndex(map[string]string{"/app/package.json": `{"private":true}`})

		_, err := VerifyGitOriginal(ctx, projectRequest(bare, commit), observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("names no package")))
	})

	ginkgo.It("refuses a mapping remote that names no repository, and a commit that is not one", func(ctx ginkgo.SpecContext) {
		bare, commit := gitFixtureRepository(manifest, map[string]string{"src/index.ts": "export const app = 1;\n"})
		observed := fixtureIndex(map[string]string{"/app/package.json": manifest})

		broken := projectRequest(bare, commit)
		broken.RemoteURL = "file:///srv/redoc"
		_, err := VerifyGitOriginal(ctx, broken, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported transport")))

		short := projectRequest(bare, commit)
		short.Commit = commit[:12]
		_, err = VerifyGitOriginal(ctx, short, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not a full commit")))
	})
})

var _ = ginkgo.Describe("Verifying a Git original fetched from a listed mirror", func() {
	mirrors := []GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "github.com"}}
	mirrored := func(bare, commit, remote string) GitOriginalRequest {
		return GitOriginalRequest{
			GitDir:         bare,
			RemoteURL:      remote,
			Commit:         commit,
			Locator:        "git+https://github.com/argoproj/argo-ui.git#" + commit,
			Mirrors:        mirrors,
			PackageName:    "argo-ui",
			PackageVersion: "1.0.0",
			InstalledRoot:  "/app/node_modules/argo-ui",
		}
	}
	fixture := func() (string, string, *shippedscope.FileIndex) {
		ginkgo.GinkgoHelper()
		bare, commit := gitFixtureRepository(gitFixtureManifest, map[string]string{"index.js": "body\n"})

		return bare, commit, fixtureIndex(map[string]string{"/app/node_modules/argo-ui/index.js": "body\n"})
	}

	// The objects are the commit's either way, so the component stays the one the
	// lockfile named: only where they were fetched from differs, and that is recorded
	// as evidence beside it rather than as a second identity.
	ginkgo.It("accepts the mirror the configuration lists and keeps the locator of the lock", func(ctx ginkgo.SpecContext) {
		bare, commit, observed := fixture()

		original, err := VerifyGitOriginal(ctx, mirrored(bare, commit, "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git"), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.Component.Source).To(gomega.Equal(shared.BuildSource{
			Kind: "node", Locator: "git+https://github.com/argoproj/argo-ui.git#" + commit, Checksum: "git-commit:sha1:" + commit,
		}))
		gomega.Expect(original.Files).To(gomega.HaveLen(1))
		gomega.Expect(original.Mirror).To(gomega.Equal("https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git"))
	})

	// Whatever the fetch authenticated itself with is the build's business: a job
	// token in the url of the mirror is never written into the evidence.
	ginkgo.It("records the mirror it fetched from without the credentials of the fetch", func(ctx ginkgo.SpecContext) {
		bare, commit, observed := fixture()

		for remote, recorded := range map[string]string{
			"https://gitlab-ci-token:secret@fox.flant.com/deckhouse/3p/argoproj/argo-ui.git": "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git",
			"ssh://git@fox.flant.com/deckhouse/3p/argoproj/argo-ui.git":                      "ssh://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git",
			"git@fox.flant.com:deckhouse/3p/argoproj/argo-ui.git":                            "fox.flant.com:deckhouse/3p/argoproj/argo-ui.git",
			"https://FOX.flant.com/deckhouse/3p/argoproj/argo-ui.git":                        "https://FOX.flant.com/deckhouse/3p/argoproj/argo-ui.git",
		} {
			original, err := VerifyGitOriginal(ctx, mirrored(bare, commit, remote), observed)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), remote)
			gomega.Expect(original.Mirror).To(gomega.Equal(recorded), remote)
			gomega.Expect(original.Mirror).NotTo(gomega.ContainSubstring("secret"))
		}
	})

	ginkgo.It("records no mirror for a mapping that fetches the pinned repository itself", func(ctx ginkgo.SpecContext) {
		bare, commit, observed := fixture()

		original, err := VerifyGitOriginal(ctx, mirrored(bare, commit, "https://github.com/argoproj/argo-ui.git"), observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.Mirror).To(gomega.BeEmpty())
	})

	// A mirror buys the host it is fetched from and nothing else: below its prefix it
	// must be the very repository the locator pins, and a host, a prefix or an
	// upstream nothing lists is a different repository as before.
	ginkgo.DescribeTable("refuses what the configuration does not list", func(ctx ginkgo.SpecContext, remote string, listed []GitMirror) {
		bare, commit, observed := fixture()
		request := mirrored(bare, commit, remote)
		request.Mirrors = listed

		_, err := VerifyGitOriginal(ctx, request, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: the mapping fetches")))
	},
		ginkgo.Entry("no mirror is listed at all", "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git", nil),
		ginkgo.Entry("another host", "https://mirror.example/deckhouse/3p/argoproj/argo-ui.git", mirrors),
		ginkgo.Entry("another path of the mirror", "https://fox.flant.com/deckhouse/other/argoproj/argo-ui.git", mirrors),
		ginkgo.Entry("the prefix itself as a repository", "https://fox.flant.com/deckhouse/3p.git", mirrors),
		ginkgo.Entry("another owner below the prefix", "https://fox.flant.com/deckhouse/3p/fork-owner/argo-ui.git", mirrors),
		ginkgo.Entry("another repository below the prefix", "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui-fork.git", mirrors),
		ginkgo.Entry("a prefix of the listed prefix", "https://fox.flant.com/deckhouse/3party/argoproj/argo-ui.git", mirrors),
		ginkgo.Entry("another upstream than the locator pins", "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git",
			[]GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "gitlab.example"}}),
	)

	// An entry nothing can match would silently narrow what is accepted, so a
	// malformed allowlist refuses the verification it was supplied for.
	ginkgo.DescribeTable("refuses a malformed allowlist", func(ctx ginkgo.SpecContext, listed []GitMirror, message string) {
		bare, commit, observed := fixture()
		request := mirrored(bare, commit, "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git")
		request.Mirrors = listed

		_, err := VerifyGitOriginal(ctx, request, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(message)))
	},
		ginkgo.Entry("credentials in the host", []GitMirror{{Host: "gitlab-ci-token:secret@fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "github.com"}},
			`gitMirror 0: host "gitlab-ci-token:secret@fox.flant.com" is not a bare host`),
		ginkgo.Entry("a transport in the host", []GitMirror{{Host: "https://fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "github.com"}},
			"host \"https://fox.flant.com\" is not a bare host"),
		ginkgo.Entry("a path in the host", []GitMirror{{Host: "fox.flant.com/deckhouse", PathPrefix: "3p", UpstreamHost: "github.com"}},
			"host \"fox.flant.com/deckhouse\" is not a bare host"),
		ginkgo.Entry("no host", []GitMirror{{PathPrefix: "deckhouse/3p", UpstreamHost: "github.com"}}, `host "" is not a bare host`),
		ginkgo.Entry("no upstream host", []GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p"}}, `upstreamHost "" is not a bare host`),
		ginkgo.Entry("credentials in the upstream host", []GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "user@github.com"}},
			`upstreamHost "user@github.com" is not a bare host`),
		ginkgo.Entry("no prefix", []GitMirror{{Host: "fox.flant.com", UpstreamHost: "github.com"}}, `pathPrefix "" is not a path of the mirror host`),
		ginkgo.Entry("an absolute prefix", []GitMirror{{Host: "fox.flant.com", PathPrefix: "/deckhouse/3p", UpstreamHost: "github.com"}},
			`pathPrefix "/deckhouse/3p" is not a path of the mirror host`),
		ginkgo.Entry("a trailing slash", []GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p/", UpstreamHost: "github.com"}},
			`pathPrefix "deckhouse/3p/" is not a path of the mirror host`),
		ginkgo.Entry("a relative segment", []GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/../3p", UpstreamHost: "github.com"}},
			`pathPrefix "deckhouse/../3p" is not a path of the mirror host`),
		ginkgo.Entry("the same mirror twice", []GitMirror{
			{Host: "fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "github.com"},
			{Host: "FOX.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "gitlab.example"},
		}, "gitMirror 1: fox.flant.com/deckhouse/3p is listed more than once"),
	)

	// The project is named by nothing but its own mapping, so a mirrored mapping must
	// spell the repository the mirror serves, not the mirror.
	ginkgo.It("spells the locator of a mirrored project from the repository the mirror serves", func(ctx ginkgo.SpecContext) {
		const manifest = `{"name":"redoc","version":"2.4.0"}`
		bare, commit := gitFixtureRepository(manifest, map[string]string{"src/index.ts": "export const app = 1;\n"})
		observed := fixtureIndex(map[string]string{"/app/package.json": manifest})

		original, err := VerifyGitOriginal(ctx, GitOriginalRequest{
			GitDir:        bare,
			RemoteURL:     "https://fox.flant.com/deckhouse/3p/Redocly/redoc.git",
			Commit:        commit,
			Mirrors:       mirrors,
			InstalledRoot: "/app",
			Project:       true,
		}, observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.Component.Source.Locator).To(gomega.Equal("git+https://github.com/Redocly/redoc.git#" + commit))
		gomega.Expect(original.Mirror).To(gomega.Equal("https://fox.flant.com/deckhouse/3p/Redocly/redoc.git"))
	})
})
