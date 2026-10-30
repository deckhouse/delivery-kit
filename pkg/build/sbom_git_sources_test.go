package build

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/git_repo"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/werf"
)

// localGitRepo is a mapping repository that is somebody's working checkout rather than
// a mirror DK fetched: it answers nothing about where it came from.
type localGitRepo struct {
	git_repo.GitRepo
}

func (localGitRepo) IsLocal() bool { return true }

// fixtureRemoteRepo opens the repository DK would open for a `git:` mapping of that url
// and fetches the given work tree into the mirror DK would fetch it into. What comes
// back is the very type a build holds, so the url it is held against is the one the
// config names - not whatever the mirror's own config happens to say.
func fixtureRemoteRepo(url, work string) *git_repo.Remote {
	ginkgo.GinkgoHelper()
	// The mirror of a remote repository lives in werf's own cache, so the cache of
	// this spec is a directory of its own and the machine's is left alone.
	gomega.Expect(werf.Init("", ginkgo.GinkgoT().TempDir())).To(gomega.Succeed())
	ginkgo.DeferCleanup(func() { gomega.Expect(werf.Init("", "")).To(gomega.Succeed()) })
	repo, err := git_repo.OpenRemoteRepo("fixture", url, nil)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	clone := repo.GetClonePath()
	gomega.Expect(os.MkdirAll(filepath.Dir(clone), 0o755)).To(gomega.Succeed())
	if work != "" {
		gitFixtureCommand(filepath.Dir(clone), "clone", "-q", "--bare", work, clone)
	}

	return repo
}

// gitFixtureCommand runs one git command of a fixture repository, with the environment
// of the machine kept out of it.
func gitFixtureCommand(dir string, args ...string) string {
	ginkgo.GinkgoHelper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_AUTHOR_DATE=2020-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid", "GIT_COMMITTER_DATE=2020-01-01T00:00:00Z",
	)
	out, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

	return strings.TrimSpace(string(out))
}

// gitMappingFixture builds a repository holding one package at one commit and answers
// its work tree, plus that commit.
func gitMappingFixture(manifest, body string) (string, string) {
	ginkgo.GinkgoHelper()
	root := ginkgo.GinkgoT().TempDir()
	work := filepath.Join(root, "work")
	gomega.Expect(os.MkdirAll(work, 0o755)).To(gomega.Succeed())
	gitFixtureCommand(work, "init", "-q", "-b", "main", ".")
	gomega.Expect(os.WriteFile(filepath.Join(work, "package.json"), []byte(manifest), 0o644)).To(gomega.Succeed())
	gomega.Expect(os.WriteFile(filepath.Join(work, "index.js"), []byte(body), 0o644)).To(gomega.Succeed())
	gitFixtureCommand(work, "add", "-A")
	gitFixtureCommand(work, "commit", "-q", "-m", "fixture")

	return work, gitFixtureCommand(work, "rev-parse", "HEAD")
}

func fixtureGitImage(mappings ...*stage.GitMapping) *image.Image {
	ginkgo.GinkgoHelper()
	img, err := image.NewImage(context.Background(), "linux/amd64", "app", image.NoBaseImage, image.ImageOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gitStage := stage.NewGitArchiveStage(&stage.NewGitArchiveStageOptions{}, &stage.BaseStageOptions{TargetPlatform: "linux/amd64"})
	gitStage.SetGitMappings(mappings)
	img.SetStages([]stage.Interface{gitStage})

	return img
}

func fixtureInstalledIndex(files map[string]string) *shippedscope.FileIndex {
	index := &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{}}
	for name, body := range files {
		sum := sha256.Sum256([]byte(body))
		index.Files[name] = shippedscope.File{Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(body))}
	}

	return index
}

var _ = ginkgo.Describe("producer git sources", func() {
	const manifest = `{"name":"argo-ui","version":"1.0.0"}`
	const body = "export const ui = 1;\n"

	binding := func(commit string) sbomBuildContextGitSource {
		return sbomBuildContextGitSource{
			To:             "/src/originals/argo-ui",
			Locator:        "git+https://github.com/argoproj/argo-ui.git#" + commit,
			InstalledPath:  "/app/node_modules/argo-ui",
			PackageName:    "argo-ui",
			PackageVersion: "1.0.0",
		}
	}
	mapping := func(commit, work string) *stage.GitMapping {
		gitMapping := stage.NewGitMapping()
		gitMapping.To = "/src/originals/argo-ui"
		gitMapping.Commit = commit
		gitMapping.SetGitRepo(fixtureRemoteRepo("https://github.com/argoproj/argo-ui.git", work))

		return gitMapping
	}
	observed := fixtureInstalledIndex(map[string]string{
		"/app/node_modules/argo-ui/package.json": manifest,
		"/app/node_modules/argo-ui/index.js":     body,
	})

	ginkgo.It("verifies the mapping the binding names and carries its files into the manifest", func(ctx ginkgo.SpecContext) {
		clone, commit := gitMappingFixture(manifest, body)
		img := fixtureGitImage(mapping(commit, clone))

		originals, identities, err := producerGitSources(ctx, img, []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.Source.Checksum).To(gomega.Equal("git-commit:sha1:" + commit))
		gomega.Expect(originals[0].Files).To(gomega.HaveLen(2))
		// The resolved mapping takes part in the stage checksum, not only the
		// declaration that asked for it.
		gomega.Expect(identities).To(gomega.ContainElement(commit))
		gomega.Expect(identities).To(gomega.ContainElement("https://github.com/argoproj/argo-ui.git"))
	})

	ginkgo.It("refuses a binding no single fetched mapping answers", func(ctx ginkgo.SpecContext) {
		clone, commit := gitMappingFixture(manifest, body)

		_, _, err := producerGitSources(ctx, fixtureGitImage(), []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no git mapping at /src/originals/argo-ui")))

		_, _, err = producerGitSources(ctx, fixtureGitImage(mapping(commit, clone), mapping(commit, clone)), []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("more than one git mapping")))

		unpinned := mapping("", clone)
		_, _, err = producerGitSources(ctx, fixtureGitImage(unpinned), []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not pinned to a commit")))

		checkout := mapping(commit, clone)
		checkout.SetGitRepo(localGitRepo{})
		_, _, err = producerGitSources(ctx, fixtureGitImage(checkout), []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("adds a local checkout, which is not a verifiable source")))

		// A mirror DK never fetched into: the mapping names a repository whose
		// objects are not there to be read.
		unfetched := mapping(commit, clone)
		unfetched.SetGitRepo(fixtureRemoteRepo("https://github.com/argoproj/argo-ui.git", ""))
		_, _, err = producerGitSources(ctx, fixtureGitImage(unfetched), []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})

	ginkgo.It("refuses a mapping that fetches another repository than the locator pins", func(ctx ginkgo.SpecContext) {
		clone, commit := gitMappingFixture(manifest, body)
		forked := mapping(commit, clone)
		forked.SetGitRepo(fixtureRemoteRepo("https://github.com/fork-owner/argo-ui.git", clone))

		_, _, err := producerGitSources(ctx, fixtureGitImage(forked), []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("git source /src/originals/argo-ui: invalid: the mapping fetches")))
	})
})

var _ = ginkgo.Describe("producer git sources of the project itself", func() {
	const manifest = `{"name":"redoc","version":"2.4.0"}`
	const body = "export const app = 1;\n"
	const url = "https://github.com/Redocly/redoc.git"

	binding := sbomBuildContextGitSource{To: "/app", Kind: "project", InstalledPath: "/app"}
	mapping := func(commit, work string) *stage.GitMapping {
		gitMapping := stage.NewGitMapping()
		gitMapping.To = "/app"
		gitMapping.Add = "/"
		gitMapping.Commit = commit
		gitMapping.SetGitRepo(fixtureRemoteRepo(url, work))

		return gitMapping
	}
	observed := fixtureInstalledIndex(map[string]string{
		"/app/package.json": manifest,
		"/app/index.js":     body,
	})

	// A production rebuild stage adds the project with an ordinary remote `git:`
	// mapping pinned by commit. That mapping, and the url the config names it by,
	// are the whole of what the project is held to be.
	ginkgo.It("verifies the project against the remote mapping that adds it", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)

		originals, identities, err := producerGitSources(ctx, fixtureGitImage(mapping(commit, work)), []sbomBuildContextGitSource{binding}, nil, observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.Name).To(gomega.Equal("redoc"))
		gomega.Expect(originals[0].Component.Version).To(gomega.Equal("2.4.0"))
		// Spelled from the url of the config, not from anything the mirror says
		// about where it was fetched from.
		gomega.Expect(originals[0].Component.Source.Locator).To(gomega.Equal("git+https://github.com/Redocly/redoc.git#" + commit))
		gomega.Expect(originals[0].Component.Source.Checksum).To(gomega.Equal("git-commit:sha1:" + commit))
		var listed []string
		for _, file := range originals[0].Files {
			listed = append(listed, file.Path)
		}
		gomega.Expect(listed).To(gomega.ConsistOf("/app/index.js", "/app/package.json"))
		gomega.Expect(identities).To(gomega.ContainElement(url))
		gomega.Expect(identities).To(gomega.ContainElement(commit))
	})

	// What a local checkout holds is whatever the machine running the build put
	// there: it pins no commit of its own and nothing states where it came from.
	ginkgo.It("refuses a project added from a local checkout", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)
		checkout := mapping(commit, work)
		checkout.SetGitRepo(localGitRepo{})

		_, _, err := producerGitSources(ctx, fixtureGitImage(checkout), []sbomBuildContextGitSource{binding}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("git mapping /app adds a local checkout, which is not a verifiable source: it pins no commit and its origin is unverified")))
	})

	ginkgo.It("refuses a project mapping that is not pinned to a commit", func(ctx ginkgo.SpecContext) {
		work, _ := gitMappingFixture(manifest, body)

		_, _, err := producerGitSources(ctx, fixtureGitImage(mapping("", work)), []sbomBuildContextGitSource{binding}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not pinned to a commit")))
	})

	// The files are read from the root of the commit tree, so a mapping that adds
	// a part of the repository puts them somewhere else than this says they are.
	ginkgo.It("refuses a project mapping that adds a part of the repository", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)
		partial := mapping(commit, work)
		partial.Add = "/packages/redoc"

		_, _, err := producerGitSources(ctx, fixtureGitImage(partial), []sbomBuildContextGitSource{binding}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("adds /packages/redoc of the project, not the whole repository")))
	})
})

var _ = ginkgo.Describe("producer git sources fetched from an internal mirror", func() {
	const manifest = `{"name":"argo-ui","version":"1.0.0"}`
	const body = "export const ui = 1;\n"
	const mirrorURL = "https://fox.flant.com/deckhouse/3p/argoproj/argo-ui.git"

	mirrors := []nativegate.GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "github.com"}}
	binding := func(commit string) sbomBuildContextGitSource {
		return sbomBuildContextGitSource{
			To:             "/src/originals/argo-ui",
			Locator:        "git+https://github.com/argoproj/argo-ui.git#" + commit,
			InstalledPath:  "/app/node_modules/argo-ui",
			PackageName:    "argo-ui",
			PackageVersion: "1.0.0",
		}
	}
	mapping := func(commit, work, url string) *stage.GitMapping {
		gitMapping := stage.NewGitMapping()
		gitMapping.To = "/src/originals/argo-ui"
		gitMapping.Commit = commit
		gitMapping.SetGitRepo(fixtureRemoteRepo(url, work))

		return gitMapping
	}
	observed := fixtureInstalledIndex(map[string]string{
		"/app/node_modules/argo-ui/package.json": manifest,
		"/app/node_modules/argo-ui/index.js":     body,
	})

	// The recipe fetches every source through the internal mirror, so the mapping's
	// url is the mirror's: the lock entry it is held against is still the one the
	// lockfile carries, and the component keeps it.
	ginkgo.It("accepts a mapping of a mirror the declaration lists", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)
		img := fixtureGitImage(mapping(commit, work, mirrorURL))

		originals, identities, err := producerGitSources(ctx, img, []sbomBuildContextGitSource{binding(commit)}, mirrors, observed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.Source.Locator).To(gomega.Equal("git+https://github.com/argoproj/argo-ui.git#" + commit))
		gomega.Expect(originals[0].Mirror).To(gomega.Equal(mirrorURL))
		gomega.Expect(identities).To(gomega.ContainElement(mirrorURL))
	})

	ginkgo.It("refuses the same mapping where the declaration lists no mirror", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)
		img := fixtureGitImage(mapping(commit, work, mirrorURL))

		_, _, err := producerGitSources(ctx, img, []sbomBuildContextGitSource{binding(commit)}, nil, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("the mapping fetches fox.flant.com/deckhouse/3p/argoproj/argo-ui, the locator pins github.com/argoproj/argo-ui")))
	})

	ginkgo.It("refuses a fork served under the listed prefix", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)
		img := fixtureGitImage(mapping(commit, work, "https://fox.flant.com/deckhouse/3p/fork-owner/argo-ui.git"))

		_, _, err := producerGitSources(ctx, img, []sbomBuildContextGitSource{binding(commit)}, mirrors, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("which serves github.com/fork-owner/argo-ui, the locator pins github.com/argoproj/argo-ui")))
	})

	ginkgo.It("refuses a malformed mirror allowlist", func(ctx ginkgo.SpecContext) {
		work, commit := gitMappingFixture(manifest, body)
		img := fixtureGitImage(mapping(commit, work, mirrorURL))

		_, _, err := producerGitSources(ctx, img, []sbomBuildContextGitSource{binding(commit)},
			[]nativegate.GitMirror{{Host: "fox.flant.com", PathPrefix: "deckhouse/3p"}}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`gitMirror 0: upstreamHost "" is not a bare host`)))
	})
})
