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
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// fixtureGitRepo answers what a fetched mapping repository answers about itself; every
// other operation is out of reach of the code under test and stays unimplemented.
type fixtureGitRepo struct {
	git_repo.GitRepo
	local bool
	url   string
	clone string
}

func (repo fixtureGitRepo) IsLocal() bool { return repo.local }

func (repo fixtureGitRepo) RemoteOriginUrl(context.Context) (string, error) { return repo.url, nil }

func (repo fixtureGitRepo) GetClonePath() string { return repo.clone }

// unfetchedGitRepo is a mapping repository DK has no object database for.
type unfetchedGitRepo struct {
	git_repo.GitRepo
}

func (unfetchedGitRepo) IsLocal() bool { return false }

func (unfetchedGitRepo) RemoteOriginUrl(context.Context) (string, error) { return "", nil }

// gitMappingFixture builds a repository holding one package at one commit and answers
// the bare clone DK would fetch, plus that commit.
func gitMappingFixture(manifest, body string) (string, string) {
	ginkgo.GinkgoHelper()
	root := ginkgo.GinkgoT().TempDir()
	work := filepath.Join(root, "work")
	gomega.Expect(os.MkdirAll(work, 0o755)).To(gomega.Succeed())
	run := func(dir string, args ...string) string {
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
	run(work, "init", "-q", "-b", "main", ".")
	gomega.Expect(os.WriteFile(filepath.Join(work, "package.json"), []byte(manifest), 0o644)).To(gomega.Succeed())
	gomega.Expect(os.WriteFile(filepath.Join(work, "index.js"), []byte(body), 0o644)).To(gomega.Succeed())
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "fixture")
	bare := filepath.Join(root, "bare.git")
	run(root, "clone", "-q", "--bare", work, bare)

	return bare, run(work, "rev-parse", "HEAD")
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
	mapping := func(commit, clone string) *stage.GitMapping {
		gitMapping := stage.NewGitMapping()
		gitMapping.To = "/src/originals/argo-ui"
		gitMapping.Commit = commit
		gitMapping.SetGitRepo(fixtureGitRepo{url: "https://github.com/argoproj/argo-ui.git", clone: clone})

		return gitMapping
	}
	observed := fixtureInstalledIndex(map[string]string{
		"/app/node_modules/argo-ui/package.json": manifest,
		"/app/node_modules/argo-ui/index.js":     body,
	})

	ginkgo.It("verifies the mapping the binding names and carries its files into the manifest", func(ctx ginkgo.SpecContext) {
		clone, commit := gitMappingFixture(manifest, body)
		img := fixtureGitImage(mapping(commit, clone))

		originals, identities, err := producerGitSources(ctx, img, []sbomBuildContextGitSource{binding(commit)}, observed)
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

		_, _, err := producerGitSources(ctx, fixtureGitImage(), []sbomBuildContextGitSource{binding(commit)}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no git mapping at /src/originals/argo-ui")))

		_, _, err = producerGitSources(ctx, fixtureGitImage(mapping(commit, clone), mapping(commit, clone)), []sbomBuildContextGitSource{binding(commit)}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("more than one git mapping")))

		unpinned := mapping("", clone)
		_, _, err = producerGitSources(ctx, fixtureGitImage(unpinned), []sbomBuildContextGitSource{binding(commit)}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not pinned to a commit")))

		project := mapping(commit, clone)
		project.SetGitRepo(fixtureGitRepo{local: true})
		_, _, err = producerGitSources(ctx, fixtureGitImage(project), []sbomBuildContextGitSource{binding(commit)}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("adds the project repository")))

		unfetched := mapping(commit, clone)
		unfetched.SetGitRepo(unfetchedGitRepo{})
		_, _, err = producerGitSources(ctx, fixtureGitImage(unfetched), []sbomBuildContextGitSource{binding(commit)}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no fetched object database")))
	})

	ginkgo.It("refuses a mapping that fetches another repository than the locator pins", func(ctx ginkgo.SpecContext) {
		clone, commit := gitMappingFixture(manifest, body)
		forked := mapping(commit, clone)
		forked.SetGitRepo(fixtureGitRepo{url: "https://github.com/fork-owner/argo-ui.git", clone: clone})

		_, _, err := producerGitSources(ctx, fixtureGitImage(forked), []sbomBuildContextGitSource{binding(commit)}, observed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("git source /src/originals/argo-ui: invalid: the mapping fetches")))
	})
})
