package stage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// These specs check the FIXTURES of the planned git.patches feature (testdata/git_patches) against plain `git apply -p1`, the
// reference semantics proposed for the DSL: patches of the list are applied in order to repo@commit, no fuzz, no fallback.
// They do not touch the Delivery Kit code: the API of git.patches does not exist yet, so the specs of the feature itself
// (identity, cache, pedigree, giterminism, nativegate hash-mismatch) are written once the syntax is fixed.
const gitPatchesFixtureDir = "testdata/git_patches"

func gitPatchesGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "core.autocrlf=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func gitPatchesFixtureRepo() string {
	dir := ginkgo.GinkgoT().TempDir()
	entries, err := os.ReadDir(filepath.Join(gitPatchesFixtureDir, "repo"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(gitPatchesFixtureDir, "repo", e.Name()))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(os.WriteFile(filepath.Join(dir, e.Name()), body, 0o644)).To(gomega.Succeed())
	}
	for _, args := range [][]string{{"init", "-q", "."}, {"add", "-A"}, {"commit", "-qm", "base"}} {
		out, err := gitPatchesGit(dir, args...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), out)
	}
	return dir
}

// gitPatchesApply applies the named patches in order and returns the first error with its git message.
func gitPatchesApply(dir string, names ...string) error {
	for _, name := range names {
		abs, err := filepath.Abs(filepath.Join(gitPatchesFixtureDir, "patches", name))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		if out, err := gitPatchesGit(dir, "apply", "-p1", abs); err != nil {
			return &gitPatchesError{name: name, message: strings.TrimSpace(out)}
		}
	}
	return nil
}

type gitPatchesError struct{ name, message string }

func (e *gitPatchesError) Error() string { return e.name + ": " + e.message }

func gitPatchesSum(path string) string {
	body, err := os.ReadFile(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type gitPatchesManifest struct {
	Patches  map[string]string `json:"patches"`
	Expected map[string]string `json:"expected"`
}

func gitPatchesLoadManifest() gitPatchesManifest {
	body, err := os.ReadFile(filepath.Join(gitPatchesFixtureDir, "manifest.json"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var m gitPatchesManifest
	gomega.Expect(json.Unmarshal(body, &m)).To(gomega.Succeed())
	return m
}

var _ = ginkgo.Describe("git.patches fixtures", func() {
	ginkgo.It("pins the sha256 of every patch blob and expected file", func() {
		m := gitPatchesLoadManifest()
		for name, sum := range m.Patches {
			gomega.Expect(gitPatchesSum(filepath.Join(gitPatchesFixtureDir, "patches", name))).To(gomega.Equal(sum), name)
		}
		for name, sum := range m.Expected {
			gomega.Expect(gitPatchesSum(filepath.Join(gitPatchesFixtureDir, "expected", filepath.FromSlash(name)))).To(gomega.Equal(sum), name)
		}
	})

	expectTree := func(dir, expected string) {
		for _, name := range []string{"a.txt", "b.txt"} {
			got, err := os.ReadFile(filepath.Join(dir, name))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			want, err := os.ReadFile(filepath.Join(gitPatchesFixtureDir, "expected", expected, name))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(got)).To(gomega.Equal(string(want)), name)
		}
	}

	ginkgo.It("two sequential patches give the canonical patched tree", func() {
		dir := gitPatchesFixtureRepo()
		gomega.Expect(gitPatchesApply(dir, "001-edit-a.patch", "002-edit-a-and-b.patch")).To(gomega.Succeed())
		expectTree(dir, "after-001-002")
	})

	ginkgo.It("the order of the list matters: 002 before 001 does not apply", func() {
		dir := gitPatchesFixtureRepo()
		err := gitPatchesApply(dir, "002-edit-a-and-b.patch", "001-edit-a.patch")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("002-edit-a-and-b.patch")))
	})

	ginkgo.It("another committed version of a patch changes the patched tree and the blob identity", func() {
		dir := gitPatchesFixtureRepo()
		gomega.Expect(gitPatchesApply(dir, "001-edit-a.patch", "002-edit-a-and-b.alt.patch")).To(gomega.Succeed())
		expectTree(dir, "after-001-002-alt")
		m := gitPatchesLoadManifest()
		gomega.Expect(m.Patches["002-edit-a-and-b.alt.patch"]).NotTo(gomega.Equal(m.Patches["002-edit-a-and-b.patch"]))
		gomega.Expect(m.Expected["after-001-002-alt/b.txt"]).NotTo(gomega.Equal(m.Expected["after-001-002/b.txt"]))
	})

	// The wording of git differs between versions ("unrecognized input" before 2.4x, "No valid patches in input" after), so the
	// message is matched by alternatives.
	ginkgo.DescribeTable("a patch the reference semantics refuse", func(name, message string) {
		dir := gitPatchesFixtureRepo()
		err := gitPatchesApply(dir, name)
		gomega.Expect(err).To(gomega.MatchError(gomega.MatchRegexp(message)))
	},
		ginkgo.Entry("context mismatch (no fuzz, no fallback)", "003-does-not-apply.patch", "patch does not apply"),
		ginkgo.Entry("path leaving the tree", "004-unsafe-parent-path.patch", "outside|\\.\\./"),
		ginkgo.Entry("empty patch", "008-empty.patch", "unrecognized input|No valid patches"),
	)

	// Rename, delete and mode change apply under plain git; whether the DSL accepts them is a decision of the DSL,
	// recorded here as the observable result of the reference semantics only.
	ginkgo.It("rename, delete and mode change are plain-git facts", func() {
		dir := gitPatchesFixtureRepo()
		gomega.Expect(gitPatchesApply(dir, "005-rename.patch", "006-delete.patch", "007-mode.patch")).To(gomega.Succeed())
		_, err := os.Stat(filepath.Join(dir, "new-name.txt"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = os.Stat(filepath.Join(dir, "old-name.txt"))
		gomega.Expect(os.IsNotExist(err)).To(gomega.BeTrue())
		_, err = os.Stat(filepath.Join(dir, "doomed.txt"))
		gomega.Expect(os.IsNotExist(err)).To(gomega.BeTrue())
		info, err := os.Stat(filepath.Join(dir, "script.sh"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(info.Mode().Perm() & 0o111).NotTo(gomega.BeZero())
	})

	ginkgo.It("a file edited beyond the patched tree no longer matches the canonical hash", func() {
		dir := gitPatchesFixtureRepo()
		gomega.Expect(gitPatchesApply(dir, "001-edit-a.patch", "002-edit-a-and-b.patch")).To(gomega.Succeed())
		m := gitPatchesLoadManifest()
		gomega.Expect(gitPatchesSum(filepath.Join(dir, "a.txt"))).To(gomega.Equal(m.Expected["after-001-002/a.txt"]))
		f, err := os.OpenFile(filepath.Join(dir, "a.txt"), os.O_APPEND|os.O_WRONLY, 0)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = f.WriteString("tampered\n")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(f.Close()).To(gomega.Succeed())
		gomega.Expect(gitPatchesSum(filepath.Join(dir, "a.txt"))).NotTo(gomega.Equal(m.Expected["after-001-002/a.txt"]))
	})

	ginkgo.It("a working-copy patch differing from its committed blob is detectable", func() {
		dir := gitPatchesFixtureRepo()
		patch := filepath.Join(dir, "p.patch")
		body, err := os.ReadFile(filepath.Join(gitPatchesFixtureDir, "patches", "001-edit-a.patch"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(os.WriteFile(patch, body, 0o644)).To(gomega.Succeed())
		for _, args := range [][]string{{"add", "p.patch"}, {"commit", "-qm", "patch"}} {
			out, err := gitPatchesGit(dir, args...)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), out)
		}
		committed, err := gitPatchesGit(dir, "rev-parse", "HEAD:p.patch")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(os.WriteFile(patch, append(body, '\n'), 0o644)).To(gomega.Succeed())
		worktree, err := gitPatchesGit(dir, "hash-object", "p.patch")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.TrimSpace(worktree)).NotTo(gomega.Equal(strings.TrimSpace(committed)))
	})
})
