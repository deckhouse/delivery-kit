package e2e_build_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/test/pkg/report"
	"github.com/werf/werf/v3/test/pkg/werf"
)

// Files the daemon creates when a container is made, which belong to the container rather
// than to the image.
var containerRuntimeFiles = map[string]bool{
	"/etc/hostname":    true,
	"/etc/hosts":       true,
	"/etc/resolv.conf": true,
	"/.dockerenv":      true,
	"/dev/console":     true,
	"/etc/mtab":        true,
}

var _ = Describe("SBOM shipped-scope file index", Label("e2e", "sbom", "shipped-scope", "simple"), func() {
	It("indexes the built image exactly as the daemon exports it", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_shipped_scope_index"
		SuiteData.InitTestRepo(ctx, repoDirname, "shipped_scope_index")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)
		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_shipped_scope_index.json"), nil,
		)

		appRecord, found := buildReport.Images["app"]
		Expect(found).To(BeTrue(), "expected image %q in build report", "app")

		imageRef := appRecord.DockerRepo + "@" + appRecord.DockerImageDigest

		ref, err := name.NewDigest(imageRef, name.Insecure)
		Expect(err).NotTo(HaveOccurred())

		img, err := remote.Image(ref, insecureRemoteOptions(ctx)...)
		Expect(err).NotTo(HaveOccurred())

		index, err := shippedscope.IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		By("agreeing with the layer semantics the fixture builds")
		Expect(index.Files["/opt/app/busybox"].Digest).To(Equal(digestOfString("new")),
			"the setup stage rewrote the file, so the image must carry the new content")
		Expect(index.Files["/opt/app/sh"].Digest).To(Equal(digestOfString("old")),
			"the hardlink was made before that rewrite, so it still holds the content of its own layer")
		Expect(index.Files).NotTo(HaveKey("/opt/app/removed"),
			"the setup stage deleted the file, so a whiteout must hide it")
		Expect(index.Files["/opt/app/empty"].Size).To(BeZero())
		Expect(index.Symlinks).To(HaveKeyWithValue("/opt/app/link", "/opt/app/busybox"))
		Expect(index.Files).NotTo(HaveKey("/opt/app/link"))

		By("matching docker export file for file")
		exportFiles, exportSymlinks := exportImageWithDocker(ctx, imageRef)

		var missing, extra, mismatched, symlinkDiff []string
		for path, want := range exportFiles {
			if containerRuntimeFiles[path] {
				continue
			}

			got, ok := index.Files[path]
			switch {
			case !ok:
				missing = append(missing, path)
			case got != want:
				mismatched = append(mismatched, fmt.Sprintf("%s: index %s/%d, export %s/%d", path, got.Digest, got.Size, want.Digest, want.Size))
			}
		}
		for path := range index.Files {
			if _, ok := exportFiles[path]; !ok && !containerRuntimeFiles[path] {
				extra = append(extra, path)
			}
		}
		for path, target := range exportSymlinks {
			if containerRuntimeFiles[path] {
				continue
			}

			if got, ok := index.Symlinks[path]; !ok || got != target {
				symlinkDiff = append(symlinkDiff, fmt.Sprintf("%s: index %q, export %q", path, got, target))
			}
		}

		sort.Strings(missing)
		sort.Strings(extra)
		sort.Strings(mismatched)
		sort.Strings(symlinkDiff)

		Expect(len(index.Files)).To(BeNumerically(">", 100), "an image of this base cannot hold so few files")
		Expect(missing).To(BeEmpty(), "files docker exports that the index does not hold")
		Expect(extra).To(BeEmpty(), "files the index holds that docker does not export")
		Expect(mismatched).To(BeEmpty(), "files whose digest or size disagree")
		Expect(symlinkDiff).To(BeEmpty(), "symlinks whose target disagrees")
	})
})

func digestOfString(body string) string {
	sum := sha256.Sum256([]byte(body))

	return "sha256:" + hex.EncodeToString(sum[:])
}

func exportImageWithDocker(ctx SpecContext, imageRef string) (map[string]shippedscope.File, map[string]string) {
	pull := exec.CommandContext(ctx, "docker", "pull", imageRef)
	pullOut, err := pull.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "docker pull %s: %s", imageRef, pullOut)

	create := exec.CommandContext(ctx, "docker", "create", imageRef)
	var createErr bytes.Buffer
	create.Stderr = &createErr
	created, err := create.Output()
	Expect(err).NotTo(HaveOccurred(), "docker create %s: %s", imageRef, createErr.String())

	container := strings.TrimSpace(string(created))
	DeferCleanup(func() {
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})

	export := exec.CommandContext(ctx, "docker", "export", container)
	var exportErr bytes.Buffer
	export.Stderr = &exportErr
	stdout, err := export.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	Expect(export.Start()).To(Succeed())

	files := make(map[string]shippedscope.File)
	symlinks := make(map[string]string)
	hardlinks := make(map[string]string)

	reader := tar.NewReader(stdout)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		Expect(err).NotTo(HaveOccurred())

		path := "/" + strings.TrimPrefix(strings.TrimPrefix(header.Name, "./"), "/")

		switch header.Typeflag {
		case tar.TypeReg:
			hasher := sha256.New()
			_, err := io.Copy(hasher, reader)
			Expect(err).NotTo(HaveOccurred())

			files[path] = shippedscope.File{
				Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
				Size:   header.Size,
			}
		case tar.TypeSymlink:
			symlinks[path] = header.Linkname
		case tar.TypeLink:
			hardlinks[path] = "/" + strings.TrimPrefix(strings.TrimPrefix(header.Linkname, "./"), "/")
		}
	}
	Expect(export.Wait()).To(Succeed(), "docker export %s: %s", container, exportErr.String())

	for path, target := range hardlinks {
		if file, ok := files[target]; ok {
			files[path] = file
		}
	}

	return files, symlinks
}
