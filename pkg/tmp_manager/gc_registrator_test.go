package tmp_manager

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prashantv/gostub"

	"github.com/werf/werf/v3/pkg/werf"
)

var _ = Describe("gc registration queue", func() {
	It("registers a queued path once", func() {
		stubs := gostub.New()
		defer stubs.Reset()

		for range 2 {
			stubs.SetEnv("WERF_TMP_DIR", GinkgoT().TempDir())
			stubs.SetEnv("WERF_HOME", GinkgoT().TempDir())
			Expect(werf.Init("", "")).To(Succeed())

			fromDockerConfig := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(fromDockerConfig, "config.json"), []byte("{}"), 0o600)).To(Succeed())

			_, err := CreateDockerConfigDir(GinkgoT().Context(), fromDockerConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(DelegateCleanup(GinkgoT().Context())).To(Succeed())
		}
	})

	It("retries every failed registration", func(ctx SpecContext) {
		root := GinkgoT().TempDir()
		registrator := newGCRegistrator()
		var blockedTargetDirs []string
		var paths []string

		for _, name := range []string{"first", "second"} {
			blockedTargetDir := filepath.Join(root, name+"-blocked")
			path := filepath.Join(root, name)
			Expect(os.WriteFile(blockedTargetDir, nil, 0o600)).To(Succeed())
			Expect(os.WriteFile(path, nil, 0o600)).To(Succeed())
			Expect(registrator.queueRegistration(ctx, path, blockedTargetDir)).To(Succeed())
			blockedTargetDirs = append(blockedTargetDirs, blockedTargetDir)
			paths = append(paths, path)
		}

		err := registrator.registerAll(ctx)
		Expect(err).NotTo(Succeed())
		for _, targetDir := range blockedTargetDirs {
			Expect(err.Error()).To(ContainSubstring(targetDir))
			Expect(os.Remove(targetDir)).To(Succeed())
		}

		Expect(registrator.registerAll(ctx)).To(Succeed())
		for index, targetDir := range blockedTargetDirs {
			Expect(filepath.Join(targetDir, filepath.Base(paths[index]))).To(BeAnExistingFile())
		}
	})

	It("retries a failed registration and the remaining queue", func(ctx SpecContext) {
		root := GinkgoT().TempDir()
		blockedTargetDir := filepath.Join(root, "blocked")
		readyTargetDir := filepath.Join(root, "ready")
		firstPath := filepath.Join(root, "first")
		secondPath := filepath.Join(root, "second")
		Expect(os.WriteFile(blockedTargetDir, nil, 0o600)).To(Succeed())
		Expect(os.WriteFile(firstPath, nil, 0o600)).To(Succeed())
		Expect(os.WriteFile(secondPath, nil, 0o600)).To(Succeed())

		registrator := newGCRegistrator()
		Expect(registrator.queueRegistration(ctx, firstPath, blockedTargetDir)).To(Succeed())
		Expect(registrator.queueRegistration(ctx, secondPath, readyTargetDir)).To(Succeed())
		Expect(registrator.registerAll(ctx)).NotTo(Succeed())
		Expect(filepath.Join(readyTargetDir, filepath.Base(secondPath))).To(BeAnExistingFile())
		Expect(os.Remove(blockedTargetDir)).To(Succeed())

		Expect(registrator.registerAll(ctx)).To(Succeed())
		Expect(filepath.Join(blockedTargetDir, filepath.Base(firstPath))).To(BeAnExistingFile())
	})
})
