package nativegate

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("Linux loader agreement", func() {
	ginkgo.It("preserves RUNPATH precedence against the real loader", func() {
		if runtime.GOOS != "linux" {
			ginkgo.Skip("requires native Linux loader")
		}
		dir := ginkgo.GinkgoT().TempDir()
		first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
		gomega.Expect(os.Mkdir(first, 0o755)).To(gomega.Succeed())
		gomega.Expect(os.Mkdir(second, 0o755)).To(gomega.Succeed())
		source := filepath.Join(dir, "pick.c")
		main := filepath.Join(dir, "main.c")
		app := filepath.Join(dir, "app")
		gomega.Expect(os.WriteFile(source, []byte("int pick(void){return PICK;}"), 0o644)).To(gomega.Succeed())
		gomega.Expect(os.WriteFile(main, []byte("#include <stdio.h>\nint pick(void); int main(void){printf(\"%d\\n\",pick());}"), 0o644)).To(gomega.Succeed())
		run := func(args ...string) {
			output, err := exec.Command("gcc", args...).CombinedOutput()
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(output))
		}
		run("-shared", "-fPIC", "-DPICK=1", "-Wl,-soname,libpick.so.1", source, "-o", filepath.Join(first, "libpick.so.1"))
		run("-shared", "-fPIC", "-DPICK=2", "-Wl,-soname,libpick.so.1", source, "-o", filepath.Join(second, "libpick.so.1"))
		run(main, "-L"+first, "-l:libpick.so.1", "-Wl,-rpath,"+first+":"+second, "-o", app)
		actual, err := exec.Command(app).Output()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.TrimSpace(string(actual))).To(gomega.Equal("1"))
		cmd := exec.Command(app)
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+second)
		actual, err = cmd.Output()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.TrimSpace(string(actual))).To(gomega.Equal("2"))
		f, err := elf.Open(app)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer f.Close()
		dirs, err := runtimeDirs(f, app, &loaderModel{dirs: []string{"/lib64", "/usr/lib64"}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(dirs[:2]).To(gomega.Equal([]string{first, second}))
		fs := &filesystem{index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{}}, bodies: map[string][]byte{}}
		present := map[string]Record{}
		for _, dir := range []string{first, second} {
			name := filepath.Join(dir, "libpick.so.1")
			body, err := os.ReadFile(name)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fs.bodies[name] = body
			fs.index.Files[name] = shippedscope.File{Digest: digest(body)}
			present[name] = Record{SHA256: digest(body)}
		}
		selected, err := resolveRuntime(fs, present, "libpick.so.1", dirs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(selected).To(gomega.Equal(filepath.Join(first, "libpick.so.1")))
	})
})
