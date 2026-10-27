package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("native ELF archive evidence wiring", func() {
	ginkgo.It("rejects a damaged selected member through inspect", func() {
		dir := os.Getenv("DK_NATIVE_INSPECT_FIXTURE")
		if dir == "" {
			ginkgo.Skip("run export-native-inspect-fixture.py and set DK_NATIVE_INSPECT_FIXTURE")
		}
		raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var manifest struct {
			Image string            `json:"image"`
			Files map[string]string `json:"files"`
		}
		gomega.Expect(json.Unmarshal(raw, &manifest)).To(gomega.Succeed())
		gomega.Expect(manifest.Image).To(gomega.ContainSubstring("@sha256:"))
		files := map[string][]byte{}
		for name, hash := range manifest.Files {
			body, err := os.ReadFile(filepath.Join(dir, name))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(digest(body)).To(gomega.Equal("sha256:"+hash), name)
			files[name] = body
		}
		var policy Policy
		gomega.Expect(decode(files["policy.json"], &policy)).To(gomega.Succeed())
		ip := policy.Images["producer"]
		fs := &filesystem{index: &shippedscope.FileIndex{Symlinks: map[string]string{}}, bodies: map[string][]byte{}}
		gomega.Expect(json.Unmarshal(files["symlinks.json"], &fs.index.Symlinks)).To(gomega.Succeed())
		bodies := map[string][]byte{}
		compiled := map[string]Compile{}
		for name, body := range files {
			if strings.HasPrefix(name, "pm/") {
				bodies["/var/lib/pm/"+strings.TrimPrefix(name, "pm/")] = body
			}
			if strings.HasPrefix(name, "archives/") {
				bodies[ip.MetaDir+"/"+name] = body
			}
			if strings.HasPrefix(name, "objects/") {
				var record Compile
				gomega.Expect(decode(body, &record)).To(gomega.Succeed())
				compiled[record.SHA256] = record
			}
		}
		catalog := emptyCatalog()
		gomega.Expect(catalog.addPM(context.Background(), bodies)).To(gomega.Succeed())
		gomega.Expect(catalog.resolvePaths(fs)).To(gomega.Succeed())
		gomega.Expect(catalog.coalescePM()).To(gomega.Succeed())
		inspect := func(body []byte) error {
			inspector := inspector{policy: &policy, image: ip, catalog: &catalog, compiled: compiled, active: map[string]bool{}, archives: bodies, fs: fs}
			_, err := inspector.inspect(body)
			return err
		}
		original := files["app"]
		gomega.Expect(inspect(original)).To(gomega.Succeed())
		f, err := elf.NewFile(bytes.NewReader(original))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer f.Close()
		section := f.Section(".dk.link")
		gomega.Expect(section).NotTo(gomega.BeNil())
		linkBody, err := section.Data()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var link Link
		gomega.Expect(decode(linkBody, &link)).To(gomega.Succeed())
		selected := ""
		for _, input := range link.Inputs {
			if input.Kind == "archive-member" && bytes.Count(linkBody, []byte(input.SHA256)) == 1 {
				selected = input.SHA256
				break
			}
		}
		gomega.Expect(selected).NotTo(gomega.BeEmpty())
		replacement := selected[:len(selected)-1] + "0"
		if replacement == selected {
			replacement = selected[:len(selected)-1] + "1"
		}
		corrupted := bytes.Clone(original)
		offset := int(section.Offset) + bytes.Index(linkBody, []byte(selected))
		copy(corrupted[offset:offset+len(selected)], replacement)
		gomega.Expect(inspect(corrupted)).To(gomega.MatchError(gomega.ContainSubstring("archive member content mismatch")))
	})
})
