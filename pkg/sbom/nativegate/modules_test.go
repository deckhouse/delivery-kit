package nativegate

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"golang.org/x/mod/sumdb/dirhash"
)

var _ = ginkgo.Describe("registry module provenance", func() {
	ginkgo.It("checks canonical h1 independently of transport SHA and matches buildinfo version", func() {
		files := map[string]string{"example.org/library@v1.0.0/go.mod": "module example.org/library\n", "example.org/library@v1.0.0/lib.go": "package library\nfunc Value()int{return 1}\n"}
		names := []string{}
		var buffer bytes.Buffer
		zw := zip.NewWriter(&buffer)
		for name, body := range files {
			names = append(names, name)
			f, err := zw.Create(name)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			_, err = f.Write([]byte(body))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
		gomega.Expect(zw.Close()).To(gomega.Succeed())
		checksum, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(files[name])), nil })
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		sumBody := []byte("example.org/library v1.0.0 " + checksum + "\n")
		entry := map[string]string{"path": "example.org/library", "version": "v1.0.0", "dir": "/go/pkg/mod/example.org/library@v1.0.0", "zip": "/meta/library.zip", "url": "https://proxy.golang.org/example.org/library/@v/v1.0.0.zip", "sha256": digest(buffer.Bytes()), "sum": checksum, "source": "registry"}
		inventory := map[string]any{"schema": "dk.go-modules/v1", "goSum": "/src/go.sum", "modules": []map[string]string{entry}}
		raw, err := json.Marshal(inventory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bodies := map[string][]byte{"/meta/go-modules.json": raw, "/src/go.sum": sumBody, "/meta/library.zip": buffer.Bytes()}
		ip := ImagePolicy{MetaDir: "/meta", Sources: map[string]string{"/src/go.sum": digest(sumBody)}}
		c := emptyCatalog()
		gomega.Expect(c.addGoModules(ip, bodies)).To(gomega.Succeed())
		ref := "pkg:golang/example.org/library@v1.0.0"
		gomega.Expect(componentProperty(c.Components[ref], "dk:go:sum")).To(gomega.Equal(checksum))
		deps := []goDependency{{Path: "example.org/library", Version: "v1.0.0", Sum: checksum}}
		gomega.Expect(validateGoDependencies(deps, []string{ref}, &c)).To(gomega.Succeed())
		deps[0].Version = "v1.0.1"
		gomega.Expect(validateGoDependencies(deps, []string{ref}, &c)).To(gomega.HaveOccurred())
		wrong := "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		entry["sum"] = wrong
		raw, err = json.Marshal(inventory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bodies["/meta/go-modules.json"] = raw
		bodies["/src/go.sum"] = []byte(fmt.Sprintf("example.org/library v1.0.0 %s\n", wrong))
		ip.Sources["/src/go.sum"] = digest(bodies["/src/go.sum"])
		c = emptyCatalog()
		gomega.Expect(c.addGoModules(ip, bodies)).To(gomega.MatchError(gomega.ContainSubstring("canonical h1 mismatch")))
		delete(bodies, "/meta/library.zip")
		gomega.Expect(c.addGoModules(ip, bodies)).To(gomega.MatchError(gomega.ContainSubstring("transport hash mismatch")))
	})
	ginkgo.It("checks Cargo registry checksum against the committed lock", func() {
		body := []byte(`version = 4
[[package]]
name = "itoa"
version = "1.0.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "` + strings.Repeat("a", 64) + `"
`)
		comp := fixtureCatalog().Components["pkg:generic/example@1"]
		comp.Name = "itoa"
		comp.Version = "1.0.15"
		comp.PackageURL = "pkg:cargo/itoa@1.0.15"
		comp.BOMRef = comp.PackageURL
		inv := sourceInventory{Distribution: Distribution{URL: "https://static.crates.io/crates/itoa/itoa-1.0.15.crate", SHA256: "sha256:" + strings.Repeat("a", 64)}, Components: []cdx.Component{comp}}
		c := emptyCatalog()
		ip := ImagePolicy{Sources: map[string]string{"/src/Cargo.lock": digest(body)}}
		bodies := map[string][]byte{"/src/Cargo.lock": body}
		gomega.Expect(c.verifyCargoDistribution(ip, inv, bodies)).To(gomega.Succeed())
		inv.Distribution.SHA256 = "sha256:" + strings.Repeat("b", 64)
		gomega.Expect(c.verifyCargoDistribution(ip, inv, bodies)).To(gomega.MatchError(gomega.ContainSubstring("Cargo source/checksum mismatch")))
	})
})
