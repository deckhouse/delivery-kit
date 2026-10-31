package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"runtime/debug"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const goPackagePath = "/usr/local/go/pkg/example.com/m/pkg.a"

// goPackageRecord is a complete revision 3 go-package record: the evidence pm
// writes for one compiled Go package, into the __.SBOM member of its archive.
func goPackageRecord() *shared.BuildRecord {
	sum := "h1:" + strings.Repeat("A", 43) + "="
	return &shared.BuildRecord{
		Schema: "pm.buildinfo/v1", Artifact: "go-package",
		Profile:    shared.BuildProfile{ID: "go-package", Revision: "3", Platform: "linux/amd64"},
		Subject:    "pkg",
		Complete:   true,
		GoModules:  &[]shared.GoModuleBinding{{Component: "pkg", Module: debug.Module{Path: "example.com/m/pkg", Version: "v1.0.0", Sum: sum}}},
		Components: []shared.BuildComponent{{ID: "pkg", Name: "example.com/m/pkg", Version: "v1.0.0", Source: shared.BuildSource{Kind: "go", Locator: "example.com/m/pkg@v1.0.0", Checksum: sum}}},
		Inputs:     []shared.BuildInput{},
		Tools:      []shared.BuildTool{{Name: "fixture-tool", Version: "1.0", SHA256: "sha256:" + strings.Repeat("2", 64)}},
	}
}

// A go-package record is evidence about a compiled package, which a link
// consumes and an image never ships. No DK target names the profile, and the
// archive it lives in is read as the members it holds: a Go package archive
// holds Go object files and the record beside them, none of which is a
// relocatable object answering for itself. The bumped reader reads revision 3
// of it, so what keeps it out of an inventory is the container it is found in
// rather than the revision going unrecognized.
var _ = ginkgo.Describe("Go package record", func() {
	goPackagePolicy := func() *Policy {
		policy := fixturePolicy("image")
		policy.Profiles = []string{"c-object", "go-package"}
		return policy
	}

	ginkgo.DescribeTable("is no record of a file an image ships", func(build func() []byte, expected string) {
		err := Apply(context.Background(), goPackagePolicy(), "image", fixtureImage(map[string]string{goPackagePath: string(build())}), nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		// The archive the record really belongs to: pm writes it into a member
		// of its own, beside Go object files that are no ELF at all, and every
		// member of a shipped archive has to answer for itself.
		ginkgo.Entry("the archive it belongs to", func() []byte {
			record, err := json.Marshal(map[string]any{"type": "pm", "sbom": goPackageRecord()})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			return fixtureArchive(
				archiveEntry{name: "__.PKGDEF/", body: []byte("go object linux amd64\n")},
				archiveEntry{name: "__.SBOM/", body: record},
			)
		}, "no-data: archive member __.PKGDEF (index 0) is no relocatable object carrying a record of its build"),
		ginkgo.Entry("an executable carrying it", func() []byte {
			return runtimeELFWithRecord(elf.ET_EXEC, goPackageRecord())
		}, `invalid: artifact "go-package" does not match ELF type ET_EXEC`),
		ginkgo.Entry("a relocatable object carrying it", func() []byte {
			return runtimeELFWithRecord(elf.ET_REL, goPackageRecord())
		}, `invalid: artifact "go-package" does not match ELF type ET_REL`),
	)
})
