package nativegate

import (
	"context"
	"debug/elf"
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
// consumes and an image never ships: the archives it lives in are not a
// container this gate reads, and no DK target names the profile. The bumped
// reader reads revision 3 of it, so what keeps it out of an inventory is the
// container it is found in rather than the revision going unrecognized.
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
		// The archive the record really belongs to: DK selects no member of it
		// and reads no record out of it, whatever it carries.
		ginkgo.Entry("the archive it belongs to", func() []byte {
			return []byte("!<arch>\n")
		}, "unsupported: binary format has no embedded composition reader"),
		ginkgo.Entry("an executable carrying it", func() []byte {
			return runtimeELFWithRecord(elf.ET_EXEC, goPackageRecord())
		}, `invalid: artifact "go-package" does not match ELF type ET_EXEC`),
		ginkgo.Entry("a relocatable object carrying it", func() []byte {
			return runtimeELFWithRecord(elf.ET_REL, goPackageRecord())
		}, `invalid: artifact "go-package" does not match ELF type ET_REL`),
	)
})
