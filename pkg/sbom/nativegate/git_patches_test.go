package nativegate

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

// Fixtures of the git.patches pedigree (CycloneDX 1.6). Representation (proposal of Delivery Kit, checked here only against the
// official schema and the identity link): the own component carries pedigree.patches[] {type: unofficial, diff.url: canonical VCS
// blob URI git+<repo URL>@<commit>#<repo-relative patch path>}; the same URI is an externalReferences entry of type vcs whose
// hashes carry the SHA-256 of that blob. Patch content is never inlined. The specs do not call the Delivery Kit API of
// git.patches (it does not exist yet): schema, identity link against the stage fixtures' manifest, order, library round trip and
// the absence of host paths. Subject-checksum negatives wait for the GitPatch API.
const gitPatchesNativegateDir = "testdata/git_patches"

func gitPatchesBOMFixture(name string) []byte {
	body, err := os.ReadFile(filepath.Join(gitPatchesNativegateDir, name))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return body
}

func gitPatchesManifestHashes() map[string]string {
	body, err := os.ReadFile("../../build/stage/testdata/git_patches/manifest.json")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var m struct {
		Patches map[string]string `json:"patches"`
	}
	gomega.Expect(json.Unmarshal(body, &m)).To(gomega.Succeed())
	return m.Patches
}

// gitPatchesLinkBreak returns the first break of pedigree.patches[i].diff.url -> vcs externalReference with the same url and a
// SHA-256 equal to the committed blob's; "" if the link holds.
func gitPatchesLinkBreak(bom *cdx.BOM, committed map[string]string) string {
	for _, component := range *bom.Components {
		for _, patch := range *component.Pedigree.Patches {
			found := false
			for _, ref := range *component.ExternalReferences {
				if ref.URL != patch.Diff.URL {
					continue
				}
				found = true
				name := path.Base(strings.SplitN(ref.URL, "#", 2)[1])
				if ref.Type != cdx.ERTypeVCS || ref.Hashes == nil || len(*ref.Hashes) != 1 || (*ref.Hashes)[0].Algorithm != cdx.HashAlgoSHA256 {
					return name + ": expected a vcs reference with exactly one SHA-256"
				}
				if (*ref.Hashes)[0].Value != committed[name] {
					return name + ": hash is not the committed blob's"
				}
			}
			if !found {
				return path.Base(strings.SplitN(patch.Diff.URL, "#", 2)[1]) + ": no externalReference with its url"
			}
		}
	}
	return ""
}

func gitPatchesDecode(body []byte) *cdx.BOM {
	bom := new(cdx.BOM)
	gomega.Expect(cdx.NewBOMDecoder(bytes.NewReader(body), cdx.BOMFileFormatJSON).Decode(bom)).To(gomega.Succeed())
	return bom
}

func gitPatchesOrder(bom *cdx.BOM) []string {
	var order []string
	for _, patch := range *(*bom.Components)[0].Pedigree.Patches {
		order = append(order, path.Base(strings.SplitN(patch.Diff.URL, "#", 2)[1]))
	}
	return order
}

var _ = ginkgo.Describe("git.patches pedigree fixtures", func() {
	ginkgo.It("the pedigree fixture is valid CycloneDX 1.6 and its patch identities are the committed blobs'", func() {
		body := gitPatchesBOMFixture("bom-valid.json")
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(body)).To(gomega.Succeed())
		gomega.Expect(gitPatchesLinkBreak(gitPatchesDecode(body), gitPatchesManifestHashes())).To(gomega.BeEmpty())
		gomega.Expect(gitPatchesOrder(gitPatchesDecode(body))).To(gomega.Equal([]string{"001-edit-a.patch", "002-edit-a-and-b.patch"}))
	})

	ginkgo.DescribeTable("schema-invalid documents are refused", func(name string) {
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(gitPatchesBOMFixture(name))).To(gomega.MatchError(gomega.ContainSubstring("schema validation errors")))
	},
		ginkgo.Entry("unknown patch type", "bom-invalid-patch-type.json"),
		ginkgo.Entry("patch without type", "bom-invalid-patch-without-type.json"),
	)

	ginkgo.DescribeTable("schema-valid documents that break the patch identity are detected", func(name, message string) {
		body := gitPatchesBOMFixture(name)
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(body)).To(gomega.Succeed())
		gomega.Expect(gitPatchesLinkBreak(gitPatchesDecode(body), gitPatchesManifestHashes())).To(gomega.ContainSubstring(message))
	},
		ginkgo.Entry("a patch without its blob reference", "bom-broken-patch-identity.json", "no externalReference with its url"),
		ginkgo.Entry("a blob hash that is not the committed one", "bom-wrong-patch-hash.json", "hash is not the committed blob's"),
	)

	ginkgo.It("the order of pedigree.patches is the order of the list and a reordered document differs", func() {
		valid := gitPatchesOrder(gitPatchesDecode(gitPatchesBOMFixture("bom-valid.json")))
		reordered := gitPatchesOrder(gitPatchesDecode(gitPatchesBOMFixture("bom-reordered-patches.json")))
		gomega.Expect(reordered).NotTo(gomega.Equal(valid))
		gomega.Expect(reordered).To(gomega.ConsistOf(valid))
	})

	ginkgo.It("inline patch content is schema-valid but is a contract violation: the blob is referenced, never embedded", func() {
		body := gitPatchesBOMFixture("bom-inline-patch-content.json")
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(body)).To(gomega.Succeed())
		for _, patch := range *(*gitPatchesDecode(body).Components)[0].Pedigree.Patches {
			if patch.Diff.Text != nil {
				return
			}
		}
		ginkgo.Fail("the fixture is expected to carry inline diff text")
	})

	ginkgo.It("a library round trip keeps the pedigree patches, their urls and the SHA-256 hashes", func() {
		original := gitPatchesDecode(gitPatchesBOMFixture("bom-valid.json"))
		data, err := cyclonedxutil.ToJSON(original)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.Succeed())
		again := gitPatchesDecode(data)
		gomega.Expect(gitPatchesOrder(again)).To(gomega.Equal(gitPatchesOrder(original)))
		gomega.Expect(gitPatchesLinkBreak(again, gitPatchesManifestHashes())).To(gomega.BeEmpty())
		gomega.Expect((*again.Components)[0].Pedigree.Commits).To(gomega.Equal((*original.Components)[0].Pedigree.Commits))
	})

	ginkgo.It("no stage or host path enters the evidence", func() {
		entries, err := os.ReadDir(gitPatchesNativegateDir)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, e := range entries {
			body := gitPatchesBOMFixture(e.Name())
			for _, forbidden := range []string{"/home/", "/tmp/", "/.werf", "/build/", "/src/", "/Users/"} {
				gomega.Expect(string(body)).NotTo(gomega.ContainSubstring(forbidden), e.Name())
			}
		}
	})
})
