package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("declared code git identity", func() {
	ginkgo.It("preserves distinct source identities from cached install and patched setup including beforeInstall", func(ctx ginkgo.SpecContext) {
		first := []GitSource{{Repository: "https://example.invalid/project.git", Commit: strings.Repeat("a", 40), Add: "/", To: "/src"}}
		second := []GitSource{{Repository: first[0].Repository, Commit: strings.Repeat("b", 40), Add: "/", To: "/src"}}
		sets := [][]GitSource{nil, first, second}
		files := map[string][]byte{}
		for i, sources := range sets {
			subject, _, err := declaredSubject(ctx, "app", sources)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			record := fixtureRecord("c-static", "linux/amd64")
			component := record["components"].([]any)[0].(map[string]any)
			component["version"] = "unspecified"
			component["source"].(map[string]string)["locator"] = subject.Source.Locator
			files[[]string{"/out/before", "/out/install", "/out/setup"}[i]] = fixtureELF(elf.ET_EXEC, record)
		}
		bom := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(files), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", BuildGitSources: sets})).To(gomega.Succeed())
		commits := []string{}
		for _, component := range *bom.Components {
			if component.Pedigree != nil {
				commits = append(commits, (*component.Pedigree.Ancestors)[0].Version)
			}
		}
		gomega.Expect(commits).To(gomega.ConsistOf(first[0].Commit, second[0].Commit))
		err := Verify(ctx, fixtureImage(files), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", BuildGitSources: [][]GitSource{nil, first}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/setup"), gomega.ContainSubstring("subject"))))
	})
	ginkgo.It("binds the helper subject to a sorted set of repository commit and mapping paths", func(ctx ginkgo.SpecContext) {
		first := GitSource{Repository: "https://example.invalid/a.git", Commit: strings.Repeat("a", 40), Add: "/code", To: "/src"}
		second := GitSource{Repository: "https://example.invalid/b.git", Commit: strings.Repeat("b", 40), Add: "/", To: "/other"}
		directory := ginkgo.GinkgoT().TempDir()
		_, err := MaterializeBuildContext(ctx, fixtureImage(nil), &PackageSet{}, directory, ContextOptions{Subject: "app", Platform: "linux/amd64", ContainerRoot: "/.werf/context", GitSources: []GitSource{second, first, first}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		data, err := os.ReadFile(filepath.Join(directory, "context.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		declared, err := buildcontext.Decode(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		checksum, err := GitSourcesChecksum(ctx, []GitSource{first, second})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(checksum).To(gomega.MatchRegexp(`^sha256:[a-f0-9]{64}$`))
		gomega.Expect(declared.Subject.Source.Checksum).To(gomega.BeEmpty())
		gomega.Expect(declared.Subject.Source.Locator).To(gomega.Equal("dk:image:app@" + checksum))
		for _, field := range []string{"repository", "commit", "add", "to"} {
			changed := first
			switch field {
			case "repository":
				changed.Repository = "https://example.invalid/fork.git"
			case "commit":
				changed.Commit = strings.Repeat("c", 40)
			case "add":
				changed.Add = "/other-code"
			case "to":
				changed.To = "/other-target"
			}
			other, err := GitSourcesChecksum(ctx, []GitSource{changed, second})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(other).NotTo(gomega.Equal(checksum), field)
		}
	})
	ginkgo.It("preserves git pedigree when only a compiled ELF is imported", func(ctx ginkgo.SpecContext) {
		sources := []GitSource{{Repository: "https://example.invalid/project.git", Commit: strings.Repeat("a", 40), Add: "/code", To: "/src"}}
		checksum, err := GitSourcesChecksum(ctx, sources)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := fixtureRecord("c-static", "linux/amd64")
		record["components"].([]any)[0].(map[string]any)["version"] = "unspecified"
		record["components"].([]any)[0].(map[string]any)["source"].(map[string]string)["locator"] = "dk:image:app@" + checksum
		body := fixtureELF(elf.ET_EXEC, record)
		bom := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(map[string][]byte{"/out/app": body}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", BuildGitSources: [][]GitSource{sources}})).To(gomega.Succeed())
		encoded, err := cyclonedxutil.ToJSON(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(encoded)).To(gomega.Succeed())
		var transported cdx.BOM
		gomega.Expect(json.Unmarshal(encoded, &transported)).To(gomega.Succeed())
		originals, err := ImageOriginals(ctx, &transported, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		originals[0].Path = "/usr/bin/app"
		result := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(map[string][]byte{"/usr/bin/app": body}), result, VerifyOptions{Subject: "final", Platform: "linux/amd64", Originals: originals, TrustedComponents: *transported.Components})).To(gomega.Succeed())
		var ancestor *cdx.Component
		for _, component := range *result.Components {
			if component.Pedigree != nil && component.Pedigree.Ancestors != nil {
				gomega.Expect(*component.Pedigree.Ancestors).To(gomega.HaveLen(1))
				ancestor = &(*component.Pedigree.Ancestors)[0]
			}
		}
		gomega.Expect(ancestor).NotTo(gomega.BeNil())
		gomega.Expect(ancestor.Version).To(gomega.Equal(sources[0].Commit))
		gomega.Expect(*ancestor.ExternalReferences).To(gomega.ContainElement(cdx.ExternalReference{Type: cdx.ERTypeVCS, URL: sources[0].Repository}))
	})
	ginkgo.It("imports two components sharing a git ancestor without duplicate ancestor identifiers", func(ctx ginkgo.SpecContext) {
		sources := []GitSource{{Repository: "https://example.invalid/project.git", Commit: strings.Repeat("a", 40), Add: "/", To: "/src"}}
		checksum, err := GitSourcesChecksum(ctx, sources)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		files := map[string][]byte{}
		originals := []Original{}
		trusted := []cdx.Component{}
		for _, name := range []string{"one", "two"} {
			record := fixtureRecord("c-static", "linux/amd64")
			component := record["components"].([]any)[0].(map[string]any)
			component["name"], component["version"] = name, "unspecified"
			component["source"].(map[string]string)["locator"] = "dk:image:" + name + "@" + checksum
			filename := "/usr/bin/" + name
			body := fixtureELF(elf.ET_EXEC, record)
			bom := cdx.NewBOM()
			gomega.Expect(Verify(ctx, fixtureImage(map[string][]byte{filename: body}), bom, VerifyOptions{Subject: name, Platform: "linux/amd64", BuildGitSources: [][]GitSource{sources}})).To(gomega.Succeed())
			from, err := ImageOriginals(ctx, bom, "linux/amd64")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			originals = append(originals, from...)
			trusted = append(trusted, (*bom.Components)...)
			files[filename] = body
		}
		result := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(files), result, VerifyOptions{Subject: "final", Platform: "linux/amd64", Originals: originals, TrustedComponents: trusted})).To(gomega.Succeed())
		data, err := cyclonedxutil.ToJSON(result)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.Succeed())
		count := 0
		for _, component := range *result.Components {
			if component.Pedigree == nil {
				continue
			}
			count++
			for _, ancestor := range *component.Pedigree.Ancestors {
				gomega.Expect(ancestor.BOMRef).To(gomega.BeEmpty())
			}
		}
		gomega.Expect(count).To(gomega.Equal(2))
	})
	ginkgo.It("preserves imported component metadata when the current build has the same git identity", func(ctx ginkgo.SpecContext) {
		sources := []GitSource{{Repository: "https://example.invalid/project.git", Commit: strings.Repeat("a", 40), Add: "/", To: "/src"}}
		subject, _, err := declaredSubject(ctx, "app", sources)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := fixtureRecord("c-static", "linux/amd64")
		component := record["components"].([]any)[0].(map[string]any)
		component["version"] = "unspecified"
		component["source"].(map[string]string)["locator"] = subject.Source.Locator
		record["components"] = append(record["components"].([]any), map[string]any{"id": "dependency", "name": "dependency", "version": "1", "source": map[string]string{"kind": "declared", "locator": "dk:image:dependency"}})
		record["inputs"] = []any{map[string]any{"kind": "object", "origin": "build", "path": "/build/dependency.o", "sha256": "sha256:" + strings.Repeat("3", 64), "disposition": "included", "components": []string{"dependency"}}}
		body := fixtureELF(elf.ET_EXEC, record)
		bom := cdx.NewBOM()
		bom.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "source", BOMRef: "source-image"}}
		gomega.Expect(Verify(ctx, fixtureImage(map[string][]byte{"/out/app": body}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", BuildGitSources: [][]GitSource{sources}})).To(gomega.Succeed())
		property := cdx.Property{Name: "example:provenance", Value: "retained"}
		reference := cdx.ExternalReference{Type: cdx.ERTypeDistribution, URL: "https://example.invalid/release"}
		for i, component := range *bom.Components {
			if component.Pedigree != nil {
				*(*bom.Components)[i].Properties = append(*component.Properties, property)
				(*bom.Components)[i].ExternalReferences = &[]cdx.ExternalReference{reference}
			}
		}
		originals, err := ImageOriginals(ctx, bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.BOMRef).To(gomega.Equal("source-image"))
		result := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(map[string][]byte{"/out/app": body}), result, VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: originals, TrustedComponents: *bom.Components, BuildGitSources: [][]GitSource{sources}})).To(gomega.Succeed())
		gomega.Expect(*result.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Pedigree", gomega.Not(gomega.BeNil())), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(property))), gomega.HaveField("ExternalReferences", gomega.HaveValue(gomega.ContainElement(reference))))))
	})
	ginkgo.It("rejects a binary recorded for another git mapping identity", func(ctx ginkgo.SpecContext) {
		sources := []GitSource{{Repository: "https://example.invalid/project.git", Commit: strings.Repeat("a", 40), Add: "/", To: "/src"}}
		record := fixtureRecord("c-static", "linux/amd64")
		record["components"].([]any)[0].(map[string]any)["version"] = "unspecified"
		record["components"].([]any)[0].(map[string]any)["source"].(map[string]string)["locator"] = "dk:image:app@sha256:" + strings.Repeat("f", 64)
		err := Verify(ctx, fixtureImage(map[string][]byte{"/out/app": fixtureELF(elf.ET_EXEC, record)}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", BuildGitSources: [][]GitSource{sources}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/app"), gomega.ContainSubstring("subject"))))
	})
	ginkgo.It("keeps efb source SBOMs without pedigree valid for imports", func() {
		bom := fixtureContractBOM()
		originals, err := ImageOriginals(context.Background(), bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.Pedigree).To(gomega.BeNil())
		record := fixtureRecord("c-static", "linux/amd64")
		record["components"].([]any)[0].(map[string]any)["source"].(map[string]string)["locator"] = "https://example.invalid/app"
		body := fixtureELF(elf.ET_EXEC, record)
		gomega.Expect(fixtureDigest(body)).To(gomega.Equal(originals[0].SHA256))
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{originals[0].Path: body}), cdx.NewBOM(), VerifyOptions{Subject: "new-final", Platform: "linux/amd64", Originals: originals, TrustedComponents: *bom.Components})).To(gomega.Succeed())
	})
})
