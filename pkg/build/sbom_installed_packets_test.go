package build

import (
	"encoding/json"
	"fmt"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

var _ = ginkgo.Describe("producer installed packet declarations", func() {
	packet := `{"packageName":"esbuild","packageVersion":"0.25.0","packageType":"file","sourcePlatform":"linux/amd64","files":["/usr/lib/esbuild/bin/esbuild","/usr/lib/esbuild/lib/main.js"]}`
	declaration := func(packets string) []byte {
		return []byte(`{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}],"installedPackets":` + packets + `}}}`)
	}

	ginkgo.It("names the packet identity and the installed files the stage is held to", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + packet + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].InstalledPackets).To(gomega.Equal([]sbomBuildContextInstalledPacket{{
			PackageName:    "esbuild",
			PackageVersion: "0.25.0",
			PackageType:    "file",
			SourcePlatform: "linux/amd64",
			Files:          []string{"/usr/lib/esbuild/bin/esbuild", "/usr/lib/esbuild/lib/main.js"},
		}}))
	})

	ginkgo.It("accepts one packet identity per platform", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + packet + "," +
			strings.NewReplacer(`"linux/amd64"`, `"linux/arm64"`, `"/usr/lib/esbuild/bin/esbuild"`, `"/opt/arm64/esbuild/bin/esbuild"`, `"/usr/lib/esbuild/lib/main.js"`, `"/opt/arm64/esbuild/lib/main.js"`).Replace(packet) + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].InstalledPackets).To(gomega.HaveLen(2))
	})

	ginkgo.DescribeTable("refuses a packet nothing could be held against", func(packets, expected string) {
		_, err := parseSBOMBuildContextDeclaration(declaration(packets))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("null", "null", "installedPackets must be an array"),
		ginkgo.Entry("not an array", packet, "cannot unmarshal object"),
		ginkgo.Entry("unknown member", "["+strings.Replace(packet, `"packageName"`, `"registry":"example.org/packages","packageName"`, 1)+"]", "unknown field"),
		ginkgo.Entry("missing identity", `[{"files":["/usr/lib/esbuild/bin/esbuild"]}]`, "installedPacket 0: packageName is required"),
		ginkgo.Entry("no type", "["+strings.Replace(packet, `"packageType":"file",`, "", 1)+"]", "installedPacket 0: packageType is required"),
		ginkgo.Entry("host platform", "["+strings.Replace(packet, `"linux/amd64"`, `"darwin/arm64"`, 1)+"]", `sourcePlatform "darwin/arm64" is not a canonical linux platform`),
		ginkgo.Entry("no files", "["+strings.Replace(packet, `["/usr/lib/esbuild/bin/esbuild","/usr/lib/esbuild/lib/main.js"]`, "[]", 1)+"]", "installedPacket 0: at least one installed file is required"),
		ginkgo.Entry("relative file", "["+strings.Replace(packet, `"/usr/lib/esbuild/bin/esbuild"`, `"usr/lib/esbuild/bin/esbuild"`, 1)+"]", "installedPacket 0: files must be a clean absolute path"),
		ginkgo.Entry("unclean file", "["+strings.Replace(packet, `"/usr/lib/esbuild/bin/esbuild"`, `"/usr/lib/esbuild/bin/../bin/esbuild"`, 1)+"]", "installedPacket 0: files must be a clean absolute path"),
		ginkgo.Entry("one file declared twice", "["+strings.Replace(packet, `"/usr/lib/esbuild/lib/main.js"`, `"/usr/lib/esbuild/bin/esbuild"`, 1)+"]", `installedPacket 0: file "/usr/lib/esbuild/bin/esbuild" is declared more than once`),
		ginkgo.Entry("one file claimed by two packets", "["+packet+","+strings.Replace(packet, `"esbuild","packageVersion":"0.25.0"`, `"esbuild","packageVersion":"0.17.19"`, 1)+"]", `installedPacket 1: file "/usr/lib/esbuild/bin/esbuild" is declared more than once`),
		ginkgo.Entry("one identity declared twice", "["+packet+","+strings.Replace(packet, `["/usr/lib/esbuild/bin/esbuild","/usr/lib/esbuild/lib/main.js"]`, `["/opt/esbuild/bin/esbuild"]`, 1)+"]", "installedPacket 1: esbuild 0.25.0 is declared more than once"),
	)
})

// installedPacketReceiptEntry is one entry of the receipt pm writes where it installed a
// packet: the registry it opened the packet from, the explicit platform and the packet
// metadata pinning the manifest digest.
func installedPacketReceiptEntry(registry, name, version string) sources.Source {
	packet := fmt.Sprintf(`{"name":%q,"version":%q,"type":"file","arch":["linux/amd64"],"digest":"sha256:%s","license":"MIT"}`, name, version, strings.Repeat("b", 64))

	return sources.Source{Registry: registry, Platform: "linux/amd64", Packet: json.RawMessage(packet)}
}

func installedPacketDeclared() sbomBuildContextInstalledPacket {
	return sbomBuildContextInstalledPacket{
		PackageName: "esbuild", PackageVersion: "0.25.0", PackageType: "file", SourcePlatform: "linux/amd64",
		Files: []string{"/usr/lib/esbuild/bin/esbuild"},
	}
}

var _ = ginkgo.Describe("selecting the packets a stage installed", func() {
	entry := installedPacketReceiptEntry("example.org/packages/esbuild", "esbuild", "0.25.0")
	observed := func(receipt *sources.Receipt) []sbomSourceSnapshot {
		return []sbomSourceSnapshot{
			{Stage: stage.From},
			{Stage: stage.Packages, Receipt: receipt},
			{Stage: stage.Install},
		}
	}

	ginkgo.It("takes where the packet came from from the install receipt, not from the declaration", func() {
		opened, installed, err := producerInstalledPackets(observed(&sources.Receipt{Version: sources.Version, Sources: []sources.Source{
			installedPacketReceiptEntry("example.org/packages/other", "other", "1.0"), entry,
		}}), []sbomBuildContextInstalledPacket{installedPacketDeclared()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(opened).To(gomega.Equal([]sources.Source{entry}))
		gomega.Expect(installed).To(gomega.Equal([]nativegate.InstalledPacket{{
			Name: "esbuild", Version: "0.25.0", Type: "file", Platform: "linux/amd64",
			Files: []string{"/usr/lib/esbuild/bin/esbuild"},
		}}))
	})

	ginkgo.It("reads nothing where the stage declares no installed packet", func() {
		opened, installed, err := producerInstalledPackets(observed(nil), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(opened).To(gomega.BeEmpty())
		gomega.Expect(installed).To(gomega.BeEmpty())
	})

	ginkgo.It("refuses built stages that opened packages at two boundaries", func() {
		receipt := &sources.Receipt{Version: sources.Version, Sources: []sources.Source{entry}}
		_, _, err := producerInstalledPackets([]sbomSourceSnapshot{
			{Stage: stage.From}, {Stage: stage.Packages, Receipt: receipt}, {Stage: stage.Packages, Receipt: receipt}, {Stage: stage.Install},
		}, []sbomBuildContextInstalledPacket{installedPacketDeclared()})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: 2 package install boundaries among the built stages, need exactly one")))
	})

	ginkgo.It("refuses built stages that hold no package install boundary", func() {
		_, _, err := producerInstalledPackets([]sbomSourceSnapshot{{Stage: stage.From}, {Stage: stage.Install}},
			[]sbomBuildContextInstalledPacket{installedPacketDeclared()})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: 0 package install boundaries among the built stages, need exactly one")))
	})

	ginkgo.It("refuses a receipt that opened another version of the declared packet", func() {
		_, _, err := producerInstalledPackets(observed(&sources.Receipt{Version: sources.Version, Sources: []sources.Source{
			installedPacketReceiptEntry("example.org/packages/esbuild", "esbuild", "0.17.19"),
		}}), []sbomBuildContextInstalledPacket{installedPacketDeclared()})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: 0 receipt entries open the file packet esbuild 0.25.0 for linux/amd64")))
	})
})
