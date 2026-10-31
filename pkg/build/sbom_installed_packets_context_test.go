package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/logging"
)

const (
	producerPacketName    = "esbuild"
	producerPacketVersion = "0.25.0-flant.1"
	producerPacketType    = "runtime"
	producerPacketBinary  = "/usr/lib/esbuild/bin/esbuild"
	producerPacketEntry   = "/usr/lib/esbuild/lib/main.js"
	producerPacketRuntime = "/usr/lib/esbuild/src/internal/runtime/runtime.go"
)

// producerPacketFiles is the tool layout a strict esbuild packet delivers: the checked
// executable, the prepared client the bundler loads and the runtime source its evidence
// is pinned to.
func producerPacketFiles() map[string]string {
	return map[string]string{
		producerPacketBinary:  "instrumented executable",
		producerPacketEntry:   "prepared client",
		producerPacketRuntime: "runtime source",
	}
}

// producerPacketReceipt is what pm writes where it opened the packet: the registry it
// came from, the explicit platform and the packet metadata pinning the manifest digest.
func producerPacketReceipt(repo, pinned string) string {
	ginkgo.GinkgoHelper()
	packet := fmt.Sprintf(`{"name":%q,"version":%q,"type":%q,"arch":["linux/amd64"],"digest":%q,"license":"MIT"}`,
		producerPacketName, producerPacketVersion, producerPacketType, pinned)
	body, err := sources.Encode(&sources.Receipt{Version: sources.Version, Sources: []sources.Source{
		{Registry: repo, Platform: producerPlatform, Packet: json.RawMessage(packet)},
	}})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return string(body)
}

// producerInstalledPacketDeclaration is the intent of a checked Webpack stage whose
// esbuild comes from a packet pm installed rather than from an image of this config.
func producerInstalledPacketDeclaration(files ...string) string {
	ginkgo.GinkgoHelper()
	if len(files) == 0 {
		files = []string{producerPacketBinary, producerPacketEntry, producerPacketRuntime}
	}
	declared, err := json.Marshal(files)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	packets := fmt.Sprintf(`"installedPackets":[{"packageName":%q,"packageVersion":%q,"packageType":%q,"sourcePlatform":%q,"files":%s}]`,
		producerPacketName, producerPacketVersion, producerPacketType, producerPlatform, declared)

	return webpackDeclaration(webpackStageSettings + "," + packets)
}

var _ = ginkgo.Describe("Building a producer context on a packet pm installed", func() {
	ginkgo.It("pins the packet of the install receipt and names its files for the collector", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{
			installedPacket: true, declaration: producerInstalledPacketDeclaration(),
		})

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ginkgo.DeferCleanup(func() { gomega.Expect(input.remove()).To(gomega.Succeed()) })

		written := producerWrittenContext(input)
		// The prepared source of the project, then the packet the receipt opened.
		gomega.Expect(written.Packages).To(gomega.HaveLen(2))
		gomega.Expect(written.Packages[0].Registry).To(gomega.Equal(fixture.sourceRepo))
		gomega.Expect(written.Packages[1].Registry).To(gomega.Equal(fixture.packetRepo))
		gomega.Expect(written.Packages[1].Platform).To(gomega.Equal(producerPlatform))
		gomega.Expect(string(written.Packages[1].Packet)).To(gomega.ContainSubstring(`"digest":"` + fixture.packetDigest + `"`))
		gomega.Expect(written.Subject.Name).To(gomega.Equal(producerSourceName), "the subject stays the project's own prepared source")

		paths := map[string]string{}
		for _, mapping := range written.Imports {
			gomega.Expect(mapping.Package).NotTo(gomega.BeNil())
			paths[mapping.Path] = fmt.Sprintf("%d:%s", *mapping.Package, mapping.OriginalPath)
		}
		gomega.Expect(paths).To(gomega.Equal(map[string]string{
			"/src/main.c":         "0:src/main.c",
			producerPacketBinary:  "1:usr/lib/esbuild/bin/esbuild",
			producerPacketEntry:   "1:usr/lib/esbuild/lib/main.js",
			producerPacketRuntime: "1:usr/lib/esbuild/src/internal/runtime/runtime.go",
		}))

		body, err := os.ReadFile(filepath.Join(input.directory, "webpack-originals.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		manifest := string(body)
		gomega.Expect(manifest).To(gomega.ContainSubstring(fmt.Sprintf(`"name":%q,"version":%q`, producerPacketName, producerPacketVersion)))
		gomega.Expect(manifest).To(gomega.ContainSubstring(fmt.Sprintf(`"locator":%q,"checksum":%q`, fixture.packetRepo, fixture.packetDigest)))
		for _, name := range []string{producerPacketBinary, producerPacketEntry, producerPacketRuntime, "/src/main.c"} {
			gomega.Expect(manifest).To(gomega.ContainSubstring(fmt.Sprintf(`"path":%q`, name)))
		}
		gomega.Expect(input.checksum).NotTo(gomega.BeEmpty())
	})

	ginkgo.It("refuses the stage when it declares a file the packet never served", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{
			installedPacket: true,
			declaration:     producerInstalledPacketDeclaration(producerPacketBinary, "/usr/lib/esbuild/bin/esbuild-wrapper"),
		})

		_, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /usr/lib/esbuild/bin/esbuild-wrapper does not stand in the build as bytes the runtime packet esbuild 0.25.0-flant.1 still serves")))
	})

	ginkgo.It("refuses the stage when the build no longer holds the installed executable", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{
			installedPacket:     true,
			declaration:         producerInstalledPacketDeclaration(),
			replacedPacketFiles: map[string]string{producerPacketBinary: "another executable"},
		})

		_, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: " + producerPacketBinary + " does not stand in the build as bytes the runtime packet esbuild 0.25.0-flant.1 still serves")))
	})

	ginkgo.It("refuses a packet identity the install receipt never opened", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{
			installedPacket: true,
			declaration:     strings.Replace(producerInstalledPacketDeclaration(), producerPacketVersion, "0.25.0", 1),
		})

		_, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: 0 receipt entries open the runtime packet esbuild 0.25.0 for linux/amd64")))
	})

	ginkgo.It("names no packet where the stage declares none", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{
			installedPacket: true, declaration: webpackDeclaration(webpackStageSettings),
		})

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ginkgo.DeferCleanup(func() { gomega.Expect(input.remove()).To(gomega.Succeed()) })

		gomega.Expect(producerWrittenContext(input).Packages).To(gomega.HaveLen(1))
		body, err := os.ReadFile(filepath.Join(input.directory, "webpack-originals.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(body)).NotTo(gomega.ContainSubstring("esbuild"))
	})
})
