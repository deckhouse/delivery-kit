package build

import (
	"context"
	"encoding/json"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

var _ = ginkgo.Describe("producer prebuilt asset declarations", func() {
	binding := `{"sourceImage":"redoc","proofPath":"/proof/assets.json","assetPath":"bundles/redoc.standalone.js","installedPath":"/app/node_modules/redoc/bundles/redoc.standalone.js"}`
	declaration := func(assets string, webpack bool) []byte {
		sources := `"webpackSources":true,`
		if !webpack {
			sources = ""
		}

		return []byte(`{"version":1,"stages":{"install":{"subject":0,` + sources + `"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}],"prebuiltAssets":` + assets + `}}}`)
	}

	ginkgo.It("binds an installed file to the rebuild that produced it", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("["+binding+"]", true))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].PrebuiltAssets).To(gomega.Equal([]sbomBuildContextPrebuilt{{
			SourceImage:   "redoc",
			ProofPath:     "/proof/assets.json",
			AssetPath:     "bundles/redoc.standalone.js",
			InstalledPath: "/app/node_modules/redoc/bundles/redoc.standalone.js",
		}}))
	})

	ginkgo.DescribeTable("refuses a binding that delivers nothing provable", func(assets string, webpack bool) {
		_, err := parseSBOMBuildContextDeclaration(declaration(assets, webpack))
		gomega.Expect(err).To(gomega.HaveOccurred())
	},
		ginkgo.Entry("null", "null", true),
		ginkgo.Entry("not an array", binding, true),
		ginkgo.Entry("missing members", `[{}]`, true),
		ginkgo.Entry("unknown member", "["+strings.Replace(binding, `"proofPath"`, `"extra":true,"proofPath"`, 1)+"]", true),
		ginkgo.Entry("duplicate member", "["+strings.Replace(binding, `"proofPath"`, `"proofPath":"/other.json","proofPath"`, 1)+"]", true),
		ginkgo.Entry("relative proof path", "["+strings.Replace(binding, `"/proof/assets.json"`, `"proof/assets.json"`, 1)+"]", true),
		ginkgo.Entry("unclean installed path", "["+strings.Replace(binding, `"/app/node_modules/redoc/bundles/redoc.standalone.js"`, `"/app/node_modules/redoc/../redoc/bundles/x.js"`, 1)+"]", true),
		ginkgo.Entry("absolute asset path", "["+strings.Replace(binding, `"bundles/redoc.standalone.js"`, `"/bundles/redoc.standalone.js"`, 1)+"]", true),
		ginkgo.Entry("asset path reaching out of the output", "["+strings.Replace(binding, `"bundles/redoc.standalone.js"`, `"../redoc.standalone.js"`, 1)+"]", true),
		ginkgo.Entry("installed outside node_modules", "["+strings.Replace(binding, `"/app/node_modules/redoc/bundles/redoc.standalone.js"`, `"/app/vendor/redoc.js"`, 1)+"]", true),
		ginkgo.Entry("the same installed file twice", "["+binding+","+binding+"]", true),
		// The delivered composition is written beside the originals manifest, and
		// the installed digest is only proven there.
		ginkgo.Entry("without the originals manifest", "["+binding+"]", false),
	)

	ginkgo.It("leaves a declaration that delivers nothing untouched", func() {
		parsed, err := parseSBOMBuildContextDeclaration([]byte(`{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].PrebuiltAssets).To(gomega.BeEmpty())
	})
})

const prebuiltInstalled = "/app/node_modules/redoc/bundles/redoc.standalone.js"

func prebuiltComponent() map[string]any {
	return map[string]any{
		"id": "node:redoc@2.4.0", "name": "redoc", "version": "2.4.0",
		"source": map[string]any{"kind": "node", "locator": "https://registry.yarnpkg.com/redoc/-/redoc-2.4.0.tgz", "checksum": "sha512-" + strings.Repeat("c", 86) + "=="},
	}
}

func prebuiltOtherComponent() map[string]any {
	return map[string]any{
		"id": "node:other@1.0.0", "name": "other", "version": "1.0.0",
		"source": map[string]any{"kind": "node", "locator": "https://registry.yarnpkg.com/other/-/other-1.0.0.tgz", "checksum": "sha512-" + strings.Repeat("d", 86) + "=="},
	}
}

func prebuiltRow(overrides map[string]any) map[string]any {
	row := map[string]any{
		"path": "bundles/redoc.standalone.js", "sha256": "sha256:" + strings.Repeat("a", 64), "size": 12,
		"status": "present", "includedComponents": []any{"node:redoc@2.4.0"},
		"components": []any{prebuiltComponent()},
		"inputs": []any{map[string]any{
			"kind": "source", "path": "src/index.tsx", "sha256": "sha256:" + strings.Repeat("b", 64),
			"components": []any{"node:redoc@2.4.0"}, "disposition": "included",
		}},
		"tools": []any{},
	}
	for key, value := range overrides {
		if value == nil {
			delete(row, key)
			continue
		}
		row[key] = value
	}

	return row
}

func prebuiltProof(rows ...map[string]any) []byte {
	assets := make([]any, 0, len(rows))
	for _, row := range rows {
		assets = append(assets, row)
	}
	body, err := json.Marshal(map[string]any{"version": 1, "sourceRoot": "/build/dist", "assets": assets})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return body
}

// The composition of a delivered row is carried into this build's own evidence, so the
// shared validator has to accept it as it stands - including the paths it names, which
// are paths of the container the rebuild ran in and of no tree this build has.
var _ = ginkgo.Describe("a delivered composition held to the shared validator", func() {
	composition := func(row map[string]any) []byte {
		body, err := json.Marshal(map[string]any{
			"components": row["components"], "includedComponents": row["includedComponents"],
			"inputs": row["inputs"], "tools": row["tools"],
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		return body
	}

	ginkgo.It("accepts the absolute rebuild-container paths a collector proof names", func() {
		row := prebuiltRow(map[string]any{"inputs": []any{map[string]any{
			"kind": "source", "path": "/build/src/index.tsx", "sha256": "sha256:" + strings.Repeat("b", 64),
			"components": []any{"node:redoc@2.4.0"}, "disposition": "included",
		}}})
		status, err := shared.ValidateComposition(composition(row), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(status).To(gomega.Equal("present"))
	})

	ginkgo.It("accepts the relative paths a collector proof names as well", func() {
		status, err := shared.ValidateComposition(composition(prebuiltRow(nil)), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(status).To(gomega.Equal("present"))
	})
})

var _ = ginkgo.Describe("reading a prebuilt composition out of a rebuild proof", func() {
	ginkgo.It("carries the components and inputs of the row it delivers", func() {
		asset, err := prebuiltAssetFromProof(prebuiltProof(prebuiltRow(nil)), "bundles/redoc.standalone.js", prebuiltInstalled)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(asset.InstalledPath).To(gomega.Equal(prebuiltInstalled))
		gomega.Expect(asset.SHA256).To(gomega.Equal("sha256:" + strings.Repeat("a", 64)))
		gomega.Expect(asset.Components).To(gomega.HaveLen(1))
		gomega.Expect(asset.Components[0].ID).To(gomega.Equal("node:redoc@2.4.0"))
		gomega.Expect(asset.Inputs).To(gomega.Equal([]nativegate.PrebuiltInput{{
			Path: "src/index.tsx", SHA256: "sha256:" + strings.Repeat("b", 64), Components: []string{"node:redoc@2.4.0"},
		}}))
	})

	ginkgo.It("delivers the row it was asked for and no other", func() {
		other := prebuiltRow(map[string]any{"path": "bundles/other.js"})
		asset, err := prebuiltAssetFromProof(prebuiltProof(other, prebuiltRow(nil)), "bundles/redoc.standalone.js", prebuiltInstalled)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(asset.SHA256).To(gomega.Equal("sha256:" + strings.Repeat("a", 64)))
	})

	ginkgo.DescribeTable("refuses a proof that delivers no provable composition", func(body []byte, expected string) {
		_, err := prebuiltAssetFromProof(body, "bundles/redoc.standalone.js", prebuiltInstalled)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("unreadable", []byte(`{"version":1,"assets":[`), "invalid: prebuilt proof JSON"),
		ginkgo.Entry("not an object", []byte(`[]`), "invalid: prebuilt proof JSON"),
		ginkgo.Entry("no version", []byte(`{"assets":[]}`), "no-data: prebuilt proof has no version"),
		ginkgo.Entry("null version", []byte(`{"version":null,"assets":[]}`), "invalid: prebuilt proof version is null"),
		ginkgo.Entry("another version", []byte(`{"version":2,"assets":[]}`), "unsupported: prebuilt proof version 2"),
		ginkgo.Entry("noncanonical field", []byte(`{"version":1,"Assets":[]}`), "invalid: unknown prebuilt proof member Assets"),
		// A member this build does not know may be the one that qualifies what
		// the rest of the document says.
		ginkgo.Entry("unknown member", []byte(`{"version":1,"assets":[],"partial":true}`), "invalid: unknown prebuilt proof member partial"),
		ginkgo.Entry("no assets", []byte(`{"version":1}`), "no-data: prebuilt proof has no assets"),
		// The row this delivery is for must be there, exactly once, and described.
		ginkgo.Entry("the row is absent", prebuiltProof(prebuiltRow(map[string]any{"path": "bundles/other.js"})),
			"no-data: prebuilt proof states no asset bundles/redoc.standalone.js"),
		ginkgo.Entry("the row is stated twice", prebuiltProof(prebuiltRow(nil), prebuiltRow(nil)),
			"invalid: prebuilt proof states bundles/redoc.standalone.js twice"),
		ginkgo.Entry("the rebuild could not describe it", prebuiltProof(prebuiltRow(map[string]any{
			"status": "no-data", "sha256": "", "size": 0, "components": []any{}, "includedComponents": []any{}, "inputs": []any{},
		})), "no-data: prebuilt asset bundles/redoc.standalone.js is no-data in its own proof"),
		ginkgo.Entry("the row carries no digest", prebuiltProof(prebuiltRow(map[string]any{"sha256": "sha256:short"})),
			"invalid: prebuilt asset bundles/redoc.standalone.js carries no sha256 digest"),
		ginkgo.Entry("the row is described as empty", prebuiltProof(prebuiltRow(map[string]any{"size": 0})),
			"invalid: prebuilt asset bundles/redoc.standalone.js is described as empty"),
		ginkgo.Entry("the row states no components", prebuiltProof(prebuiltRow(map[string]any{
			"components": []any{}, "includedComponents": []any{}, "inputs": []any{},
		})), "no-data: prebuilt asset bundles/redoc.standalone.js states no components"),
		ginkgo.Entry("a component is repeated", prebuiltProof(prebuiltRow(map[string]any{
			"components": []any{prebuiltComponent(), prebuiltComponent()},
		})), "states an unnamed or repeated component"),
		ginkgo.Entry("an included component is not stated", prebuiltProof(prebuiltRow(map[string]any{
			"includedComponents": []any{"npm:ghost@1.0.0"},
		})), "includes the unstated component npm:ghost@1.0.0"),
		ginkgo.Entry("an input is claimed by a component that is not stated", prebuiltProof(prebuiltRow(map[string]any{
			"inputs": []any{map[string]any{"kind": "source", "path": "a.ts", "sha256": "sha256:" + strings.Repeat("b", 64), "components": []any{"npm:ghost@1.0.0"}, "disposition": "included"}},
		})), "claimed by the unstated component npm:ghost@1.0.0"),
		ginkgo.Entry("an input carries no digest", prebuiltProof(prebuiltRow(map[string]any{
			"inputs": []any{map[string]any{"kind": "source", "path": "a.ts", "sha256": "nope", "components": []any{"node:redoc@2.4.0"}, "disposition": "included"}},
		})), "states an unnamed or undigested input"),
		ginkgo.Entry("an input is claimed by nobody", prebuiltProof(prebuiltRow(map[string]any{
			"inputs": []any{map[string]any{"kind": "source", "path": "a.ts", "sha256": "sha256:" + strings.Repeat("b", 64), "components": []any{}, "disposition": "included"}},
		})), "claimed by no component"),
		// A composition of components alone states what the asset is said to
		// contain without stating one byte it was built from.
		ginkgo.Entry("the row states no inputs", prebuiltProof(prebuiltRow(map[string]any{"inputs": []any{}})),
			"no-data: prebuilt asset bundles/redoc.standalone.js states no inputs"),
		ginkgo.Entry("a stated component is not included", prebuiltProof(prebuiltRow(map[string]any{
			"includedComponents": []any{},
		})), "states the component node:redoc@2.4.0 it does not include"),
		ginkgo.Entry("a stated component is claimed by no input", prebuiltProof(prebuiltRow(map[string]any{
			"components":         []any{prebuiltComponent(), prebuiltOtherComponent()},
			"includedComponents": []any{"node:redoc@2.4.0", "node:other@1.0.0"},
		})), "states the component node:other@1.0.0 no input is claimed by"),
	)
})

var _ = ginkgo.Describe("holding a prebuilt source to the recipe of this configuration", func() {
	declaring := func(labels map[string]string) config.ImageInterface {
		base := &config.StapelImageBase{Name: "redoc"}
		if labels != nil {
			base.ImageSpec = &config.ImageSpec{Labels: labels}
		}

		return &config.StapelImage{StapelImageBase: base}
	}
	producer := `{"version":1,"stages":{"install":{"subject":0,"webpackSources":true,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`

	ginkgo.It("accepts an image declared to run the webpack collector", func() {
		gomega.Expect(checkPrebuiltSourceDeclaration(declaring(map[string]string{sbomBuildContextLabel: producer}), "redoc")).To(gomega.Succeed())
	})

	ginkgo.DescribeTable("refuses an image that cannot have written a collector proof", func(configured config.ImageInterface, expected string) {
		gomega.Expect(checkPrebuiltSourceDeclaration(configured, "redoc")).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("no image of this configuration", nil, "is no image of this configuration"),
		ginkgo.Entry("a typed nil", (*config.StapelImage)(nil), "is no image of this configuration"),
		ginkgo.Entry("no image spec at all", declaring(nil), "declares no producer context"),
		ginkgo.Entry("no producer declaration", declaring(map[string]string{"other": "1"}), "declares no producer context"),
		ginkgo.Entry("an unreadable declaration", declaring(map[string]string{sbomBuildContextLabel: "{"}), "parse SBOM build context declaration"),
		// A stage that never asks for the collector cannot have run it.
		ginkgo.Entry("no stage running the collector", declaring(map[string]string{sbomBuildContextLabel: strings.Replace(producer, `"webpackSources":true,`, "", 1)}),
			"declares no stage that runs the webpack collector"),
	)
})

// The declaration check has to stand in the path a build really takes, before
// anything of the named image is read.
var _ = ginkgo.Describe("reading deliveries declared against an undeclared source", func() {
	ginkgo.It("refuses before resolving the image it names", func() {
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{werfConfig: &config.WerfConfig{}}}}
		_, _, err := phase.producerPrebuiltAssets(context.Background(), nil, "", []sbomBuildContextPrebuilt{{
			SourceImage: "redoc", ProofPath: "/proof/assets.json",
			AssetPath: "bundles/redoc.standalone.js", InstalledPath: prebuiltInstalled,
		}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("prebuilt source redoc is no image of this configuration")))
	})
})
