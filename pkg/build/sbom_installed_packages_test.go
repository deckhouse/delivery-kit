package build

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("Installed package scanning", func() {
	DescribeTable("inventories metadata independently of declarations and preserves the declaration graph when merging",
		func(specCtx SpecContext, metadataPath, catalogerName, language, purl, symlinkTarget string) {
			ctx := logging.WithLogger(specCtx)
			ctrl := gomock.NewController(GinkgoT())
			backend := mock.NewMockContainerBackend(ctrl)
			reader := mock.NewMockImageReader(ctrl)
			backend.EXPECT().OpenImageReader(gomock.Any(), "app:latest", gomock.Any()).Return(reader, nil)
			index := &shippedscope.FileIndex{Files: map[string]shippedscope.File{metadataPath: {Size: 8}}}
			readPath := metadataPath
			if symlinkTarget != "" {
				index.Files = map[string]shippedscope.File{symlinkTarget: {Size: 8}}
				index.Symlinks = map[string]string{metadataPath: symlinkTarget}
				readPath = symlinkTarget
			}
			reader.EXPECT().ReadFile(gomock.Any(), readPath).Return([]byte("metadata"), nil)
			reader.EXPECT().Close(gomock.Any()).Return(nil)

			installed := cdx.Component{
				Type: cdx.ComponentTypeLibrary, BOMRef: "installed", Name: "installed", Version: "2.0", PackageURL: purl,
				Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
			}
			scanned := cyclonedxutil.NewBOM()
			scanned.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeFile, Name: "/scan", BOMRef: "scan"}}
			scanned.Components = &[]cdx.Component{installed, {Type: cdx.ComponentTypeFile, Name: "METADATA", BOMRef: "file"}}
			scanned.Dependencies = &[]cdx.Dependency{{Ref: "scan", Dependencies: lo.ToPtr([]string{"installed"})}}
			data, err := cyclonedxutil.ToJSON(scanned)
			Expect(err).NotTo(HaveOccurred())

			var scanDir string
			backend.EXPECT().GenerateSBOM(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, opts scanner.ScanOptions) ([]byte, error) {
				Expect(opts.Commands).To(HaveLen(1))
				cmd := opts.Commands[0]
				Expect(cmd.SourceType).To(Equal(scanner.SourceTypeDir))
				Expect(cmd.Catalogers).To(HaveLen(1))
				Expect(cmd.Catalogers[0].Name).To(Equal(catalogerName))
				Expect(cmd.Catalogers[0].Ecosystem).To(BeEmpty(), "inventory is not a packages directive")
				scanDir = cmd.SourcePath
				body, err := os.ReadFile(filepath.Join(scanDir, metadataPath))
				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(Equal("metadata"))
				parent, err := os.Stat(filepath.Dir(scanDir))
				Expect(err).NotTo(HaveOccurred())
				Expect(parent.Mode().Perm()).To(Equal(os.FileMode(0o700)))
				return data, nil
			})

			step := &sbomStep{containerBackend: backend}
			opts := scanner.DefaultSyftScanOptions()
			originalSource := opts.Commands[0].SourceType
			boms, err := step.scanInstalledPackages(ctx, &image.Info{Name: "app:latest"}, opts, index, "linux/amd64")
			Expect(err).NotTo(HaveOccurred())
			Expect(boms).To(HaveLen(1))
			Expect(lo.FromPtr(boms[0].Components)).To(HaveLen(1))
			Expect(gost.GetComponentSourceLangs(ctx, &(*boms[0].Components)[0])).To(Equal([]string{language}))
			Expect(boms[0].Dependencies).To(BeNil(), "installed metadata must not invent root or optional-dependency edges")
			Expect(opts.Commands[0].SourceType).To(Equal(originalSource))
			_, err = os.Stat(scanDir)
			Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue())

			declared := cyclonedxutil.NewBOM()
			declared.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "app", BOMRef: "app"}}
			declaration := installed
			declaration.BOMRef = "declared"
			declaration.Licenses = &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}}
			child := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "child", Version: "1.0", BOMRef: "child", PackageURL: "pkg:generic/child@1.0"}
			declared.Components = &[]cdx.Component{declaration, child}
			declared.Dependencies = &[]cdx.Dependency{
				{Ref: "app", Dependencies: lo.ToPtr([]string{"declared"})},
				{Ref: "declared", Dependencies: lo.ToPtr([]string{"child"})},
			}
			merged, err := cyclonedxutil.MergeBOMs(ctx, declared, cyclonedxutil.MergeOpts{ImportBOMs: boms})
			Expect(err).NotTo(HaveOccurred())
			Expect(merged.Metadata.Component.Name).To(Equal("app"))
			Expect(merged.Metadata.Component.Type).To(Equal(cdx.ComponentTypeContainer))
			Expect(lo.FromPtr(merged.Components)).To(HaveLen(2))
			comp, found := lo.Find(*merged.Components, func(c cdx.Component) bool { return c.PackageURL == purl })
			Expect(found).To(BeTrue())
			Expect(comp.PackageURL).To(Equal(purl))
			Expect(lo.FromPtr(comp.Licenses)).To(ConsistOf(
				cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}},
				cdx.LicenseChoice{License: &cdx.License{ID: "Apache-2.0"}},
			))
			root, found := lo.Find(lo.FromPtr(merged.Dependencies), func(d cdx.Dependency) bool { return d.Ref == merged.Metadata.Component.BOMRef })
			Expect(found).To(BeTrue())
			Expect(lo.FromPtr(root.Dependencies)).To(Equal([]string{comp.BOMRef}))
			mergedChild, found := lo.Find(*merged.Components, func(c cdx.Component) bool { return c.PackageURL == child.PackageURL })
			Expect(found).To(BeTrue())
			dependency, found := lo.Find(lo.FromPtr(merged.Dependencies), func(d cdx.Dependency) bool { return d.Ref == comp.BOMRef })
			Expect(found).To(BeTrue())
			Expect(lo.FromPtr(dependency.Dependencies)).To(Equal([]string{mergedChild.BOMRef}))
		},
		Entry("Python", "/opt/vendor/installed-2.0.dist-info/METADATA", "python-installed-package-cataloger", "Python", "pkg:pypi/installed@2.0", ""),
		Entry("JavaScript", "/app/node_modules/installed/package.json", "javascript-package-cataloger", "JavaScript", "pkg:npm/installed@2.0", ""),
		Entry("Lua", "/usr/lib/luarocks/rocks-5.4/installed/2.0/installed-2.0.rockspec", "lua-rock-cataloger", "Lua", "pkg:luarocks/installed@2.0", ""),
		Entry("symlinked JavaScript metadata", "/app/node_modules/installed/package.json", "javascript-package-cataloger", "JavaScript", "pkg:npm/installed@2.0", "/shared/manifest"),
	)

	It("does not start a scanner when no installed metadata exists", func(ctx SpecContext) {
		step := &sbomStep{containerBackend: mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))}
		boms, err := step.scanInstalledPackages(ctx, &image.Info{Name: "app:latest"}, scanner.DefaultSyftScanOptions(),
			&shippedscope.FileIndex{Files: map[string]shippedscope.File{"/app/requirements.txt": {Size: 123}}}, "linux/amd64")
		Expect(err).NotTo(HaveOccurred())
		Expect(boms).To(BeEmpty())
	})

	It("propagates metadata read errors without returning a partial inventory", func(ctx SpecContext) {
		ctrl := gomock.NewController(GinkgoT())
		backend := mock.NewMockContainerBackend(ctrl)
		reader := mock.NewMockImageReader(ctrl)
		backend.EXPECT().OpenImageReader(gomock.Any(), "app:latest", gomock.Any()).Return(reader, nil)
		reader.EXPECT().ReadFile(gomock.Any(), gomock.Any()).Return(nil, os.ErrPermission)
		reader.EXPECT().Close(gomock.Any()).Return(nil)
		step := &sbomStep{containerBackend: backend}
		boms, err := step.scanInstalledPackages(ctx, &image.Info{Name: "app:latest"}, scanner.DefaultSyftScanOptions(),
			&shippedscope.FileIndex{Files: map[string]shippedscope.File{"/app/node_modules/pkg/package.json": {Size: 123}}}, "linux/amd64")
		Expect(errors.Is(err, os.ErrPermission)).To(BeTrue())
		Expect(boms).To(BeNil())
	})
})
