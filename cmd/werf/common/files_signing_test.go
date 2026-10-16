package common

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/config"
)

var _ = Describe("files signing options", func() {
	signingConfig := func() *config.WerfConfig {
		return config.NewWerfConfig(&config.Meta{}, []config.ImageInterface{
			&config.StapelImage{StapelImageBase: &config.StapelImageBase{Name: "app", Sign: []*config.Sign{{Path: "/out/x", After: "install"}}}},
		})
	}

	DescribeTable("refuses an incomplete command line before any stage runs",
		func(cmdData *CmdData, expectedError string) {
			_, err := getFilesSigningOptions(context.Background(), cmdData, signingConfig())
			Expect(err).To(MatchError(ContainSubstring(expectedError)))
		},
		Entry("no key", &CmdData{SignFiles: lo.ToPtr(true)}, "images app declare files to sign: specify the signing key"),
		Entry("no certificate", &CmdData{SignFiles: lo.ToPtr(true), SignFilesKey: lo.ToPtr("k")}, "specify the signing certificate"),
		Entry("vault role without jwt", &CmdData{SignFiles: lo.ToPtr(true), SignFilesKey: lo.ToPtr("k"), SignFilesCert: lo.ToPtr("c"), SignFilesVaultAuthRole: lo.ToPtr("r")}, "qualify --sign-files-vault-auth-jwt"),
		Entry("vault auth path without jwt", &CmdData{SignFiles: lo.ToPtr(true), SignFilesKey: lo.ToPtr("k"), SignFilesCert: lo.ToPtr("c"), SignFilesVaultAuthPath: lo.ToPtr("fox")}, "qualify --sign-files-vault-auth-jwt"),
	)

	DescribeTable("is disabled without touching the key",
		func(cmdData *CmdData, werfConfig *config.WerfConfig) {
			options, err := getFilesSigningOptions(context.Background(), cmdData, werfConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(options.Enabled).To(BeFalse())
		},
		Entry("signing switched off", &CmdData{SignFiles: lo.ToPtr(false)}, signingConfig()),
		Entry("flag not registered", &CmdData{}, signingConfig()),
		Entry("no image declares files to sign", &CmdData{SignFiles: lo.ToPtr(true)}, config.NewWerfConfig(&config.Meta{}, []config.ImageInterface{
			&config.StapelImage{StapelImageBase: &config.StapelImageBase{Name: "app"}},
		})),
	)
})
