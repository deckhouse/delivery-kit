package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("StapelImageBase OSPMLockPath", func() {
	It("returns empty string when no packages are configured", func() {
		base := &StapelImageBase{}
		Expect(base.OSPMLockPath()).To(Equal(""))
	})

	It("returns empty string when only non-os-pm packages are configured", func() {
		base := &StapelImageBase{
			Packages: []*PackagesDirective{
				{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"}},
			},
		}
		Expect(base.OSPMLockPath()).To(Equal(""))
	})

	It("returns empty string when multiple non-os-pm packages are configured", func() {
		base := &StapelImageBase{
			Packages: []*PackagesDirective{
				{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"}},
				{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/native", Spec: "Cargo.toml", Lock: "Cargo.lock"}},
			},
		}
		Expect(base.OSPMLockPath()).To(Equal(""))
	})
})
