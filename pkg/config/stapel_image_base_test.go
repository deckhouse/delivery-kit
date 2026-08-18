package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("StapelImageBase HasOSPMPackages", func() {
	It("returns false when no packages are configured", func() {
		base := &StapelImageBase{}
		Expect(base.HasOSPMPackages()).To(BeFalse())
	})

	It("returns false when only non-os-pm packages are configured", func() {
		base := &StapelImageBase{
			Packages: []*PackagesDirective{
				{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"}},
			},
		}
		Expect(base.HasOSPMPackages()).To(BeFalse())
	})

	It("returns false when multiple non-os-pm packages are configured", func() {
		base := &StapelImageBase{
			Packages: []*PackagesDirective{
				{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"}},
				{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/native", Spec: "Cargo.toml", Lock: "Cargo.lock"}},
			},
		}
		Expect(base.HasOSPMPackages()).To(BeFalse())
	})

	It("returns true when os-pm packages are configured", func() {
		base := &StapelImageBase{
			Packages: []*PackagesDirective{
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
			},
		}
		Expect(base.HasOSPMPackages()).To(BeTrue())
	})
})
