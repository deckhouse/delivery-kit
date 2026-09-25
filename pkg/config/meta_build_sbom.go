package config

import (
	"github.com/werf/werf/v3/pkg/sbom"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

type MetaBuildSbom struct {
	Enable   bool
	Standard sbom.StandardType
	Gost     gost.Config
}
