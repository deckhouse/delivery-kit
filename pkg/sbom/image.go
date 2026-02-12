package sbom

import (
	"fmt"

	"github.com/distribution/reference"
)

const (
	werfScratchRegistry  = "registry.werf.io"
	werfScratchImageRepo = "werf/scratch"
)

func IsScratchRef(imageRef string) bool {
	if imageRef == "" {
		return false
	}

	ref, err := reference.ParseAnyReference(imageRef)
	if err != nil {
		return false
	}

	named, ok := ref.(reference.Named)
	if !ok {
		return false
	}

	domain := reference.Domain(named)
	path := reference.Path(named)

	return domain == werfScratchRegistry && path == werfScratchImageRepo
}

func ImageName(name string) string {
	return fmt.Sprintf("%s-sbom", name)
}

func BaseImageSbomName(repo, tag string) string {
	return ImageName(fmt.Sprintf("%s:%s", repo, tag))
}
