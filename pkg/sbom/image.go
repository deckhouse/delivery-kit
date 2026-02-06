package sbom

import (
	"fmt"
)

const ScratchImageName = "scratch"

func ImageName(name string) string {
	return fmt.Sprintf("%s-sbom", name)
}

func BaseImageSbomName(repo, digest string, creationTs int64) string {
	return fmt.Sprintf("%s:%s-%d-sbom", repo, digest, creationTs)
}
