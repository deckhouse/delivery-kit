package sbom

import (
	"fmt"
	"strings"
)

func IsScratchImage(imageRef string) bool {
	if imageRef == "scratch" {
		return true
	}

	ref := imageRef
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		if !strings.Contains(ref[idx:], "/") {
			ref = ref[:idx]
		}
	}

	return strings.HasSuffix(ref, "/scratch")
}

func ImageName(name string) string {
	return fmt.Sprintf("%s-sbom", name)
}

func BaseImageSbomName(repo, digest string, creationTs int64) string {
	return fmt.Sprintf("%s:%s-%d-sbom", repo, digest, creationTs)
}
