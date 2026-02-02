package sbom

import (
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func ExtractFromImageStream(opener tarball.Opener) (io.ReadCloser, error) {
	if img, err := tarball.Image(opener, nil); err != nil {
		return nil, fmt.Errorf("unable to open image: %w", err)
	} else {
		return mutate.Extract(img), nil
	}
}
