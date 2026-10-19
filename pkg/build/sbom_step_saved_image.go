package build

import (
	"context"
	"io"
)

// Kept out of sbom_step.go: the mockgen directive there generates a mock for every
// interface in its source file, and a test double for this one is a stub, not a mock.
type imageSaver interface {
	SaveImageToStream(ctx context.Context, imageName string) (io.ReadCloser, error)
}
