package contback

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/utils"
)

// PrepareBaseImageSbomStub creates a stub SBOM image and pushes it to the registry.
// This simulates the presence of a base image SBOM in the registry.
// baseImageReference is the reference to the base image (e.g., "alpine:3.18")
// registryRepo is the target registry repository (e.g., "localhost:5000/test-repo")
func (r *DockerBackend) PrepareBaseImageSbomStub(ctx context.Context, baseImageReference, registryRepo string) {
	sbomImageName := sbom.ImageName(baseImageReference)
	targetSbomImage := registryRepo + ":" + extractTag(sbomImageName)

	// Create a minimal SBOM stub image
	tmpDir, err := os.MkdirTemp("", "sbom-stub-*")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tmpDir)

	// Create stub SBOM content
	sbomDir := filepath.Join(tmpDir, "sbom")
	Expect(os.MkdirAll(sbomDir, 0o755)).To(Succeed())

	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	Expect(os.WriteFile(filepath.Join(sbomDir, "sbom.json"), []byte(sbomContent), 0o644)).To(Succeed())

	// Create Dockerfile
	dockerfile := `FROM scratch
COPY sbom /sbom
`
	Expect(os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfile), 0o644)).To(Succeed())

	// Build the stub image
	buildArgs := r.CommonCliArgs
	buildArgs = append(buildArgs, "build", "-t", targetSbomImage, tmpDir)
	utils.RunSucceedCommand(ctx, "/", "docker", buildArgs...)

	// Push to registry
	pushArgs := r.CommonCliArgs
	pushArgs = append(pushArgs, "push", targetSbomImage)
	utils.RunSucceedCommand(ctx, "/", "docker", pushArgs...)

	// Also tag with the original SBOM name for local availability
	tagArgs := r.CommonCliArgs
	tagArgs = append(tagArgs, "tag", targetSbomImage, sbomImageName)
	utils.RunSucceedCommand(ctx, "/", "docker", tagArgs...)
}

// PrepareBaseImageSbomStub creates a stub SBOM image and pushes it to the registry.
func (r *NativeBuildahBackend) PrepareBaseImageSbomStub(ctx context.Context, baseImageReference, registryRepo string) {
	sbomImageName := sbom.ImageName(baseImageReference)
	targetSbomImage := registryRepo + ":" + extractTag(sbomImageName)

	// Create a minimal SBOM stub image
	tmpDir, err := os.MkdirTemp("", "sbom-stub-*")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tmpDir)

	// Create stub SBOM content
	sbomDir := filepath.Join(tmpDir, "sbom")
	Expect(os.MkdirAll(sbomDir, 0o755)).To(Succeed())

	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	Expect(os.WriteFile(filepath.Join(sbomDir, "sbom.json"), []byte(sbomContent), 0o644)).To(Succeed())

	// Create Dockerfile
	dockerfile := `FROM scratch
COPY sbom /sbom
`
	Expect(os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfile), 0o644)).To(Succeed())

	// Build the stub image
	buildArgs := r.CommonCliArgs
	buildArgs = append(buildArgs, "build", "--isolation", r.Isolation.String(), "-t", targetSbomImage, tmpDir)
	utils.RunSucceedCommand(ctx, "/", "buildah", buildArgs...)

	// Push to registry
	pushArgs := r.CommonCliArgs
	pushArgs = append(pushArgs, "push", "--tls-verify=false", targetSbomImage)
	utils.RunSucceedCommand(ctx, "/", "buildah", pushArgs...)

	// Also tag with the original SBOM name for local availability
	tagArgs := r.CommonCliArgs
	tagArgs = append(tagArgs, "tag", targetSbomImage, sbomImageName)
	utils.RunSucceedCommand(ctx, "/", "buildah", tagArgs...)
}

func extractTag(imageRef string) string {
	for i := len(imageRef) - 1; i >= 0; i-- {
		if imageRef[i] == ':' {
			return imageRef[i+1:]
		}
		if imageRef[i] == '/' {
			break
		}
	}
	return "latest"
}
