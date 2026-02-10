package sbom

import "testing"

func TestIsScratchImage(t *testing.T) {
	tests := []struct {
		name     string
		imageRef string
		want     bool
	}{
		{"bare scratch", "scratch", true},
		{"scratch with tag", "scratch:latest", true},
		{"scratch with custom tag", "scratch:v1", true},

		{"registry scratch", "registry.werf.io/werf/scratch", true},
		{"registry scratch with tag", "registry.werf.io/werf/scratch:latest", true},
		{"registry scratch with digest", "registry.werf.io/werf/scratch@sha256:abc123", true},
		{"registry scratch with tag and digest", "registry.werf.io/werf/scratch:v1@sha256:abc123", true},

		{"localhost scratch", "localhost:5000/scratch", true},
		{"localhost scratch with tag", "localhost:5000/scratch:latest", true},
		{"localhost scratch with digest", "localhost:5000/scratch@sha256:abc123", true},

		{"ubuntu", "ubuntu", false},
		{"ubuntu with tag", "ubuntu:22.04", false},
		{"registry image", "registry.werf.io/base/ubuntu:22.04", false},
		{"image with scratch in name", "my-scratch-image:latest", false},
		{"scratch prefix", "scratchpad:latest", false},
		{"scratch in path", "registry.werf.io/scratch-images/app:latest", false},

		{"empty string", "", false},
		{"only digest", "@sha256:abc123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsScratchImage(tt.imageRef)
			if got != tt.want {
				t.Errorf("IsScratchImage(%q) = %v, want %v", tt.imageRef, got, tt.want)
			}
		})
	}
}

func TestImageName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"myapp:v1", "myapp:v1-sbom"},
		{"registry.io/image:tag", "registry.io/image:tag-sbom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImageName(tt.name)
			if got != tt.want {
				t.Errorf("ImageName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestBaseImageSbomName(t *testing.T) {
	tests := []struct {
		repo string
		tag  string
		want string
	}{
		{"registry.io/image", "v1", "registry.io/image:v1-sbom"},
		{"localhost:5000/app", "latest", "localhost:5000/app:latest-sbom"},
	}

	for _, tt := range tests {
		t.Run(tt.repo+":"+tt.tag, func(t *testing.T) {
			got := BaseImageSbomName(tt.repo, tt.tag)
			if got != tt.want {
				t.Errorf("BaseImageSbomName(%q, %q) = %q, want %q", tt.repo, tt.tag, got, tt.want)
			}
		})
	}
}
