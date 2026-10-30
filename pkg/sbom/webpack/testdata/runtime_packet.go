// Command runtime_packet repacks one selected esbuild source file as a real
// prepared source package, so the webpack runtime fixture can bind it to a pm
// distribution instead of the Go module it was resolved from.
//
// It is a test fixture builder, not a product entry point:
//
//	go run ./pkg/sbom/webpack/testdata/runtime_packet.go -- <runtime.go> <empty output directory>
//
// The separator is what keeps go run from taking the selected .go file for one
// more file of this program.
//
// The image it builds is never pushed; its repository is an unresolvable name,
// because nothing here claims the package was published. What the fixture gets
// is what a consumer gets: an OCI layout, the packet JSON of that image's own
// labels and digest, and an original root read back out of the packed layer.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

const (
	packetRepository  = "example.invalid/fixtures/esbuild-runtime-source"
	packetName        = "esbuild-runtime-source"
	packetVersion     = "0.25.0"
	packetPlatform    = "linux/amd64"
	packetSourcePath  = "internal/runtime/runtime.go"
	packetLayoutDir   = "layout"
	packetOriginalDir = "original"
)

type packetFixture struct {
	Component    shared.BuildComponent `json:"component"`
	OriginalRoot string                `json:"originalRoot"`
	SourcePath   string                `json:"sourcePath"`
	RelativePath string                `json:"relativePath"`
	Layout       string                `json:"layout"`
	Packet       json.RawMessage       `json:"packet"`
	Registry     string                `json:"registry"`
	Platform     string                `json:"platform"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "runtime packet fixture: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) != 2 {
		return fmt.Errorf("want a source file and an empty output directory, got %d arguments", len(args))
	}
	source, out := args[0], args[1]
	body, err := readSelectedFile(source)
	if err != nil {
		return err
	}
	if err := requireEmptyDirectory(out); err != nil {
		return err
	}

	image, err := packetImage(body)
	if err != nil {
		return err
	}
	config, err := image.ConfigFile()
	if err != nil {
		return err
	}
	pin, err := image.Digest()
	if err != nil {
		return err
	}
	packet, err := os_pm.PacketJSONFromImageLabels(ctx, config.Config.Labels, pin.String())
	if err != nil {
		return err
	}

	layoutPath, originalRoot := filepath.Join(out, packetLayoutDir), filepath.Join(out, packetOriginalDir)
	if err := writeFixture(image, body, layoutPath, originalRoot); err != nil {
		return cleanupFixture(err, layoutPath, originalRoot)
	}

	return json.NewEncoder(os.Stdout).Encode(packetFixture{
		Component: shared.BuildComponent{
			ID: "pm:" + packetName, Name: packetName, Version: packetVersion,
			Source: shared.BuildSource{Kind: "pm", Locator: packetRepository, Checksum: pin.String()},
		},
		OriginalRoot: originalRoot,
		SourcePath:   source,
		RelativePath: packetSourcePath,
		Layout:       layoutPath,
		Packet:       packet,
		Registry:     packetRepository,
		Platform:     packetPlatform,
	})
}

// readSelectedFile takes the one file this package is built out of. A symlink is
// refused rather than followed: the bytes packed have to be the bytes of the path
// the caller named.
func readSelectedFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}

	return os.ReadFile(path)
}

func requireEmptyDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s: output directory is not empty", path)
	}

	return nil
}

// packetImage is an ordinary image of one layer holding one regular file, with the
// platform and the pkg.* labels a prepared source package of the packages build
// carries. Nothing in the header depends on the host, so the same bytes in produce
// the same digest out.
func packetImage(body []byte) (v1.Image, error) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	header := &tar.Header{Typeflag: tar.TypeReg, Name: packetSourcePath, Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(header); err != nil {
		return nil, err
	}
	if _, err := tw.Write(body); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	layer, err := tarball.LayerFromReader(&archive)
	if err != nil {
		return nil, err
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return nil, err
	}
	config, err := image.ConfigFile()
	if err != nil {
		return nil, err
	}
	config.OS, config.Architecture = "linux", "amd64"
	config.Config.Labels = map[string]string{
		"pkg.name":    packetName,
		"pkg.version": packetVersion,
		"pkg.type":    "source",
		"pkg.arch":    packetPlatform,
		"pkg.default": "false",
	}

	return mutate.ConfigFile(image, config)
}

// writeFixture saves the layout and then mirrors the original root out of the
// packed image, so the tree the fixture serves comes from the verified original
// view rather than from a second copy of the input.
func writeFixture(image v1.Image, body []byte, layoutPath, originalRoot string) error {
	target, err := layout.Write(layoutPath, empty.Index)
	if err != nil {
		return err
	}
	if err := target.AppendImage(image); err != nil {
		return err
	}

	pin, err := image.Digest()
	if err != nil {
		return err
	}
	reopened, err := target.Image(pin)
	if err != nil {
		return err
	}
	packed, err := readOriginal(reopened)
	if err != nil {
		return err
	}
	if !bytes.Equal(packed, body) {
		return fmt.Errorf("%s: the packed original is not the selected source", packetSourcePath)
	}

	return writeOriginalRoot(originalRoot, packed)
}

func readOriginal(image v1.Image) ([]byte, error) {
	pkg, err := original.NewOriginalPackage(image)
	if err != nil {
		return nil, err
	}
	if !pkg.Complete() {
		return nil, fmt.Errorf("the packed original is an incomplete view")
	}
	entry, err := pkg.Lookup(packetSourcePath)
	if err != nil {
		return nil, err
	}

	reader, err := pkg.Open(packetSourcePath)
	if err != nil {
		return nil, err
	}
	// Open verifies against the indexed hash only once the body is read through EOF.
	body, readErr := io.ReadAll(reader)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, fmt.Errorf("%s: %w", packetSourcePath, err)
	}
	sum := sha256.Sum256(body)
	if digest := "sha256:" + hex.EncodeToString(sum[:]); digest != entry.SHA256 {
		return nil, fmt.Errorf("%s: the original served %s for %s", packetSourcePath, entry.SHA256, digest)
	}

	return body, nil
}

func writeOriginalRoot(root string, body []byte) error {
	path := filepath.Join(root, filepath.FromSlash(packetSourcePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}

	return file.Close()
}

func cleanupFixture(cause error, directories ...string) error {
	for _, directory := range directories {
		if err := os.RemoveAll(directory); err != nil {
			cause = errors.Join(cause, fmt.Errorf("remove %s: %w", directory, err))
		}
	}

	return cause
}
