package nativegate

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	ospm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

// A prepared source image is the one image allowed to take files out of a bootstrap source
// without answering for them one by one. That permission rests on what such an image is:
// it stands on no base, runs nothing and only collects files, so the image as a whole is
// what a pinned package consists of, and a build downstream reads those files out of that
// package rather than out of an image whose composition nobody states.
//
// Nothing of it may be compiled. A compiled artifact is the one thing a prepared source
// cannot be: its composition lives in the record of the build that produced it, and an
// image that collects it while claiming to be a source would put that composition beyond
// reach. The check is on the bytes, never on the name of the file - the same classifier
// the record reader selects containers by, so that a prepared source refuses exactly what
// the gate elsewhere would have to read a record from.
func compiledContent(body []byte) bool {
	if nativeCandidate(body) {
		return true
	}
	for _, magic := range []string{"!<arch>", "!<thin>", "\x00asm", "BC\xc0\xde", "\xde\xc0\x17\x0b"} {
		if bytes.HasPrefix(body, []byte(magic)) {
			return true
		}
	}

	return false
}

func checkPreparedSourceContent(fs *filesystem) error {
	for _, name := range slices.Sorted(maps.Keys(fs.index.Files)) {
		if compiledContent(fs.bodies[name]) {
			return fmt.Errorf("invalid: %s is compiled content, which a prepared source image does not ship: what it is made of lives in the record of the build that produced it", name)
		}
	}

	return nil
}

// addPreparedSourcePackage describes the files of a prepared source image as the package
// the image declares itself to be: the identity comes from its own pkg.* labels and from
// the digest the image has in the registry, so what this document names is what a build
// downstream pins when it resolves that image as a prepared source.
//
// The registry digest is passed in rather than read off the image at hand. That image was
// saved out of the daemon and re-assembled here, and re-compressing its layers yields a
// manifest digest of this process's own making; nothing but the registry's digest can be
// pinned.
//
// A file this image already answers for otherwise - one bound to an original it imported
// from - keeps that answer; the package covers the rest, which is every file whose only
// account is that it stands in this very image.
//
// A path another image published an obligation over is not covered: that obligation is
// that image's statement that the path is unaccounted for, and collecting the file is not
// what answers it. Such a file needs a binding of its own here, and without one the gate
// refuses it as it would in any other image.
func (c *Catalog) addPreparedSourcePackage(ctx context.Context, img v1.Image, registryDigest string, fs *filesystem, obliged map[string]bool) error {
	config, err := img.ConfigFile()
	if err != nil {
		return err
	}
	if registryDigest == "" {
		return fmt.Errorf("prepared source image: no-data: the digest the image has in the registry is unknown, and nothing else can be pinned")
	}
	packet, err := ospm.PacketJSONFromImageLabels(ctx, config.Config.Labels, registryDigest)
	if err != nil {
		return fmt.Errorf("prepared source image: %w", err)
	}
	packages, err := ospm.ParsePmInstalledJSON([]byte(`{"prepared-source":` + string(packet) + `}`))
	if err != nil {
		return fmt.Errorf("prepared source image: %w", err)
	}
	metadata := packages["prepared-source"]
	bom := ospm.ConvertToCycloneDX(ctx, packages, "")
	if bom == nil || bom.Components == nil || len(*bom.Components) != 1 {
		return fmt.Errorf("prepared source image: invalid: the declared package has no metadata")
	}

	id := "urn:dk:prepared-source:" + strings.TrimPrefix(registryDigest, "sha256:")
	component := (*bom.Components)[0]
	component.BOMRef = id
	component.PackageURL = packageurl.NewPackageURL("generic", "", metadata.Name, metadata.Version, nil, "").ToString()
	properties := []cdx.Property{{Name: cyclonedxutil.PropertyOriginalSource, Value: id}}
	if component.Properties != nil {
		for _, property := range *component.Properties {
			// The version of the factory that rendered the package index says nothing
			// about this image, and it is dropped off an original source for the same
			// reason here.
			if property.Name != "werf:pm:containerFactoryVersion" {
				properties = append(properties, property)
			}
		}
	}
	component.Properties = &properties

	covered := make(map[string]bool, len(c.Records))
	for _, record := range c.Records {
		covered[record.Path] = true
	}
	// An image importing from this one reads the document of this one and keeps what it
	// says occurs at a path the copy carries. Without those whereabouts the package would
	// be read as a statement about the donor alone and dropped, and the files would arrive
	// in the importing image with nothing naming what they are.
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(fs.index.Files))
	for _, name := range slices.Sorted(maps.Keys(fs.index.Files)) {
		if covered[name] || obliged[name] {
			continue
		}
		c.Records = append(c.Records, Record{
			Path: name, SHA256: fs.index.Files[name].Digest, Origin: "pm",
			Namespace: id, Owners: []string{id}, Components: []string{id},
		})
		occurrences = append(occurrences, cdx.EvidenceOccurrence{Location: name, AdditionalContext: fs.index.Files[name].Digest})
	}
	component.Evidence = &cdx.Evidence{Occurrences: &occurrences}
	c.Components[id] = component

	return nil
}
