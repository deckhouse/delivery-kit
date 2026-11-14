package nativegate

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

type GitSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Add        string `json:"add"`
	To         string `json:"to"`
}

func normalizedGitSources(sources []GitSource) []GitSource {
	result := slices.Clone(sources)
	slices.SortFunc(result, func(a, b GitSource) int {
		return cmp.Or(cmp.Compare(a.Repository, b.Repository), cmp.Compare(a.Commit, b.Commit), cmp.Compare(a.Add, b.Add), cmp.Compare(a.To, b.To))
	})
	return slices.Compact(result)
}

func GitSourcesChecksum(ctx context.Context, sources []GitSource) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(sources) == 0 {
		return "", nil
	}
	for _, source := range sources {
		if source.Repository == "" || source.Commit == "" || source.Add == "" || source.To == "" {
			return "", fmt.Errorf("incomplete git mapping identity")
		}
	}
	data, err := json.Marshal(normalizedGitSources(sources))
	if err != nil {
		return "", fmt.Errorf("encode git mapping identity: %w", err)
	}
	return digest(data), nil
}

func declaredSubject(ctx context.Context, name string, sources []GitSource) (shared.BuildComponent, cdx.Component, error) {
	subject := shared.BuildComponent{ID: "app", Name: name, Version: "unspecified", Source: shared.BuildSource{Kind: "declared", Locator: "dk:image:" + name}}
	checksum, err := GitSourcesChecksum(ctx, sources)
	if err != nil {
		return subject, cdx.Component{}, err
	}
	if checksum != "" {
		subject.Source.Locator += "@" + checksum
	}
	component, err := embeddedComponent(subject)
	if err != nil {
		return subject, cdx.Component{}, err
	}
	ancestors := []cdx.Component{}
	for _, source := range normalizedGitSources(sources) {
		ancestor := cdx.Component{
			Type: cdx.ComponentTypeApplication, Name: "git-source", Version: source.Commit,
			PackageURL: packageurl.NewPackageURL(packageurl.TypeGeneric, "", "git-source", source.Commit, packageurl.Qualifiers{{Key: "source_kind", Value: "git"}, {Key: "source_locator", Value: source.Repository}}, "").ToString(),
			Properties: &[]cdx.Property{{Name: "dk:git-add", Value: source.Add}, {Name: "dk:git-to", Value: source.To}},
		}
		if source.Repository != "." {
			ancestor.ExternalReferences = &[]cdx.ExternalReference{{Type: cdx.ERTypeVCS, URL: source.Repository}}
		}
		ancestors = append(ancestors, ancestor)
	}
	if len(ancestors) > 0 {
		component.Pedigree = &cdx.Pedigree{Ancestors: &ancestors}
		*component.Properties = append(*component.Properties, cdx.Property{Name: "dk:git-mappings-checksum", Value: checksum})
	}
	return subject, component, nil
}
