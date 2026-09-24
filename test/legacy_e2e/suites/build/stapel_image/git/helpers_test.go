package git_test

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/docker/api/types/filters"
	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
)

type imageListSnapshot struct {
	Images   []imageListIdentity
	StageIDs []string
}

type imageListIdentity struct {
	ID      string
	Tags    []string
	Digests []string
}

func comparePurgeImageLists(ctx context.Context, projectName string) {
	checkPurgeImageFiltering()
	apiClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	Expect(err).NotTo(HaveOccurred())
	defer func() { Expect(apiClient.Close()).To(Succeed()) }()
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	_, err = apiClient.Ping(probeCtx)
	Expect(err).NotTo(HaveOccurred())

	label := fmt.Sprintf("%s=%s", image.WerfLabel, projectName)
	variants := []struct {
		name    string
		filters filters.Args
	}{
		{"reference+label", filters.NewArgs(filters.Arg("reference", projectName), filters.Arg("label", label))},
		{"reference", filters.NewArgs(filters.Arg("reference", projectName))},
		{"label", filters.NewArgs(filters.Arg("label", label))},
	}
	var baseline imageListSnapshot
	for round := range 3 {
		snapshots := make([]imageListSnapshot, len(variants))
		for position := range variants {
			variantIndex := (round + position) % len(variants)
			variant := variants[variantIndex]
			requestCtx, requestCancel := context.WithTimeout(probeCtx, 90*time.Second)
			started := time.Now()
			images, listErr := apiClient.ImageList(requestCtx, dockerimage.ListOptions{Filters: variant.filters})
			requestDuration := time.Since(started)
			requestCancel()
			filterStarted := time.Now()
			selected := images
			if variantIndex != 0 {
				selected = selectPurgeImages(images, projectName, variantIndex == 2)
			}
			snapshot, snapshotErr := snapshotPurgeImages(selected)
			filterDuration := time.Since(filterStarted)
			record := struct {
				Project       string
				Round         int
				Position      int
				Variant       string
				StartedAt     time.Time
				RequestTime   string
				ClientTime    string
				RawImages     []dockerimage.Summary
				Selected      imageListSnapshot
				RequestError  string
				SnapshotError string
			}{projectName, round + 1, position + 1, variant.name, started.UTC(), requestDuration.String(), filterDuration.String(), images, snapshot, fmt.Sprint(listErr), fmt.Sprint(snapshotErr)}
			encoded, marshalErr := json.Marshal(record)
			Expect(marshalErr).NotTo(HaveOccurred())
			_, writeErr := fmt.Fprintf(GinkgoWriter, "PURGE_IMAGE_LIST %s\n", encoded)
			Expect(writeErr).NotTo(HaveOccurred())
			Expect(listErr).NotTo(HaveOccurred())
			Expect(snapshotErr).NotTo(HaveOccurred())
			snapshots[variantIndex] = snapshot
		}
		Expect(snapshots[0].StageIDs).NotTo(BeEmpty())
		if round == 0 {
			baseline = snapshots[0]
		}
		Expect(snapshots[0]).To(Equal(baseline), "project images changed between measurement rounds")
		for variantIndex := 1; variantIndex < len(variants); variantIndex++ {
			Expect(snapshots[variantIndex]).To(Equal(snapshots[0]), "round %d, variant %s", round+1, variants[variantIndex].name)
		}
	}
}

func selectPurgeImages(images []dockerimage.Summary, projectName string, filterReference bool) []dockerimage.Summary {
	var selected []dockerimage.Summary
	for _, summary := range images {
		if summary.Labels[image.WerfLabel] != projectName {
			continue
		}
		if filterReference {
			summary.RepoTags = matchingPurgeReferences(summary.RepoTags, projectName)
			summary.RepoDigests = matchingPurgeReferences(summary.RepoDigests, projectName)
			if len(summary.RepoTags) == 0 && len(summary.RepoDigests) == 0 {
				continue
			}
		}
		selected = append(selected, summary)
	}
	return selected
}

func matchingPurgeReferences(references []string, projectName string) []string {
	var matched []string
	for _, value := range references {
		parsed, err := reference.ParseAnyReference(value)
		Expect(err).NotTo(HaveOccurred())
		matches, err := reference.FamiliarMatch(projectName, parsed)
		Expect(err).NotTo(HaveOccurred())
		if matches {
			matched = append(matched, value)
		}
	}
	return matched
}

func snapshotPurgeImages(images []dockerimage.Summary) (imageListSnapshot, error) {
	snapshot := imageListSnapshot{Images: []imageListIdentity{}, StageIDs: []string{}}
	var summaries image.ImagesList
	for _, summary := range images {
		tags := slices.Clone(summary.RepoTags)
		slices.Sort(tags)
		digests := slices.Clone(summary.RepoDigests)
		slices.Sort(digests)
		snapshot.Images = append(snapshot.Images, imageListIdentity{ID: summary.ID, Tags: tags, Digests: digests})
		summaries = append(summaries, image.Summary{ID: summary.ID, RepoTags: tags})
	}
	slices.SortFunc(snapshot.Images, func(left, right imageListIdentity) int {
		return cmp.Compare(left.ID, right.ID)
	})
	stageIDs, err := summaries.ConvertToStages()
	if err != nil {
		return snapshot, fmt.Errorf("convert image list to stages: %w", err)
	}
	for _, stageID := range stageIDs {
		snapshot.StageIDs = append(snapshot.StageIDs, stageID.String())
	}
	slices.Sort(snapshot.StageIDs)
	return snapshot, nil
}

func checkPurgeImageFiltering() {
	projectName := "image-list-probe"
	stageTag := fmt.Sprintf("%056d-1700000000000", 1)
	otherStageTag := fmt.Sprintf("%056d-1700000000000", 2)
	images := []dockerimage.Summary{
		{ID: "selected", Labels: map[string]string{image.WerfLabel: projectName}, RepoTags: []string{
			"other-project:" + otherStageTag, projectName + ":" + stageTag, projectName + ":alias",
		}},
		{ID: "wrong-label", Labels: map[string]string{image.WerfLabel: "other-project"}, RepoTags: []string{projectName + ":" + otherStageTag}},
		{ID: "missing-label", RepoTags: []string{projectName + ":" + otherStageTag}},
		{ID: "wrong-repository", Labels: map[string]string{image.WerfLabel: projectName}, RepoTags: []string{projectName + "-other:" + otherStageTag}},
		{ID: "untagged", Labels: map[string]string{image.WerfLabel: projectName}},
		{ID: "digest-only", Labels: map[string]string{image.WerfLabel: projectName}, RepoDigests: []string{projectName + "@sha256:" + fmt.Sprintf("%064d", 1)}},
	}
	snapshot, err := snapshotPurgeImages(selectPurgeImages(images, projectName, true))
	Expect(err).NotTo(HaveOccurred())
	Expect(snapshot).To(Equal(imageListSnapshot{
		Images: []imageListIdentity{
			{ID: "digest-only", Digests: []string{projectName + "@sha256:" + fmt.Sprintf("%064d", 1)}},
			{ID: "selected", Tags: []string{projectName + ":" + stageTag, projectName + ":alias"}},
		},
		StageIDs: []string{stageTag},
	}))
	Expect(images[0].RepoTags).To(Equal([]string{"other-project:" + otherStageTag, projectName + ":" + stageTag, projectName + ":alias"}))
	Expect(selectPurgeImages(images[:3], projectName, false)).To(Equal(images[:1]))
}
