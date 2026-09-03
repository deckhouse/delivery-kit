package build

import (
	"github.com/werf/werf/v2/pkg/build/image"
	imagePkg "github.com/werf/werf/v2/pkg/image"
)

func contentStageDesc(img *image.Image) *imagePkg.StageDesc {
	if img == nil {
		return nil
	}

	lastStage := img.GetLastNonEmptyStage()
	if lastStage == nil || lastStage.GetStageImage() == nil || lastStage.GetStageImage().Image == nil {
		return img.GetContentTagDesc()
	}

	return lastStage.GetStageImage().Image.GetStageDesc()
}

func finalStageDescForImage(phase *BuildPhase, name string, images []*image.Image) *imagePkg.StageDesc {
	if len(images) == 1 {
		if images[0] == nil {
			return nil
		}
		return images[0].GetContentTagDesc()
	}

	if phase == nil || phase.Conveyor == nil || phase.Conveyor.imagesTree == nil {
		return nil
	}

	if multiImg := phase.Conveyor.imagesTree.GetMultiplatformImage(name); multiImg != nil {
		return multiImg.GetFinalStageDesc()
	}

	return nil
}

func vexTargetPlatform(images []*image.Image) string {
	if len(images) != 1 || images[0] == nil {
		return ""
	}

	return images[0].TargetPlatform
}

func finalStageDescForPlatform(phase *BuildPhase, name string, images []*image.Image, targetPlatform string) *imagePkg.StageDesc {
	finalStageDesc := finalStageDescForImage(phase, name, images)
	if finalStageDesc == nil || finalStageDesc.Info == nil || !finalStageDesc.Info.IsIndex {
		return finalStageDesc
	}

	for _, manifest := range finalStageDesc.Info.Index {
		if manifest != nil && manifest.Platform == targetPlatform {
			return &imagePkg.StageDesc{Info: manifest}
		}
	}

	for index, img := range images {
		if img == nil || img.TargetPlatform != targetPlatform || index >= len(finalStageDesc.Info.Index) {
			continue
		}

		return &imagePkg.StageDesc{Info: finalStageDesc.Info.Index[index]}
	}

	return nil
}
