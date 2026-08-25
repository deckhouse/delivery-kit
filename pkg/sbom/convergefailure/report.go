package convergefailure

import (
	"fmt"
	"strings"
)

// AggregatedError renders every recorded failure as one hierarchical error:
// direct failures carry their component lines, skipped images carry the image
// that caused them. Returns nil when nothing failed.
func (t *Tracker) AggregatedError(totalImages int) error {
	var errorCount int
	var sb strings.Builder
	t.failures.Range(func(key, value interface{}) bool {
		errorCount++
		imageName := key.(string)
		record := value.(Record)
		sb.WriteString(fmt.Sprintf("\n  - image: %s:\n", imageName))
		if record.RootImage != imageName {
			sb.WriteString(fmt.Sprintf("    - skipped: SBOM for image %q was not generated: %s\n", record.RootImage, record.RootCause))
			return true
		}
		for _, line := range strings.Split(record.Details, "\n") {
			if line != "" {
				sb.WriteString(line + "\n")
			}
		}
		return true
	})

	if errorCount > 0 {
		return fmt.Errorf("resolve external references: %d of %d images failed:%s", errorCount, totalImages, sb.String())
	}

	return nil
}
