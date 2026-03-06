package gomod

import (
	"fmt"
	"strings"
)

// ResolveVersionFromTags finds a semver tag matching the given commit.
// Falls back to pseudo-version v0.0.0-{shortCommit} if no tag matches.
func ResolveVersionFromTags(tags []string, commitForTag func(tag string) (string, error), commit string) (string, error) {
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "v") {
			continue
		}
		tagCommit, err := commitForTag(tag)
		if err != nil {
			return "", fmt.Errorf("resolve tag %q commit: %w", tag, err)
		}
		if tagCommit == commit {
			return tag, nil
		}
	}

	if len(commit) < 7 {
		return fmt.Sprintf("v0.0.0-%s", commit), nil
	}
	return fmt.Sprintf("v0.0.0-%s", commit[:7]), nil
}
