//go:build !embedwebpack

package webpackcollector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A werf built without the collector says so, rather than building a stage whose
// evidence nothing would ever write.
func TestExtractWithoutAnEmbeddedCollector(t *testing.T) {
	directory := t.TempDir()
	_, err := Extract(directory)
	require.ErrorContains(t, err, "no-data: this werf carries no SBOM webpack collector")

	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
