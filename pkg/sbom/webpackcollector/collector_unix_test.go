//go:build unix

package webpackcollector

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tree is mounted into a build and read by a user werf did not unpack it as, so its
// modes are the ones it was written with rather than the ones a umask left behind.
func TestUnpackIgnoresTheUmask(t *testing.T) {
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	body, _ := packed(t, map[string]string{"activate.cjs": "// collector\n", "node_modules/tar/index.js": "module.exports = {};\n"})
	directory := t.TempDir()
	require.NoError(t, unpack(body, directory))

	for file, expected := range map[string]os.FileMode{
		"activate.cjs":              0o644,
		"node_modules":              0o755,
		"node_modules/tar":          0o755,
		"node_modules/tar/index.js": 0o644,
	} {
		info, err := os.Stat(filepath.Join(directory, filepath.FromSlash(file)))
		require.NoError(t, err)
		assert.Equal(t, expected, info.Mode().Perm(), file)
	}
}
