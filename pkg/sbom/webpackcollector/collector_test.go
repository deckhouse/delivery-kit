package webpackcollector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// packed is an archive of the given entries, in the shape the generator writes.
func packed(t *testing.T, entries map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	archive := tar.NewWriter(&buf)
	for name, body := range entries {
		require.NoError(t, archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}))
		_, err := archive.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, archive.Close())

	sum := sha256.Sum256(buf.Bytes())

	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func compressed(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write(body)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	return buf.Bytes()
}

func TestUnpackWritesTheTree(t *testing.T) {
	body, _ := packed(t, map[string]string{"activate.cjs": "// collector\n", "node_modules/tar/index.js": "module.exports = {};\n"})
	directory := t.TempDir()
	require.NoError(t, unpack(body, directory))

	collector, err := os.ReadFile(filepath.Join(directory, "activate.cjs"))
	require.NoError(t, err)
	assert.Equal(t, "// collector\n", string(collector))
	dependency, err := os.ReadFile(filepath.Join(directory, "node_modules", "tar", "index.js"))
	require.NoError(t, err)
	assert.Equal(t, "module.exports = {};\n", string(dependency))

	info, err := os.Stat(filepath.Join(directory, "activate.cjs"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "the build reads the tree as a user werf did not unpack it as")
}

// The archive is this binary's own, so a name reaching out of the tree is a corrupted
// embed rather than an attack - and is still not written anywhere.
func TestUnpackRefusesNamesOutsideTheTree(t *testing.T) {
	for _, name := range []string{"../escape.cjs", "/etc/escape.cjs", "./activate.cjs", "node_modules/../../escape.cjs"} {
		t.Run(name, func(t *testing.T) {
			body, _ := packed(t, map[string]string{name: "escaped"})
			directory := t.TempDir()
			require.ErrorContains(t, unpack(body, directory), "not a path inside the collector")

			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

func TestUnpackRefusesAnythingButOrdinaryFiles(t *testing.T) {
	var buf bytes.Buffer
	archive := tar.NewWriter(&buf)
	require.NoError(t, archive.WriteHeader(&tar.Header{Name: "node_modules/tar", Typeflag: tar.TypeSymlink, Linkname: "/etc", Mode: 0o777}))
	require.NoError(t, archive.Close())

	require.ErrorContains(t, unpack(buf.Bytes(), t.TempDir()), "not an ordinary file")
}

func TestDecompressAndVerify(t *testing.T) {
	body, digest := packed(t, map[string]string{"activate.cjs": "// collector\n"})

	verified, err := decompressAndVerify(compressed(t, body), digest)
	require.NoError(t, err)
	assert.Equal(t, body, verified)

	_, err = decompressAndVerify(compressed(t, append(body, 0)), digest)
	require.ErrorContains(t, err, "integrity check failed")

	_, err = decompressAndVerify([]byte("not gzip"), digest)
	require.ErrorContains(t, err, "gzip")
}
