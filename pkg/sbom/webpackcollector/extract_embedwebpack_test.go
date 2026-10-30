//go:build embedwebpack

package webpackcollector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// node runs one script against the extracted tree, with an environment of its own:
// nothing this machine happens to export decides what the collector does.
func node(t *testing.T, script string, env ...string) (string, error) {
	t.Helper()
	binary, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	command := exec.Command(binary, "-e", script)
	command.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
	output, err := command.CombinedOutput()

	return string(output), err
}

// extracted is the collector this binary carries, unpacked once per spec.
func extracted(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	digest, err := Extract(directory)
	require.NoError(t, err)
	assert.Len(t, digest, 64)
	assert.FileExists(t, filepath.Join(directory, "activate.cjs"))

	return directory
}

// Every file of the packed tree resolves what it requires. A runtime file the closure
// missed - of the collector itself or of its production dependencies - is a tree that
// activates and then fails in the middle of somebody's build.
func TestExtractedTreeResolvesEveryRequire(t *testing.T) {
	directory := extracted(t)
	output, err := node(t, `
		const fs = require('node:fs');
		const path = require('node:path');
		const root = process.env.COLLECTOR;
		const files = fs.readdirSync(root).filter((name) => name.endsWith('.cjs'));
		if (files.length < 2) throw new Error('the collector is not in ' + root);
		for (const file of files) require(path.join(root, file));
		console.log('resolved ' + files.length);
	`, "COLLECTOR="+directory)
	require.NoError(t, err, output)
	assert.Contains(t, output, "resolved 33")
}

// Without the configuration variable the activation loads nothing at all: an ordinary
// build of the same image is the build it was before.
func TestExtractedActivationLoadsNothingUnconfigured(t *testing.T) {
	directory := extracted(t)
	output, err := node(t, `
		const activate = process.env.COLLECTOR + '/activate.cjs';
		require(activate);
		const loaded = Object.keys(require.cache).filter((file) => file !== require.resolve(activate));
		if (loaded.length > 0) throw new Error('loaded ' + loaded.join(', '));
		console.log('loaded nothing');
	`, "COLLECTOR="+directory)
	require.NoError(t, err, output)
	assert.Contains(t, output, "loaded nothing")
}

// Configured with a file that is not there, it refuses instead of compiling an
// unobserved build and writing no proof about it.
func TestExtractedActivationRefusesAMissingConfiguration(t *testing.T) {
	directory := extracted(t)
	output, err := node(t, `require(process.env.COLLECTOR + '/activate.cjs');`,
		"COLLECTOR="+directory,
		"DK_SBOM_WEBPACK_CONFIG="+filepath.Join(directory, "no-such.config.js"),
		"DK_SBOM_WEBPACK_PROOF=/private-build-metadata/ui.json",
		"DK_SBOM_YARN_CACHE="+directory,
		"SBOM_BUILD_CONTEXT=/.werf/sbom-build-context/context.json",
	)
	require.Error(t, err)
	assert.True(t, strings.Contains(output, "no-such.config.js"), output)
}
