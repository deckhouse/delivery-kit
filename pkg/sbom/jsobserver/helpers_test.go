package jsobserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

type observerFixture struct {
	Dir        string
	AssetsDir  string
	LogPath    string
	ProjectDir string
}

func newObserverFixture(ctx context.Context) observerFixture {
	if _, err := exec.LookPath("node"); err != nil {
		ginkgo.Skip("node is not installed")
	}
	dir, err := filepath.EvalSymlinks(ginkgo.GinkgoT().TempDir())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	fixture := observerFixture{
		Dir:        dir,
		AssetsDir:  filepath.Join(dir, "assets"),
		LogPath:    filepath.Join(dir, "log", "events.jsonl"),
		ProjectDir: filepath.Join(dir, "project"),
	}
	gomega.Expect(os.CopyFS(fixture.ProjectDir, os.DirFS("testdata/project"))).To(gomega.Succeed())
	gomega.Expect(os.CopyFS(filepath.Join(dir, "linked-dep"), os.DirFS("testdata/linked-dep"))).To(gomega.Succeed())
	// The project has no version of its own, so its files resolve to this enclosing package.
	gomega.Expect(os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"enclosing-root","version":"0.0.1"}`), 0o644)).To(gomega.Succeed())
	gomega.Expect(os.Symlink("../../linked-dep", filepath.Join(fixture.ProjectDir, "node_modules", "linked-dep"))).To(gomega.Succeed())
	gomega.Expect(os.Symlink("../packages/inner-ws", filepath.Join(fixture.ProjectDir, "node_modules", "inner-ws"))).To(gomega.Succeed())
	gomega.Expect(os.Mkdir(fixture.AssetsDir, 0o755)).To(gomega.Succeed())
	gomega.Expect(writeAssets(ctx, fixture.AssetsDir, fixture.LogPath)).To(gomega.Succeed())
	return fixture
}

func (fixture observerFixture) bootstrapOption() string {
	return "--require " + filepath.Join(fixture.AssetsDir, BootstrapFileName)
}

func runNode(ctx context.Context, dir, nodeOptions, script string) (string, string) {
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Dir = dir
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "NODE_OPTIONS=") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	if nodeOptions != "" {
		cmd.Env = append(cmd.Env, "NODE_OPTIONS="+nodeOptions)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	gomega.Expect(cmd.Run()).To(gomega.Succeed(), "node %s: %s", script, stderr.String())
	// Module IDs in bundler results are absolute paths of the fixture copy.
	return strings.ReplaceAll(stdout.String(), dir, "<project>"), stderr.String()
}

func readEvents(logPath string) []Event {
	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var events []Event
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		var event Event
		gomega.Expect(decoder.Decode(&event)).To(gomega.Succeed(), line)
		gomega.Expect(event.Version).To(gomega.Equal(ProtocolVersion))
		events = append(events, event)
	}
	return events
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func treeContents(dir string) map[string]string {
	contents := map[string]string{}
	gomega.Expect(filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		contents[rel] = string(data)
		return nil
	})).To(gomega.Succeed())
	return contents
}

func outputsByPath(events []Event) map[string]Output {
	outputs := map[string]Output{}
	for _, event := range events {
		for _, output := range event.Outputs {
			outputs[output.Path] = output
		}
	}
	return outputs
}

func sortedKeys(outputs map[string]Output) []string {
	var keys []string
	for key := range outputs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
