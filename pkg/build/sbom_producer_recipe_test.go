package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/stapel"
	"github.com/werf/werf/v3/test/pkg/externalrefmock"
)

const (
	producerRecipeBinaryEnv   = "DK_PRODUCER_CONTEXT_BINARY"
	producerRecipeRevisionEnv = "DK_PRODUCER_CONTEXT_REVISION"
	producerRecipeToolsEnv    = "DK_PRODUCER_TOOLS"
	producerRecipeLinkerEnv   = "DK_PRODUCER_LD"
	// producerRecipeEvidenceEnv names a task-owned directory, outside the repository, the
	// logs, build reports, hash manifest and produced record are copied to before the
	// fixture is removed. Without it they live only in the fixture's temporary directory.
	producerRecipeEvidenceEnv = "DK_PRODUCER_EVIDENCE"
)

// producerRecipeToolSHA256 pins the frozen M06 toolchain by content: these are the only
// compiler, assembler and helper this recipe executes.
var producerRecipeToolSHA256 = map[string]string{
	"gcc/xgcc":        "a565fa44710f2f1f1ecbe4ad5147629158ed3b4bb2124cf9740e8d75edb82d38",
	"gcc/cc1":         "4f154e2773e22b0a5d9c34ab6cdeb8f0c8a588452429b663c48186c31e56d655",
	"bin/as":          "4f8c618b36a3638317b22c528c532bac0803763ea3ee33374d750c1725674833",
	"bin/sbom-helper": "f46d86f0894e6be2ba959e1672776e4a5ff793f4e7fa313673f8cdb2ccd19054",
}

const producerRecipeLinkerSHA256 = "73eca7f2399dfea8a4aa55805b9b2e8c76c9d6d9810b4a42b6c8bc59727a547b"

const (
	producerRecipeToolsMount  = "/native"
	producerRecipeLinkerMount = "/linker"
	producerRecipeObjectDir   = "/build"
)

const (
	producerRecipePackageName    = "fixture-source"
	producerRecipePackageVersion = "1.0.0"
	producerRecipePackageType    = "source"
	producerRecipePlatform       = "linux/amd64"
)

var producerRecipeRevisionRegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)

// producerRecipeMain is the whole payload: a freestanding entry point that exits 0 through
// the raw Linux syscall, so the recipe needs no libc, no CRT and no headers.
const producerRecipeMain = `static void fixture_exit(long code)
{
	__asm__ volatile("syscall" : : "a"(60L), "D"(code) : "rcx", "r11", "memory");
}

void _start(void)
{
	fixture_exit(0);
	__builtin_unreachable();
}
`

// producerRecipeEnvironment holds the disposable fixture root the build gets. werf mounts
// a custom_dir read-write (stage.BaseStage addCustomMountVolumes), so what is mounted is
// never the frozen toolchain but a throwaway copy of it, together with a copy of the
// runtime closure its tools need; the frozen paths and the host libraries are only read.
type producerRecipeEnvironment struct {
	binary   string
	revision string
	tools    string
	linker   string
	// runtimeMounts maps a namespace directory (the interpreter's own absolute directory)
	// to the fixture directory copied for it.
	runtimeMounts map[string]string
	originals     producerRecipeOriginals
	// copies maps every file of the fixture root to the path it was copied from.
	copies map[string]string
}

type producerRecipeOriginals struct {
	tools  string
	linker string
}

// producerRecipeLibrarySearch are the directories a needed library is looked up in, the
// toolchain's own runtime first.
var producerRecipeLibrarySearch = []string{
	"lib", "lib64", "runtime-libs/usr/lib", "runtime-libs/usr/lib64",
}

var producerRecipeHostLibrarySearch = []string{
	"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64", "/usr/lib", "/lib",
}

// producerRecipeClosureLimit bounds the recursion over DT_NEEDED.
const producerRecipeClosureLimit = 256

func producerRecipeRequirements(ctx context.Context) producerRecipeEnvironment {
	ginkgo.GinkgoHelper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		ginkgo.Skip("the actual producer recipe runs only on linux/amd64")
	}

	env := producerRecipeEnvironment{
		binary:    os.Getenv(producerRecipeBinaryEnv),
		revision:  os.Getenv(producerRecipeRevisionEnv),
		originals: producerRecipeOriginals{tools: os.Getenv(producerRecipeToolsEnv), linker: os.Getenv(producerRecipeLinkerEnv)},
	}
	for variable, value := range map[string]string{
		producerRecipeBinaryEnv:   env.binary,
		producerRecipeRevisionEnv: env.revision,
		producerRecipeToolsEnv:    env.originals.tools,
		producerRecipeLinkerEnv:   env.originals.linker,
	} {
		if value == "" {
			ginkgo.Skip("requires " + variable)
		}
	}
	for variable, path := range map[string]string{
		producerRecipeBinaryEnv: env.binary,
		producerRecipeToolsEnv:  env.originals.tools,
		producerRecipeLinkerEnv: env.originals.linker,
	} {
		gomega.Expect(filepath.IsAbs(path)).To(gomega.BeTrue(), "%s must be an absolute path", variable)
	}
	gomega.Expect(producerRecipeRevisionRegexp.MatchString(env.revision)).To(gomega.BeTrue(),
		"%s must be a full 40-character commit", producerRecipeRevisionEnv)

	producerRecipeCheckCandidate(env)
	producerRecipeCheckDocker(ctx)
	producerRecipeFill(ctx, &env)
	producerRecipeCheckTools(env.tools, env.linker)
	producerRecipeCheckCopies(env)

	return env
}

// producerRecipeFill builds the fixture root: the toolchain, the linker's directory and
// every shared object the pinned tools load, each copied with its symlinks dereferenced.
func producerRecipeFill(ctx context.Context, env *producerRecipeEnvironment) {
	ginkgo.GinkgoHelper()
	root := producerRecipeTempDir()
	env.tools = filepath.Join(root, "tools")
	linkerDir := filepath.Join(root, "linker")
	env.copies = map[string]string{}
	producerRecipeCopyTree(ctx, env.originals.tools, env.tools, env.copies)
	producerRecipeCopyTree(ctx, filepath.Dir(env.originals.linker), linkerDir, env.copies)
	env.linker = filepath.Join(linkerDir, filepath.Base(env.originals.linker))

	pinned := []string{env.originals.linker}
	for _, relative := range slices.Sorted(maps.Keys(producerRecipeToolSHA256)) {
		pinned = append(pinned, filepath.Join(env.originals.tools, relative))
	}
	interpreters, libraries := producerRecipeClosure(pinned, producerRecipeSearchDirs(env.originals.tools))

	env.runtimeMounts = map[string]string{}
	for index, mountpoint := range slices.Sorted(maps.Keys(interpreters)) {
		directory := filepath.Join(root, fmt.Sprintf("runtime%d", index))
		gomega.Expect(os.MkdirAll(directory, 0o755)).To(gomega.Succeed())
		producerRecipeCopyFile(interpreters[mountpoint], filepath.Join(directory, filepath.Base(mountpoint)), env.copies)
		for _, soname := range slices.Sorted(maps.Keys(libraries)) {
			producerRecipeCopyFile(libraries[soname], filepath.Join(directory, soname), env.copies)
		}
		env.runtimeMounts[filepath.Dir(mountpoint)] = directory
	}
}

func producerRecipeSearchDirs(tools string) []string {
	dirs := make([]string, 0, len(producerRecipeLibrarySearch)+len(producerRecipeHostLibrarySearch))
	for _, relative := range producerRecipeLibrarySearch {
		dirs = append(dirs, filepath.Join(tools, relative))
	}

	return append(dirs, producerRecipeHostLibrarySearch...)
}

// producerRecipeClosure walks DT_NEEDED from the pinned tools and returns the program
// interpreter of each tool by the namespace path it is loaded from, and every shared
// object the closure reaches by the name it is asked for.
func producerRecipeClosure(roots, search []string) (map[string]string, map[string]string) {
	ginkgo.GinkgoHelper()
	interpreters := map[string]string{}
	libraries := map[string]string{}
	queue := slices.Clone(roots)
	for len(queue) > 0 {
		gomega.Expect(len(libraries)).To(gomega.BeNumerically("<", producerRecipeClosureLimit), "runtime closure is unbounded")
		path := queue[0]
		queue = queue[1:]
		file, err := elf.Open(path)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "open %s", path)
		if interpreter := producerRecipeInterpreter(file); interpreter != "" {
			interpreters[interpreter] = producerRecipeInterpreterFile(interpreter, search)
		}
		needed, err := file.ImportedLibraries()
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "read DT_NEEDED of %s", path)
		gomega.Expect(file.Close()).To(gomega.Succeed())
		for _, soname := range needed {
			if _, known := libraries[soname]; known {
				continue
			}
			found := producerRecipeFindLibrary(soname, search)
			libraries[soname] = found
			queue = append(queue, found)
		}
	}

	return interpreters, libraries
}

func producerRecipeInterpreter(file *elf.File) string {
	ginkgo.GinkgoHelper()
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		body, err := io.ReadAll(prog.Open())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		return strings.TrimRight(string(body), "\x00")
	}

	return ""
}

// producerRecipeInterpreterFile prefers the loader that belongs to the toolchain's own
// runtime over the host one, so a copied libc and the loader cannot disagree.
func producerRecipeInterpreterFile(interpreter string, search []string) string {
	ginkgo.GinkgoHelper()
	for _, directory := range search {
		candidate := filepath.Join(directory, filepath.Base(interpreter))
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return producerRecipeResolve(candidate)
		}
	}

	return producerRecipeResolve(interpreter)
}

func producerRecipeFindLibrary(soname string, search []string) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(soname).NotTo(gomega.ContainSubstring("/"), "DT_NEEDED must be a bare name")
	for _, directory := range search {
		candidate := filepath.Join(directory, soname)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return producerRecipeResolve(candidate)
		}
	}
	ginkgo.Fail("no " + soname + " in " + strings.Join(search, ", "))

	return ""
}

func producerRecipeResolve(path string) string {
	ginkgo.GinkgoHelper()
	resolved, err := filepath.EvalSymlinks(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "resolve %s", path)
	info, err := os.Stat(resolved)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(info.Mode().IsRegular()).To(gomega.BeTrue(), "%s is not a regular file", resolved)

	return resolved
}

// producerRecipeCheckCandidate proves which sources the candidate was built from before
// anything executes it.
func producerRecipeCheckCandidate(env producerRecipeEnvironment) {
	ginkgo.GinkgoHelper()
	info, err := buildinfo.ReadFile(env.binary)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs.revision", env.revision))
	gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs.modified", "false"))
	gomega.Expect(settings).To(gomega.HaveKeyWithValue("CGO_ENABLED", "1"))
}

// producerRecipeCopyTree copies a whole directory with every symlink dereferenced, so the
// fixture root holds no link that could reach back into the frozen paths, and records
// where each copied file came from.
func producerRecipeCopyTree(ctx context.Context, from, to string, copies map[string]string) {
	ginkgo.GinkgoHelper()
	limited, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	gomega.Expect(os.MkdirAll(to, 0o755)).To(gomega.Succeed())
	command := exec.CommandContext(limited, "cp", "-aL", from+"/.", to+"/")
	command.Env = producerRecipeBaseEnv()
	output, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "copy %s: %s", from, output)

	// A copy of a read-only source is read-only too, which this spec's own cleanup would
	// trip over; the bytes are untouched.
	writable := exec.CommandContext(limited, "chmod", "-R", "u+w", to)
	writable.Env = producerRecipeBaseEnv()
	output, err = writable.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "chmod %s: %s", to, output)

	gomega.Expect(filepath.WalkDir(to, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("copied %s is not a regular file", path)
		}
		relative, err := filepath.Rel(to, path)
		if err != nil {
			return err
		}
		copies[path] = filepath.Join(from, relative)

		return nil
	})).To(gomega.Succeed())
}

func producerRecipeCopyFile(from, to string, copies map[string]string) {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(from)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(os.WriteFile(to, body, 0o755)).To(gomega.Succeed())
	copies[to] = from
}

func producerRecipeCheckTools(tools, linker string) {
	ginkgo.GinkgoHelper()
	for _, relative := range slices.Sorted(maps.Keys(producerRecipeToolSHA256)) {
		gomega.Expect(producerRecipeFileSHA256(filepath.Join(tools, relative))).
			To(gomega.Equal(producerRecipeToolSHA256[relative]), "tool %s", relative)
	}
	gomega.Expect(producerRecipeFileSHA256(linker)).To(gomega.Equal(producerRecipeLinkerSHA256), "linker")
}

// producerRecipeCheckCopies compares every file of the fixture root with the file it was
// copied from, which also proves the sources themselves were not touched, and that the
// copy still holds exactly the files it was built with.
func producerRecipeCheckCopies(env producerRecipeEnvironment) {
	ginkgo.GinkgoHelper()
	for _, copied := range slices.Sorted(maps.Keys(env.copies)) {
		gomega.Expect(producerRecipeFileSHA256(copied)).To(gomega.Equal(producerRecipeFileSHA256(env.copies[copied])),
			"%s differs from %s", copied, env.copies[copied])
	}
	roots := append([]string{env.tools, filepath.Dir(env.linker)}, slices.Collect(maps.Values(env.runtimeMounts))...)
	for _, root := range roots {
		gomega.Expect(filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s is a symlink", path)
			}
			if _, known := env.copies[path]; !known {
				return fmt.Errorf("%s was not copied by this spec", path)
			}

			return nil
		})).To(gomega.Succeed())
	}
}

func producerRecipeFileSHA256(path string) string {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return producerRecipeBytesSHA256(body)
}

func producerRecipeBytesSHA256(body []byte) string {
	sum := sha256.Sum256(body)

	return hex.EncodeToString(sum[:])
}

func producerRecipeCheckDocker(ctx context.Context) {
	ginkgo.GinkgoHelper()
	limited, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	probe := exec.CommandContext(limited, "docker", "version", "--format", "{{.Server.Version}}")
	probe.Env = producerRecipeBaseEnv()
	if output, err := probe.CombinedOutput(); err != nil {
		ginkgo.Skip(fmt.Sprintf("requires a reachable docker daemon: %s: %s", err, output))
	}
}

// producerRecipeBaseEnv is the whole environment every subprocess of this spec gets: no
// credentials, no interactive prompt and no askpass of the environment that started the
// test are inherited.
func producerRecipeBaseEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false",
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes",
		"GIT_CONFIG_NOSYSTEM=1",
	}
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		env = append(env, "DOCKER_HOST="+host)
	}

	return env
}

func producerRecipeTempDir() string {
	ginkgo.GinkgoHelper()
	directory, err := filepath.EvalSymlinks(ginkgo.GinkgoT().TempDir())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return directory
}

// producerRecipeDeclaration is the private producer intent of the checked image: one
// explicitly named prepared source, which is also the subject of the install stage.
func producerRecipeDeclaration(packageName string) string {
	ginkgo.GinkgoHelper()
	subject := 0
	version := sbomBuildContextVersion
	declaration := sbomBuildContextDeclaration{
		Version: &version,
		Stages: map[stage.StageName]sbomBuildContextStage{
			stage.Install: {
				Subject: &subject,
				Packages: []sbomBuildContextPackage{{
					SourceImage:    "prepared",
					PackageName:    packageName,
					PackageVersion: producerRecipePackageVersion,
					PackageType:    producerRecipePackageType,
					SourcePlatform: producerRecipePlatform,
				}},
			},
		},
	}
	encoded, err := json.Marshal(declaration)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(string(encoded)).NotTo(gomega.ContainSubstring("'"), "the declaration is carried by a single-quoted YAML scalar")

	return string(encoded)
}

// producerRecipeConfig renders the recipe: a prepared source image shipping only the
// committed source file, and a checked image that imports it and compiles it with the
// mounted toolchain. packageName is what the checked image expects of the prepared source,
// which is what the negative phase disagrees about.
func producerRecipeConfig(project string, env producerRecipeEnvironment, packageName string) string {
	ginkgo.GinkgoHelper()
	var libraryPath []string
	var mounts strings.Builder
	fmt.Fprintf(&mounts, "- fromPath: %s\n  to: %s\n", env.tools, producerRecipeToolsMount)
	fmt.Fprintf(&mounts, "- fromPath: %s\n  to: %s\n", filepath.Dir(env.linker), producerRecipeLinkerMount)
	for _, mountpoint := range slices.Sorted(maps.Keys(env.runtimeMounts)) {
		fmt.Fprintf(&mounts, "- fromPath: %s\n  to: %s\n", env.runtimeMounts[mountpoint], mountpoint)
		libraryPath = append(libraryPath, mountpoint)
	}

	install := []string{
		fmt.Sprintf("export PATH=%s/bin:$PATH", producerRecipeToolsMount),
		"export LD_LIBRARY_PATH=" + strings.Join(libraryPath, ":"),
		`test -n "$SBOM_BUILD_CONTEXT"`,
		`test -f "$SBOM_BUILD_CONTEXT"`,
		// The context werf materializes, and the originals it exports beside it, are the
		// build's evidence: the build must not be able to edit them.
		fmt.Sprintf(`if : > %s/.rw-probe 2>/dev/null; then echo "build context is writable"; exit 1; fi`, producerContextMount),
		fmt.Sprintf(`if : > %s/originals/.rw-probe 2>/dev/null; then echo "build context originals are writable"; exit 1; fi`, producerContextMount),
		fmt.Sprintf("%s -p %s /tmp", stapel.MkdirBinPath(), producerRecipeObjectDir),
		"export TMPDIR=/tmp",
		fmt.Sprintf("%s/gcc/xgcc -B%s/gcc/ -B%s/bin/ -nostdinc -ffreestanding -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -c /src/main.c -o %s/app.o",
			producerRecipeToolsMount, producerRecipeToolsMount, producerRecipeToolsMount, producerRecipeObjectDir),
		fmt.Sprintf("%s -static -e _start %s/app.o -o /app", producerRecipeLinkerMount+"/"+filepath.Base(env.linker), producerRecipeObjectDir),
		// The compiled sources are the producer's input, not part of what the image ships.
		// They go only after the link succeeded, so nothing is deleted before it is used.
		fmt.Sprintf("%s -rf /src", stapel.RmBinPath()),
		fmt.Sprintf("%s -rf %s /tmp", stapel.RmBinPath(), producerRecipeObjectDir),
	}
	var commands strings.Builder
	for _, command := range install {
		// A command like `if : > …` would otherwise parse as a YAML mapping.
		quoted, err := json.Marshal(command)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		fmt.Fprintf(&commands, "  - %s\n", quoted)
	}

	return fmt.Sprintf(`project: %s
configVersion: 1
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
---
image: prepared
from: scratch
git:
- add: /main.c
  to: /src/main.c
imageSpec:
  config:
    labels:
      pkg.name: %q
      pkg.version: %q
      pkg.type: %q
      pkg.arch: %q
      pkg.default: "false"
---
image: app
from: scratch
import:
- image: prepared
  add: /src
  to: /src
  before: install
mount:
%sshell:
  install:
%s
imageSpec:
  config:
    labels:
      %s: '%s'
`,
		project,
		producerRecipePackageName, producerRecipePackageVersion, producerRecipePackageType, producerRecipePlatform,
		mounts.String(),
		commands.String(),
		stage.SBOMBuildContextLabel, producerRecipeDeclaration(packageName))
}

func producerRecipeGiterminism(env producerRecipeEnvironment) string {
	var allowed strings.Builder
	for _, path := range append([]string{env.tools, filepath.Dir(env.linker)}, slices.Sorted(maps.Values(env.runtimeMounts))...) {
		fmt.Fprintf(&allowed, "      - %s\n", path)
	}

	return fmt.Sprintf(`giterminismConfigVersion: "1"
config:
  stapel:
    mount:
      allowFromPaths:
%s`, allowed.String())
}

func producerRecipeGit(ctx context.Context, directory string, args ...string) {
	ginkgo.GinkgoHelper()
	limited, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	command := exec.CommandContext(limited, "git", args...)
	command.Dir = directory
	command.Env = producerRecipeBaseEnv()
	output, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "git %s: %s", strings.Join(args, " "), output)
}

func producerRecipeFixture(ctx context.Context, project string, env producerRecipeEnvironment) string {
	ginkgo.GinkgoHelper()
	directory := producerRecipeTempDir()
	producerRecipeWrite(directory, "main.c", producerRecipeMain)
	producerRecipeWrite(directory, "werf-giterminism.yaml", producerRecipeGiterminism(env))
	producerRecipeWrite(directory, "werf.yaml", producerRecipeConfig(project, env, producerRecipePackageName))

	producerRecipeGit(ctx, directory, "init", "--initial-branch", "main")
	producerRecipeGit(ctx, directory, "config", "user.name", "producer recipe test")
	producerRecipeGit(ctx, directory, "config", "user.email", "producer-recipe@test.invalid")
	producerRecipeGit(ctx, directory, "add", ".")
	producerRecipeGit(ctx, directory, "commit", "-m", "producer recipe fixture")

	return directory
}

func producerRecipeWrite(directory, name, content string) {
	ginkgo.GinkgoHelper()
	gomega.Expect(os.WriteFile(filepath.Join(directory, name), []byte(content), 0o644)).To(gomega.Succeed())
}

// producerRecipeEvidence preserves what the spec wrote into the fixture, which ginkgo
// deletes with it. It is registered after the fixture so that it runs before that
// deletion; the toolchain copy and the repository itself are not preserved.
func producerRecipeEvidence(fixture string) {
	destination := os.Getenv(producerRecipeEvidenceEnv)
	if destination == "" {
		return
	}
	ginkgo.DeferCleanup(func() {
		kept := filepath.Join(destination, fmt.Sprintf("producer-recipe-%d", time.Now().UnixNano()))
		gomega.Expect(os.MkdirAll(kept, 0o755)).To(gomega.Succeed())
		for _, pattern := range []string{"*.log", "report*.json", "manifest.txt", "record.json"} {
			matches, err := filepath.Glob(filepath.Join(fixture, pattern))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			for _, match := range matches {
				body, err := os.ReadFile(match)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(os.WriteFile(filepath.Join(kept, filepath.Base(match)), body, 0o644)).To(gomega.Succeed())
			}
		}
		ginkgo.AddReportEntry("producer recipe evidence", kept)
	})
}

func producerRecipeManifest(env producerRecipeEnvironment) string {
	ginkgo.GinkgoHelper()
	var manifest strings.Builder
	for _, copied := range slices.Sorted(maps.Keys(env.copies)) {
		fmt.Fprintf(&manifest, "%s  %s  %s\n", producerRecipeFileSHA256(copied), env.copies[copied], copied)
	}

	return manifest.String()
}

func producerRecipeRegistry() string {
	ginkgo.GinkgoHelper()
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://")
}

// producerRecipeRun runs the candidate binary, keeping the whole output in the test's own
// directory and reporting only its tail.
func producerRecipeRun(ctx context.Context, env producerRecipeEnvironment, directory, logName string, extraEnv []string, timeout time.Duration, args ...string) (string, error) {
	ginkgo.GinkgoHelper()
	limited, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(limited, env.binary, args...)
	command.Dir = directory
	command.Env = append(producerRecipeBaseEnv(), extraEnv...)
	output, err := command.CombinedOutput()

	path := filepath.Join(directory, logName)
	gomega.Expect(os.WriteFile(path, output, 0o644)).To(gomega.Succeed())
	ginkgo.AddReportEntry("producer recipe log", path)
	if err != nil {
		ginkgo.AddReportEntry("producer recipe log tail", producerRecipeTail(string(output)))
	}

	return string(output), err
}

func producerRecipeTail(output string) string {
	const limit = 8 << 10
	if len(output) <= limit {
		return output
	}

	return "...\n" + output[len(output)-limit:]
}

// producerRecipeBuildEnv keeps the build on an isolated home and docker configuration, so
// no registry credentials of the host reach it.
func producerRecipeBuildEnv(home, externalRefs string) []string {
	return []string{
		"HOME=" + home,
		"DOCKER_CONFIG=" + home,
		"WERF_BUILDAH_MODE=docker",
		"WERF_EXTERNAL_REFS_SERVER_URL=" + externalRefs,
		"WERF_TELEMETRY=0",
		"WERF_SYNCHRONIZATION=:local",
		"WERF_DISABLE_AUTO_HOST_CLEANUP=1",
	}
}

func producerRecipeBuildArgs(repo, reportPath string) []string {
	return []string{
		"build",
		"--repo", repo,
		"--insecure-registry",
		"--skip-tls-verify-registry",
		"--platform", producerRecipePlatform,
		"--save-build-report",
		"--build-report-path", reportPath,
	}
}

func producerRecipeReport(ctx context.Context, path string) *ImagesReport {
	ginkgo.GinkgoHelper()
	report, err := LoadBuildReportFromFile(ctx, path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return report
}

func producerRecipeImage(ctx context.Context, record ReportImageRecord) v1.Image {
	ginkgo.GinkgoHelper()
	gomega.Expect(record.DockerRepo).NotTo(gomega.BeEmpty())
	gomega.Expect(record.DockerImageDigest).NotTo(gomega.BeEmpty())
	ref, err := name.NewDigest(record.DockerRepo+"@"+record.DockerImageDigest, name.Insecure)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return image
}

func producerRecipeFile(image v1.Image, path string) []byte {
	ginkgo.GinkgoHelper()
	reader := mutate.Extract(image)
	defer reader.Close()
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		if filepath.Clean("/"+header.Name) != path {
			continue
		}
		body, err := io.ReadAll(archive)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		return body
	}
	ginkgo.Fail("image ships no " + path)

	return nil
}

func producerRecipeLabels(image v1.Image) map[string]string {
	ginkgo.GinkgoHelper()
	config, err := image.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return config.Config.Labels
}

// producerRecipeExecute runs the produced executable: the fixture is this spec's own
// freestanding payload and the only thing it can do is exit.
func producerRecipeExecute(ctx context.Context, body []byte) {
	ginkgo.GinkgoHelper()
	path := filepath.Join(producerRecipeTempDir(), "app")
	gomega.Expect(os.WriteFile(path, body, 0o755)).To(gomega.Succeed())
	limited, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(limited, path)
	command.Env = []string{}
	output, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "run produced app: %s", output)
}

// producerRecipeCleanup removes what the builds left in the local docker storage. The
// filter is this spec's own ephemeral repository, so nothing else is touched.
func producerRecipeCleanup(repo string) {
	ginkgo.DeferCleanup(func(ctx ginkgo.SpecContext) {
		limited, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		list := exec.CommandContext(limited, "docker", "image", "ls", "--filter", "reference="+repo+"*", "--format", "{{.Repository}}:{{.Tag}}")
		list.Env = producerRecipeBaseEnv()
		output, err := list.CombinedOutput()
		if err != nil {
			ginkgo.AddReportEntry("producer recipe cleanup skipped", string(output))

			return
		}
		references := strings.Fields(string(output))
		if len(references) == 0 {
			return
		}
		remove := exec.CommandContext(limited, "docker", append([]string{"image", "rm", "-f"}, references...)...)
		remove.Env = producerRecipeBaseEnv()
		if output, err := remove.CombinedOutput(); err != nil {
			ginkgo.AddReportEntry("producer recipe cleanup left references", string(output))
		}
	})
}

func producerRecipeRecord(body []byte) *shared.BuildRecord {
	ginkgo.GinkgoHelper()
	record, status, err := shared.ReadELFBuildRecord(bytes.NewReader(body))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(status).To(gomega.Equal("present"))

	return record
}

// producerRecipeRecordJSON keeps the record and the digest of the executable it came from,
// not the executable itself.
func producerRecipeRecordJSON(record *shared.BuildRecord, app []byte) string {
	ginkgo.GinkgoHelper()
	encoded, err := json.Marshal(map[string]any{"app": producerRecipeBytesSHA256(app), "record": record})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return string(encoded)
}

func producerRecipeComponent(record *shared.BuildRecord, id string) shared.BuildComponent {
	ginkgo.GinkgoHelper()
	for _, component := range record.Components {
		if component.ID == id {
			return component
		}
	}
	ginkgo.Fail("no component " + id)

	return shared.BuildComponent{}
}

var _ = ginkgo.Describe("Actual SBOM producer recipe", ginkgo.Label("producer-recipe"), func() {
	ginkgo.It("compiles a declared prepared source with the automatic build context and ships only its record", func(ctx ginkgo.SpecContext) {
		env := producerRecipeRequirements(ctx)
		project := fmt.Sprintf("producer-recipe-%d", time.Now().UnixNano())
		repo := producerRecipeRegistry() + "/" + project
		producerRecipeCleanup(repo)
		fixture := producerRecipeFixture(ctx, project, env)
		producerRecipeEvidence(fixture)
		producerRecipeWrite(fixture, "manifest.txt", producerRecipeManifest(env))
		home := producerRecipeTempDir()
		externalRefs := externalrefmock.Start().URL

		ginkgo.By("rendering the recipe without any SBOM environment at all")
		rendered, err := producerRecipeRun(ctx, env, fixture, "config-render.log", []string{"HOME=" + home}, 120*time.Second, "config", "render")
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "config render: %s", producerRecipeTail(rendered))
		gomega.Expect(rendered).To(gomega.ContainSubstring(stage.SBOMBuildContextLabel))
		gomega.Expect(rendered).To(gomega.ContainSubstring(producerRecipeDeclaration(producerRecipePackageName)))

		ginkgo.By("building the recipe with the producer context werf injects itself")
		reportPath := filepath.Join(fixture, "report.json")
		output, err := producerRecipeRun(ctx, env, fixture, "build-first.log",
			producerRecipeBuildEnv(home, externalRefs), 300*time.Second,
			producerRecipeBuildArgs(repo, reportPath)...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "build: %s", producerRecipeTail(output))

		report := producerRecipeReport(ctx, reportPath)
		gomega.Expect(report.Images).To(gomega.HaveKey("prepared"))
		gomega.Expect(report.Images).To(gomega.HaveKey("app"))

		ginkgo.By("reading back what the checked image actually ships")
		image := producerRecipeImage(ctx, report.Images["app"])
		index, err := shippedscope.IndexImageFiles(ctx, image)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(slices.Sorted(maps.Keys(index.Files))).To(gomega.Equal([]string{"/app"}))
		// Docker leaves the mount points themselves behind, so only their contents matter.
		for _, path := range append(slices.Sorted(maps.Keys(index.Files)), slices.Sorted(maps.Keys(index.Symlinks))...) {
			gomega.Expect(path).NotTo(gomega.HavePrefix(producerContextMount + "/"))
		}

		// The declaration names an internal image and must not survive into the config.
		gomega.Expect(producerRecipeLabels(image)).NotTo(gomega.HaveKey(stage.SBOMBuildContextLabel))

		app := producerRecipeFile(image, "/app")
		record := producerRecipeRecord(app)
		producerRecipeWrite(fixture, "record.json", producerRecipeRecordJSON(record, app))
		gomega.Expect(record.Profile.ID).To(gomega.Equal("c-static"))
		gomega.Expect(record.Profile.Platform).To(gomega.Equal(producerRecipePlatform))
		gomega.Expect(record.Complete).To(gomega.BeTrue())

		subject := producerRecipeComponent(record, record.Subject)
		gomega.Expect(subject.Name).To(gomega.Equal(producerRecipePackageName))
		gomega.Expect(subject.Version).To(gomega.Equal(producerRecipePackageVersion))
		gomega.Expect(subject.Source.Kind).To(gomega.Equal("pm"))

		included := []string{}
		for _, component := range record.IncludedComponents() {
			included = append(included, component.Name)
		}
		gomega.Expect(included).To(gomega.Equal([]string{producerRecipePackageName}))

		paths := []string{}
		for _, input := range record.Inputs {
			paths = append(paths, input.Path)
			// The materialized context is the producer's own scratch, never an input a
			// consumer may be pointed at.
			gomega.Expect(input.Path).NotTo(gomega.HavePrefix(producerContextMount))
		}
		gomega.Expect(paths).To(gomega.ContainElement("/src/main.c"))

		producerRecipeExecute(ctx, app)

		ginkgo.By("building the same fixture again")
		warmReportPath := filepath.Join(fixture, "report-warm.json")
		output, err = producerRecipeRun(ctx, env, fixture, "build-warm.log",
			producerRecipeBuildEnv(home, externalRefs), 300*time.Second,
			producerRecipeBuildArgs(repo, warmReportPath)...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "warm build: %s", producerRecipeTail(output))
		gomega.Expect(output).To(gomega.ContainSubstring("Use previously built image"))

		warm := producerRecipeReport(ctx, warmReportPath)
		gomega.Expect(warm.Images["app"].DockerImageDigest).To(gomega.Equal(report.Images["app"].DockerImageDigest))
		gomega.Expect(producerRecipeFile(producerRecipeImage(ctx, warm.Images["app"]), "/app")).To(gomega.Equal(app))

		ginkgo.By("disagreeing with the prepared source the recipe actually imports")
		producerRecipeWrite(fixture, "werf.yaml", producerRecipeConfig(project, env, producerRecipePackageName+"-other"))
		producerRecipeGit(ctx, fixture, "commit", "-am", "expect another prepared source")
		mismatchReportPath := filepath.Join(fixture, "report-mismatch.json")
		output, err = producerRecipeRun(ctx, env, fixture, "build-mismatch.log",
			producerRecipeBuildEnv(home, externalRefs), 300*time.Second,
			producerRecipeBuildArgs(repo, mismatchReportPath)...)
		gomega.Expect(err).To(gomega.HaveOccurred(), "a disagreeing declaration must fail the build")
		gomega.Expect(output).To(gomega.ContainSubstring("producer context for install"))
		gomega.Expect(output).To(gomega.ContainSubstring("invalid: producer source prepared has unexpected name"))
		// The declaration is checked while the stage digest is calculated, so the failing
		// build reports no image at all rather than one built by some other compiler.
		if _, statErr := os.Stat(mismatchReportPath); statErr == nil {
			gomega.Expect(producerRecipeReport(ctx, mismatchReportPath).Images).NotTo(gomega.HaveKey("app"))
		}

		ginkgo.By("leaving every copied file, and every file it was copied from, as it was")
		producerRecipeCheckTools(env.tools, env.linker)
		producerRecipeCheckCopies(env)
	})
})
