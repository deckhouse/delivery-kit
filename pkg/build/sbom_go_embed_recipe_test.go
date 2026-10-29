package build

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/docker_registry"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/stapel"
	"github.com/werf/werf/v3/test/pkg/externalrefmock"
)

const (
	// goEmbedRecipeSDKEnv names the Go SDK root itself, a GOROOT directory holding bin/go,
	// pkg/tool, src, pkg/include, VERSION and go.env, not a path to the go binary.
	goEmbedRecipeSDKEnv = "DK_GO_SDK"
	// goEmbedRecipeHelperEnv names the helper executable the producer runs.
	goEmbedRecipeHelperEnv = "DK_GO_HELPER"
	// goEmbedRecipeProofEnv and goEmbedRecipeOutputRootEnv name the asset proof and the
	// output directory it covers, both as the collector left them.
	goEmbedRecipeProofEnv      = "DK_WEBPACK_PROOF"
	goEmbedRecipeOutputRootEnv = "DK_WEBPACK_OUTPUT_ROOT"
)

// The gate executes exactly one Go toolchain and one helper, both pinned by content.
const (
	goEmbedRecipeGoSHA256       = "5e71800311c142689de31542824ed221dd0252370fba038ebeefa3651e89156b"
	goEmbedRecipeGoVersion      = "go1.27.3"
	goEmbedRecipeHelperSHA256   = "b8b4ad03bd62f7c5c8b381ad84e20a66b3e72d8c02da50b6b13f77b0f06e9f2e"
	goEmbedRecipeHelperRevision = "467bc40f59acb36a1ba8a3843c7a57d85fe18383"
	goEmbedRecipeSDKPackage     = "golang"
	goEmbedRecipeSDKVersion     = "1.27.3"
	goEmbedRecipePrimaryPackage = "ui-source"
	goEmbedRecipePrimaryVersion = "1.0.0"
	// goEmbedRecipeMainVersion is what the stock Go build info of the executable carries for
	// a main module built outside a tagged module; the prepared source the record is the
	// subject of keeps its own declared version.
	goEmbedRecipeMainVersion     = "(devel)"
	goEmbedRecipeCatalogProperty = "dk:catalog/v4"
)

const (
	// goEmbedRecipeWorkMount is a disposable fixture directory mounted read-write: the Go
	// build cache, GOPATH, HOME and TMPDIR live there instead of in the image, so the cold
	// compile does not end up in the container storage. Its contents are not payload and
	// are never removed by the build: unmounting them is the fixture's own cleanup.
	goEmbedRecipeWorkMount   = "/work"
	goEmbedRecipeToolsMount  = "/nativetools"
	goEmbedRecipeGoRoot      = "/goroot"
	goEmbedRecipeProjectRoot = "/project"
	goEmbedRecipeAssetRoot   = goEmbedRecipeProjectRoot + "/lib/assets"
	goEmbedRecipeProofPath   = "/.werf/assets/ui.json"
)

// goEmbedRecipeAssets are the two assets the recipe embeds; the proof covers two more the
// recipe does not embed, one of which carries no data.
var goEmbedRecipeAssets = []string{"main.js", "notice.txt"}

const goEmbedRecipeUnselectedAsset = "vendor.js"

type goEmbedRecipeEnvironment struct {
	binary   string
	revision string
	// sdk and helper are the frozen originals: nothing of this spec ever writes into them
	// or mounts them, only copies of them are given to the build.
	sdk        string
	helper     string
	proofPath  string
	outputRoot string

	tools         string
	work          string
	goBin         string
	goTool        string
	runtimeMounts map[string]string
	copies        map[string]string
	proof         goEmbedRecipeProof
}

// goEmbedRecipeProof is the part of the collector's proof this spec reads: the whole of it
// is carried into the source image verbatim, as the producer's own evidence.
type goEmbedRecipeProof struct {
	Version    int                     `json:"version"`
	SourceRoot string                  `json:"sourceRoot"`
	Assets     []goEmbedRecipeAssetRow `json:"assets"`
}

type goEmbedRecipeAssetRow struct {
	Path               string                  `json:"path"`
	SHA256             string                  `json:"sha256"`
	Size               int64                   `json:"size"`
	Status             string                  `json:"status"`
	IncludedComponents []string                `json:"includedComponents"`
	Components         []shared.BuildComponent `json:"components"`
	Inputs             []shared.BuildInput     `json:"inputs"`
}

func goEmbedRecipeRequirements(ctx context.Context) goEmbedRecipeEnvironment {
	ginkgo.GinkgoHelper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		ginkgo.Skip("the actual go embed recipe runs only on linux/amd64")
	}

	env := goEmbedRecipeEnvironment{
		binary:     os.Getenv(producerRecipeBinaryEnv),
		revision:   os.Getenv(producerRecipeRevisionEnv),
		sdk:        os.Getenv(goEmbedRecipeSDKEnv),
		helper:     os.Getenv(goEmbedRecipeHelperEnv),
		proofPath:  os.Getenv(goEmbedRecipeProofEnv),
		outputRoot: os.Getenv(goEmbedRecipeOutputRootEnv),
	}
	for variable, value := range map[string]string{
		producerRecipeBinaryEnv:    env.binary,
		producerRecipeRevisionEnv:  env.revision,
		goEmbedRecipeSDKEnv:        env.sdk,
		goEmbedRecipeHelperEnv:     env.helper,
		goEmbedRecipeProofEnv:      env.proofPath,
		goEmbedRecipeOutputRootEnv: env.outputRoot,
	} {
		if value == "" {
			ginkgo.Skip("requires " + variable)
		}
		if variable != producerRecipeRevisionEnv {
			gomega.Expect(filepath.IsAbs(value)).To(gomega.BeTrue(), "%s must be an absolute path", variable)
		}
	}
	gomega.Expect(producerRecipeRevisionRegexp.MatchString(env.revision)).To(gomega.BeTrue(),
		"%s must be a full 40-character commit", producerRecipeRevisionEnv)

	producerRecipeCheckCandidate(producerRecipeEnvironment{binary: env.binary, revision: env.revision})
	producerRecipeCheckDocker(ctx)
	env.proof = goEmbedRecipeReadProof(env)
	goEmbedRecipeFill(ctx, &env)
	goEmbedRecipeCheckTools(env)

	return env
}

// goEmbedRecipeReadProof keeps the proof as it is: the source root it was collected under
// is where the asset image has to ship the assets, so that nothing in it is rewritten.
func goEmbedRecipeReadProof(env goEmbedRecipeEnvironment) goEmbedRecipeProof {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(env.proofPath)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var proof goEmbedRecipeProof
	gomega.Expect(json.Unmarshal(body, &proof)).To(gomega.Succeed())
	gomega.Expect(proof.Version).To(gomega.Equal(1))
	gomega.Expect(filepath.IsAbs(proof.SourceRoot)).To(gomega.BeTrue(), "proof source root must be absolute")
	gomega.Expect(filepath.Clean(proof.SourceRoot)).To(gomega.Equal(proof.SourceRoot))
	for _, name := range append(slices.Clone(goEmbedRecipeAssets), goEmbedRecipeUnselectedAsset) {
		gomega.Expect(goEmbedRecipeAsset(proof, name).SHA256).To(
			gomega.Equal("sha256:"+producerRecipeFileSHA256(filepath.Join(env.outputRoot, name))),
			"%s of the output root is not the one the proof covers", name)
	}

	return proof
}

func goEmbedRecipeAsset(proof goEmbedRecipeProof, name string) goEmbedRecipeAssetRow {
	ginkgo.GinkgoHelper()
	for _, asset := range proof.Assets {
		if asset.Path == name {
			return asset
		}
	}
	ginkgo.Fail("the proof covers no " + name)

	return goEmbedRecipeAssetRow{}
}

// goEmbedRecipeFill copies what the build is allowed to execute into a disposable fixture
// root: the toolchain's own binaries, the helper and the runtime closure all of them need.
// The frozen originals stay read-only, werf mounts a custom_dir read-write.
func goEmbedRecipeFill(ctx context.Context, env *goEmbedRecipeEnvironment) {
	ginkgo.GinkgoHelper()
	root := producerRecipeTempDir()
	env.copies = map[string]string{}
	env.tools = filepath.Join(root, "tools")
	// The work directory is the build's own scratch; it is deliberately not recorded in
	// copies, which is the manifest of immutable files this spec hashes before and after.
	env.work = filepath.Join(root, "work")
	gomega.Expect(os.MkdirAll(env.work, 0o755)).To(gomega.Succeed())
	env.goBin = filepath.Join(root, "gobin")
	env.goTool = filepath.Join(root, "gotool")
	producerRecipeCopyTree(ctx, filepath.Join(env.sdk, "bin"), env.goBin, env.copies)
	producerRecipeCopyTree(ctx, filepath.Join(env.sdk, "pkg", "tool"), env.goTool, env.copies)
	gomega.Expect(os.MkdirAll(env.tools, 0o755)).To(gomega.Succeed())
	producerRecipeCopyFile(env.helper, filepath.Join(env.tools, "sbom-helper"), env.copies)

	pinned := []string{filepath.Join(env.goBin, "go"), filepath.Join(env.tools, "sbom-helper")}
	for _, tool := range []string{"compile", "link", "asm"} {
		pinned = append(pinned, filepath.Join(env.goTool, "linux_amd64", tool))
	}
	interpreters, libraries := producerRecipeClosure(pinned, producerRecipeHostLibrarySearch)

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

// goEmbedRecipeCheckTools proves which toolchain and which helper this gate runs, by
// content and by what they were built from, before anything executes them.
func goEmbedRecipeCheckTools(env goEmbedRecipeEnvironment) {
	ginkgo.GinkgoHelper()
	goBinary := filepath.Join(env.goBin, "go")
	gomega.Expect(producerRecipeFileSHA256(goBinary)).To(gomega.Equal(goEmbedRecipeGoSHA256), "go toolchain")
	info, err := buildinfo.ReadFile(goBinary)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(info.GoVersion).To(gomega.Equal(goEmbedRecipeGoVersion))

	helper := filepath.Join(env.tools, "sbom-helper")
	gomega.Expect(producerRecipeFileSHA256(helper)).To(gomega.Equal(goEmbedRecipeHelperSHA256), "sbom helper")
	goEmbedRecipeCheckHelperBuild(helper)

	goEmbedRecipeCheckCopies(env)
}

// goEmbedRecipeCheckHelperBuild reads which sources the helper was built from. The main
// module version of a helper built in place is "(devel)", so the revision is read where it
// is recorded exactly, not out of the module version.
func goEmbedRecipeCheckHelperBuild(path string) {
	ginkgo.GinkgoHelper()
	info, err := buildinfo.ReadFile(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs.revision", goEmbedRecipeHelperRevision))
	gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs.modified", "false"))
	gomega.Expect(settings).To(gomega.HaveKeyWithValue("CGO_ENABLED", "0"))
}

func goEmbedRecipeCheckCopies(env goEmbedRecipeEnvironment) {
	ginkgo.GinkgoHelper()
	for _, copied := range slices.Sorted(maps.Keys(env.copies)) {
		gomega.Expect(producerRecipeFileSHA256(copied)).To(gomega.Equal(producerRecipeFileSHA256(env.copies[copied])),
			"%s differs from %s", copied, env.copies[copied])
	}
	roots := append([]string{env.tools, env.goBin, env.goTool}, slices.Collect(maps.Values(env.runtimeMounts))...)
	for _, root := range roots {
		gomega.Expect(filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			if _, known := env.copies[path]; !known {
				return fmt.Errorf("%s was not copied by this spec", path)
			}

			return nil
		})).To(gomega.Succeed())
	}
}

func goEmbedRecipeManifest(env goEmbedRecipeEnvironment) string {
	ginkgo.GinkgoHelper()
	var manifest strings.Builder
	for _, copied := range slices.Sorted(maps.Keys(env.copies)) {
		fmt.Fprintf(&manifest, "%s  %s  %s\n", producerRecipeFileSHA256(copied), env.copies[copied], copied)
	}

	return manifest.String()
}

const goEmbedRecipeGoMod = "module sbom.test/ui\n\ngo 1.27\n"

const goEmbedRecipeMain = `package main

import (
	"fmt"

	"sbom.test/ui/lib"
)

func main() {
	fmt.Print(lib.Value())
}
`

// goEmbedRecipeLib is the only thing a phase varies: which assets the Go package embeds,
// which is what decides the obligation the producer has to discharge from the proof.
func goEmbedRecipeLib(assets []string) string {
	patterns := make([]string, 0, len(assets))
	quoted := make([]string, 0, len(assets))
	for _, asset := range assets {
		patterns = append(patterns, "assets/"+asset)
		quoted = append(quoted, fmt.Sprintf("%q", "assets/"+asset))
	}

	return fmt.Sprintf(`package lib

import "embed"

//go:embed %s
var assets embed.FS

func Value() string {
	var value string
	for _, name := range []string{%s} {
		body, err := assets.ReadFile(name)
		if err != nil {
			panic(err)
		}
		value += string(body)
	}

	return value
}
`, strings.Join(patterns, " "), strings.Join(quoted, ", "))
}

// goEmbedRecipeSDKExtensions are the source extensions the SDK package ships. Objects,
// archives and test data are not sources and are not shipped.
var goEmbedRecipeSDKExtensions = map[string]bool{".go": true, ".s": true, ".h": true}

// goEmbedRecipeSDKFiles are the non-extension files the distribution keeps. modules.txt is
// among them because the standard library's own vendor directories are unbuildable without
// it; it is a text manifest, not an object.
var goEmbedRecipeSDKFiles = map[string]bool{
	"go.mod": true, "go.sum": true, "go.env": true, "VERSION": true, "modules.txt": true,
}

// goEmbedRecipeSDKSources copies the SDK's own source files into the fixture repository.
// What is copied is a filtered distribution of the golang sources, never the executables:
// those are mounted from their own copies and never enter an image.
func goEmbedRecipeSDKSources(env goEmbedRecipeEnvironment, destination string) int {
	ginkgo.GinkgoHelper()
	count := 0
	for _, relative := range []string{"src", filepath.Join("pkg", "include")} {
		from := filepath.Join(env.sdk, relative)
		gomega.Expect(filepath.WalkDir(from, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}

				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			name := entry.Name()
			if strings.HasSuffix(name, "_test.go") {
				return nil
			}
			if !goEmbedRecipeSDKExtensions[filepath.Ext(name)] && !goEmbedRecipeSDKFiles[name] {
				return nil
			}
			within, err := filepath.Rel(env.sdk, path)
			if err != nil {
				return err
			}
			target := filepath.Join(destination, within)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			count++

			return os.WriteFile(target, body, 0o644)
		})).To(gomega.Succeed())
	}
	for _, name := range []string{"VERSION", "go.env"} {
		body, err := os.ReadFile(filepath.Join(env.sdk, name))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(os.WriteFile(filepath.Join(destination, name), body, 0o644)).To(gomega.Succeed())
		count++
	}
	gomega.Expect(count).To(gomega.BeNumerically(">", 1000), "the SDK source distribution is implausibly small")

	return count
}

// goEmbedRecipeDeclaration is the private producer intent: the compiled Go module is the
// subject, the SDK is the other prepared source it consumes, and the embedded assets are
// bound to the image that shipped them together with the collector's proof.
func goEmbedRecipeDeclaration(sourceRoot string) string {
	ginkgo.GinkgoHelper()
	subject := 0
	version := sbomBuildContextVersion
	declaration := sbomBuildContextDeclaration{
		Version: &version,
		Stages: map[stage.StageName]sbomBuildContextStage{
			stage.Install: {
				Subject: &subject,
				Packages: []sbomBuildContextPackage{
					{
						SourceImage:    "ui-source",
						PackageName:    goEmbedRecipePrimaryPackage,
						PackageVersion: goEmbedRecipePrimaryVersion,
						PackageType:    producerRecipePackageType,
						SourcePlatform: producerRecipePlatform,
					},
					{
						SourceImage:    "go-sdk-source",
						PackageName:    goEmbedRecipeSDKPackage,
						PackageVersion: goEmbedRecipeSDKVersion,
						PackageType:    producerRecipePackageType,
						SourcePlatform: producerRecipePlatform,
					},
				},
				GoEmbed: []sbomBuildContextGoEmbed{{
					SourceImage: "ui-assets",
					SourceRoot:  sourceRoot,
					TargetRoot:  goEmbedRecipeAssetRoot,
					ProofPath:   goEmbedRecipeProofPath,
				}},
			},
		},
	}
	encoded, err := json.Marshal(declaration)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(string(encoded)).NotTo(gomega.ContainSubstring("'"), "the declaration is carried by a single-quoted YAML scalar")

	return string(encoded)
}

func goEmbedRecipeConfig(project string, env goEmbedRecipeEnvironment) string {
	ginkgo.GinkgoHelper()
	var libraryPath []string
	var mounts strings.Builder
	for _, mount := range [][2]string{
		{env.tools, goEmbedRecipeToolsMount},
		{env.work, goEmbedRecipeWorkMount},
		{env.goBin, goEmbedRecipeGoRoot + "/bin"},
		{env.goTool, goEmbedRecipeGoRoot + "/pkg/tool"},
	} {
		fmt.Fprintf(&mounts, "- fromPath: %q\n  to: %q\n", mount[0], mount[1])
	}
	for _, mountpoint := range slices.Sorted(maps.Keys(env.runtimeMounts)) {
		fmt.Fprintf(&mounts, "- fromPath: %q\n  to: %q\n", env.runtimeMounts[mountpoint], mountpoint)
		libraryPath = append(libraryPath, mountpoint)
	}

	install := []string{
		fmt.Sprintf("export PATH=%s:%s/bin:$PATH", goEmbedRecipeToolsMount, goEmbedRecipeGoRoot),
		"export LD_LIBRARY_PATH=" + strings.Join(libraryPath, ":"),
		"export GOROOT=" + goEmbedRecipeGoRoot,
		"export GOTOOLCHAIN=local",
		"export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOPROXY=off",
		fmt.Sprintf("export GOCACHE=%s/gocache GOPATH=%s/gopath HOME=%s/home TMPDIR=%s/tmp",
			goEmbedRecipeWorkMount, goEmbedRecipeWorkMount, goEmbedRecipeWorkMount, goEmbedRecipeWorkMount),
		`test -n "$SBOM_BUILD_CONTEXT"`,
		`test -f "$SBOM_BUILD_CONTEXT"`,
		// The context werf materializes, including the asset proof it exports beside it,
		// is the build's evidence: the build must not be able to edit it.
		fmt.Sprintf(`if : > %s/.rw-probe 2>/dev/null; then echo "build context is writable"; exit 1; fi`, producerContextMount),
		fmt.Sprintf(`if : > %s/proofs/.rw-probe 2>/dev/null; then echo "build context proofs are writable"; exit 1; fi`, producerContextMount),
		fmt.Sprintf("%s -p %s/gocache %s/gopath %s/home %s/tmp", stapel.MkdirBinPath(),
			goEmbedRecipeWorkMount, goEmbedRecipeWorkMount, goEmbedRecipeWorkMount, goEmbedRecipeWorkMount),
		// The build runs as root, so everything it writes into the mounted scratch would be
		// unremovable by the test user. The trap is set in the same shell before the
		// compile and also runs when it fails; a container killed outright skips it, and
		// then the leftover is this spec's own temporary directory, nothing shared.
		fmt.Sprintf("trap '%s -R %d:%d %s' EXIT; cd %s && go build -buildvcs=false -o /app .",
			stapel.ChownBinPath(), os.Getuid(), os.Getgid(), goEmbedRecipeWorkMount, goEmbedRecipeProjectRoot),
		// The sources and the SDK distribution are the producer's input, not part of what
		// the image ships. Neither the mounted executables nor the mounted work directory
		// are removed: what a mount holds is not payload, and its root is busy.
		fmt.Sprintf("%s -rf %s %s/src %s/pkg/include %s/VERSION %s/go.env",
			stapel.RmBinPath(), goEmbedRecipeProjectRoot,
			goEmbedRecipeGoRoot, goEmbedRecipeGoRoot, goEmbedRecipeGoRoot, goEmbedRecipeGoRoot),
	}
	var commands strings.Builder
	for _, command := range install {
		quoted, err := json.Marshal(command)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		fmt.Fprintf(&commands, "  - %s\n", quoted)
	}

	rendered := fmt.Sprintf(`project: %s
configVersion: 1
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
---
image: ui-source
from: scratch
git:
- add: "/primary"
  to: "/src"
imageSpec:
  config:
    labels:
      pkg.name: %q
      pkg.version: %q
      pkg.type: %q
      pkg.arch: %q
      pkg.default: "false"
---
image: go-sdk-source
from: scratch
git:
- add: "/sdk"
  to: %q
imageSpec:
  config:
    labels:
      pkg.name: %q
      pkg.version: %q
      pkg.type: %q
      pkg.arch: %q
      pkg.default: "false"
---
image: ui-assets
from: scratch
git:
- add: "/assets/out"
  to: %q
- add: "/assets/ui.json"
  to: %q
---
image: app
from: scratch
import:
- image: ui-source
  add: "/src"
  to: %q
  before: install
- image: go-sdk-source
  add: %q
  to: %q
  before: install
- image: ui-assets
  add: %q
  to: %q
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
		goEmbedRecipePrimaryPackage, goEmbedRecipePrimaryVersion, producerRecipePackageType, producerRecipePlatform,
		goEmbedRecipeGoRoot,
		goEmbedRecipeSDKPackage, goEmbedRecipeSDKVersion, producerRecipePackageType, producerRecipePlatform,
		env.proof.SourceRoot, goEmbedRecipeProofPath,
		goEmbedRecipeProjectRoot,
		goEmbedRecipeGoRoot, goEmbedRecipeGoRoot,
		env.proof.SourceRoot, goEmbedRecipeAssetRoot,
		mounts.String(),
		commands.String(),
		stage.SBOMBuildContextLabel, goEmbedRecipeDeclaration(env.proof.SourceRoot))

	gomega.Expect(rendered).To(gomega.ContainSubstring(fmt.Sprintf("- fromPath: %q\n  to: %q\n", env.work, goEmbedRecipeWorkMount)),
		"the build's scratch must be a mount, not a layer")
	gomega.Expect(rendered).To(gomega.ContainSubstring("TMPDIR=" + goEmbedRecipeWorkMount + "/tmp"))
	gomega.Expect(rendered).NotTo(gomega.ContainSubstring("-rf "+goEmbedRecipeWorkMount),
		"a mount root cannot be removed by the build")

	return rendered
}

func goEmbedRecipeGiterminism(env goEmbedRecipeEnvironment) string {
	var allowed strings.Builder
	for _, path := range append([]string{env.tools, env.work, env.goBin, env.goTool}, slices.Sorted(maps.Values(env.runtimeMounts))...) {
		fmt.Fprintf(&allowed, "      - %q\n", path)
	}

	return fmt.Sprintf(`giterminismConfigVersion: "1"
config:
  stapel:
    mount:
      allowFromPaths:
%s`, allowed.String())
}

// goEmbedRecipeFixture commits the whole build graph: the Go module, the filtered SDK
// source distribution, and the collected assets together with the proof that covers them.
func goEmbedRecipeFixture(ctx context.Context, project string, env goEmbedRecipeEnvironment) string {
	ginkgo.GinkgoHelper()
	directory := producerRecipeTempDir()
	gomega.Expect(os.MkdirAll(filepath.Join(directory, "primary", "lib"), 0o755)).To(gomega.Succeed())
	producerRecipeWrite(filepath.Join(directory, "primary"), "go.mod", goEmbedRecipeGoMod)
	producerRecipeWrite(filepath.Join(directory, "primary"), "main.go", goEmbedRecipeMain)
	producerRecipeWrite(filepath.Join(directory, "primary", "lib"), "lib.go", goEmbedRecipeLib(goEmbedRecipeAssets))

	sdk := filepath.Join(directory, "sdk")
	gomega.Expect(os.MkdirAll(sdk, 0o755)).To(gomega.Succeed())
	ginkgo.AddReportEntry("go embed recipe SDK source files", goEmbedRecipeSDKSources(env, sdk))

	assets := filepath.Join(directory, "assets", "out")
	gomega.Expect(os.MkdirAll(assets, 0o755)).To(gomega.Succeed())
	gomega.Expect(filepath.WalkDir(env.outputRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		within, relErr := filepath.Rel(env.outputRoot, path)
		if relErr != nil {
			return relErr
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(assets, within)), 0o755); err != nil {
			return err
		}

		return os.WriteFile(filepath.Join(assets, within), body, 0o644)
	})).To(gomega.Succeed())
	proofBody, err := os.ReadFile(env.proofPath)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(os.WriteFile(filepath.Join(directory, "assets", "ui.json"), proofBody, 0o644)).To(gomega.Succeed())

	producerRecipeWrite(directory, "werf-giterminism.yaml", goEmbedRecipeGiterminism(env))
	producerRecipeWrite(directory, "werf.yaml", goEmbedRecipeConfig(project, env))

	producerRecipeGit(ctx, directory, "init", "--initial-branch", "main")
	producerRecipeGit(ctx, directory, "config", "user.name", "go embed recipe test")
	producerRecipeGit(ctx, directory, "config", "user.email", "go-embed-recipe@test.invalid")
	producerRecipeGit(ctx, directory, "add", ".")
	producerRecipeGit(ctx, directory, "commit", "-m", "go embed recipe fixture")

	return directory
}

// goEmbedRecipeExecute runs the produced executable and returns what it printed: the
// fixture's own program prints exactly the assets it embedded.
func goEmbedRecipeExecute(ctx context.Context, body []byte) string {
	ginkgo.GinkgoHelper()
	path := filepath.Join(producerRecipeTempDir(), "app")
	gomega.Expect(os.WriteFile(path, body, 0o755)).To(gomega.Succeed())
	limited, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(limited, path)
	command.Env = []string{}
	var failed bytes.Buffer
	command.Stderr = &failed
	output, err := command.Output()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "run produced app: %s", failed.String())
	gomega.Expect(failed.String()).To(gomega.BeEmpty(), "the produced app writes nothing but its assets")

	return string(output)
}

// goEmbedRecipeCatalogComposition reads, as it was published, the composition the BOM
// carries for a path: the comparison with what the executable ships is a JSON one, so no
// field of the published document is silently dropped by decoding it here.
func goEmbedRecipeCatalogComposition(ctx context.Context, repo, digest, path string) []byte {
	ginkgo.GinkgoHelper()
	bom, err := sbomImage.PullCycloneDX16BOM(ctx, repo, digest, "app")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(bom.Metadata).NotTo(gomega.BeNil())
	gomega.Expect(bom.Metadata.Properties).NotTo(gomega.BeNil())
	for _, property := range *bom.Metadata.Properties {
		if property.Name != goEmbedRecipeCatalogProperty {
			continue
		}
		var catalog struct {
			Records []struct {
				Path        string          `json:"path"`
				Composition json.RawMessage `json:"composition"`
			} `json:"records"`
		}
		gomega.Expect(json.Unmarshal([]byte(property.Value), &catalog)).To(gomega.Succeed())
		for _, record := range catalog.Records {
			if record.Path == path {
				return record.Composition
			}
		}
	}
	ginkgo.Fail("the published BOM carries no catalog record for " + path)

	return nil
}

var _ = ginkgo.Describe("Actual SBOM go embed helper identity", func() {
	// This reads the helper artifact only, so it needs neither the toolchain nor a daemon:
	// it is what proves the identity guard matches the artifact that is handed over.
	ginkgo.It("reads the reviewed revision out of the helper's recorded build settings", func() {
		helper := os.Getenv(goEmbedRecipeHelperEnv)
		if helper == "" {
			ginkgo.Skip("requires " + goEmbedRecipeHelperEnv)
		}
		gomega.Expect(producerRecipeFileSHA256(helper)).To(gomega.Equal(goEmbedRecipeHelperSHA256))
		goEmbedRecipeCheckHelperBuild(helper)
	})
})

var _ = ginkgo.Describe("Actual SBOM go embed recipe", ginkgo.Label("go-embed-recipe"), func() {
	ginkgo.It("compiles a Go module whose embedded assets are attributed from the collected proof", func(ctx ginkgo.SpecContext) {
		// The registry client this spec pulls the published BOM with is global state; this
		// spec initializes it itself instead of depending on another spec having run.
		gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
		env := goEmbedRecipeRequirements(ctx)
		project := fmt.Sprintf("go-embed-recipe-%d", time.Now().UnixNano())
		repo := producerRecipeRegistry() + "/" + project
		producerRecipeCleanup(repo)
		fixture := goEmbedRecipeFixture(ctx, project, env)
		producerRecipeEvidence(fixture)
		producerRecipeWrite(fixture, "manifest.txt", goEmbedRecipeManifest(env))
		home := producerRecipeTempDir()
		externalRefs := externalrefmock.Start().URL

		ginkgo.By("building the recipe cold with the producer context werf injects itself")
		reportPath := filepath.Join(fixture, "report.json")
		output, err := producerRecipeRun(ctx, producerRecipeEnvironment{binary: env.binary}, fixture, "build-first.log",
			producerRecipeBuildEnv(home, externalRefs), 1800*time.Second,
			producerRecipeBuildArgs(repo, reportPath)...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "build: %s", producerRecipeTail(output))

		report := producerRecipeReport(ctx, reportPath)
		for _, name := range []string{"ui-source", "go-sdk-source", "ui-assets", "app"} {
			gomega.Expect(report.Images).To(gomega.HaveKey(name))
		}

		ginkgo.By("reading back what the checked image actually ships")
		image := producerRecipeImage(ctx, report.Images["app"])
		index, err := shippedscope.IndexImageFiles(ctx, image)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(slices.Sorted(maps.Keys(index.Files))).To(gomega.Equal([]string{"/app"}))
		gomega.Expect(producerRecipeLabels(image)).NotTo(gomega.HaveKey(stage.SBOMBuildContextLabel))

		app := producerRecipeFile(image, "/app")
		info, err := shared.ReadBuildInfo(bytes.NewReader(app))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(info.Status).To(gomega.Equal("present"))
		record := info.SBOM
		producerRecipeWrite(fixture, "record.json", producerRecipeRecordJSON(record, app))
		gomega.Expect(record.Profile.ID).To(gomega.Equal("go"))
		gomega.Expect(record.Profile.Revision.String()).To(gomega.Equal("2"))
		gomega.Expect(record.Profile.Platform).To(gomega.Equal(producerRecipePlatform))
		gomega.Expect(record.Complete).To(gomega.BeTrue())

		subject := producerRecipeComponent(record, record.Subject)
		gomega.Expect(subject.Name).To(gomega.Equal(goEmbedRecipePrimaryPackage))
		gomega.Expect(subject.Source.Kind).To(gomega.Equal("pm"))
		gomega.Expect(subject.Version).To(gomega.Equal(goEmbedRecipePrimaryVersion))
		// The declared prepared source and the Go main module are separate identities: the
		// subject keeps the version the producer context declared, while the stock build
		// info of the same executable still reports an untagged main module.
		stock, err := buildinfo.Read(bytes.NewReader(app))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stock.Main.Version).To(gomega.Equal(goEmbedRecipeMainVersion))

		ginkgo.By("attributing the embedded assets to the contributors the proof selected")
		included := map[string]shared.BuildComponent{}
		for _, component := range record.IncludedComponents() {
			included[component.ID] = component
		}
		contributors := []string{}
		for _, asset := range goEmbedRecipeAssets {
			for _, id := range goEmbedRecipeAsset(env.proof, asset).IncludedComponents {
				if !slices.Contains(contributors, id) {
					contributors = append(contributors, id)
				}
			}
		}
		gomega.Expect(contributors).To(gomega.HaveLen(3))
		for _, id := range contributors {
			gomega.Expect(included).To(gomega.HaveKey(id))
		}
		for _, component := range goEmbedRecipeAsset(env.proof, goEmbedRecipeAssets[0]).Components {
			gomega.Expect(included[component.ID]).To(gomega.Equal(component),
				"the identity of %s must be the one the proof carries", component.ID)
		}
		names := []string{}
		for _, component := range included {
			names = append(names, component.Name)
		}
		gomega.Expect(names).To(gomega.ContainElement(goEmbedRecipePrimaryPackage))
		gomega.Expect(names).To(gomega.ContainElement(goEmbedRecipeSDKPackage))
		gomega.Expect(names).To(gomega.HaveLen(5))

		ginkgo.By("keeping the diagnostic input paths the collector observed")
		paths := []string{}
		for _, input := range record.Inputs {
			paths = append(paths, input.Path)
			gomega.Expect(input.Path).NotTo(gomega.HavePrefix(producerContextMount))
		}
		for _, input := range goEmbedRecipeAsset(env.proof, goEmbedRecipeAssets[0]).Inputs {
			gomega.Expect(paths).To(gomega.ContainElement(input.Path))
		}
		for _, asset := range goEmbedRecipeAssets {
			gomega.Expect(paths).To(gomega.ContainElement(filepath.Join(goEmbedRecipeAssetRoot, asset)))
		}

		ginkgo.By("running what was built")
		expected := ""
		for _, asset := range goEmbedRecipeAssets {
			body, readErr := os.ReadFile(filepath.Join(env.outputRoot, asset))
			gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
			expected += string(body)
		}
		gomega.Expect(goEmbedRecipeExecute(ctx, app)).To(gomega.Equal(expected))

		ginkgo.By("reading the record the published BOM carries for the same executable")
		published := goEmbedRecipeCatalogComposition(ctx, repo, report.Images["app"].DockerImageDigest, "/app")
		encoded, err := json.Marshal(record)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(published).To(gomega.MatchJSON(encoded))

		ginkgo.By("building the same fixture again")
		warmReportPath := filepath.Join(fixture, "report-warm.json")
		output, err = producerRecipeRun(ctx, producerRecipeEnvironment{binary: env.binary}, fixture, "build-warm.log",
			producerRecipeBuildEnv(home, externalRefs), 1800*time.Second,
			producerRecipeBuildArgs(repo, warmReportPath)...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "warm build: %s", producerRecipeTail(output))
		gomega.Expect(output).To(gomega.ContainSubstring("Use previously built image"))

		warm := producerRecipeReport(ctx, warmReportPath)
		gomega.Expect(warm.Images["app"].DockerImageDigest).To(gomega.Equal(report.Images["app"].DockerImageDigest))
		gomega.Expect(producerRecipeFile(producerRecipeImage(ctx, warm.Images["app"]), "/app")).To(gomega.Equal(app))

		ginkgo.By("embedding an asset the proof covers with no data")
		producerRecipeWrite(filepath.Join(fixture, "primary", "lib"), "lib.go",
			goEmbedRecipeLib(append(slices.Clone(goEmbedRecipeAssets), goEmbedRecipeUnselectedAsset)))
		producerRecipeGit(ctx, fixture, "commit", "-am", "embed an asset the proof carries no data for")
		negativeReportPath := filepath.Join(fixture, "report-no-data.json")
		output, err = producerRecipeRun(ctx, producerRecipeEnvironment{binary: env.binary}, fixture, "build-no-data.log",
			producerRecipeBuildEnv(home, externalRefs), 1800*time.Second,
			producerRecipeBuildArgs(repo, negativeReportPath)...)
		gomega.Expect(err).To(gomega.HaveOccurred(), "the unattributed asset must fail the build: %s", producerRecipeTail(output))
		gomega.Expect(output).To(gomega.ContainSubstring("no-data"))
		gomega.Expect(output).To(gomega.ContainSubstring(goEmbedRecipeUnselectedAsset))
		if _, statErr := os.Stat(negativeReportPath); statErr == nil {
			gomega.Expect(producerRecipeReport(ctx, negativeReportPath).Images).NotTo(gomega.HaveKey("app"))
		}

		ginkgo.By("leaving every copied file, and every file it was copied from, as it was")
		goEmbedRecipeCheckTools(env)
	})
})
