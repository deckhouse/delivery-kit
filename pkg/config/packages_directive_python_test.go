package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective python", func() {
	var localGitRepo *LocalGitRepoStub
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		localGitRepo = NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0")
		giterminismManager = NewGiterminismManagerStub(localGitRepo)
	})

	DescribeTable("unmarshal and convert succeed",
		func(ctx SpecContext, yamlMap map[string]interface{}, expected []*PackagesDirective) {
			packages, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].FileBased).To(Equal(exp.FileBased))
			}
		},

		Entry("python-uv with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-uv", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonUV,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "pyproject.toml",
						Lock:    "uv.lock",
					},
				},
			},
		),

		Entry("python-pip with only workdir defaults spec and empty lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-pip", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonPip,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "requirements.txt",
						Lock:    "",
					},
				},
			},
		),

		Entry("python-poetry with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-poetry", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonPoetry,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "pyproject.toml",
						Lock:    "poetry.lock",
					},
				},
			},
		),

		Entry("python-uv with explicit spec and lock overrides defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{
						"type":    "python-uv",
						"workdir": "/app",
						"spec":    "custom.toml",
						"lock":    "custom.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonUV,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "custom.toml",
						Lock:    "custom.lock",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails when required fields are missing",
		func(ctx SpecContext, yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("python-uv without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-uv"},
				},
			},
		),

		Entry("python-pip with spec as list instead of string",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{
						"type":    "python-pip",
						"workdir": "/app",
						"spec":    []string{"requests"},
					},
				},
			},
		),

		Entry("unknown type is rejected",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "pythonn-uv", "workdir": "/app"},
				},
			},
		),

		Entry("python-pip with lock field is rejected (pip has no lock semantics)",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{
						"type":    "python-pip",
						"workdir": "/app",
						"lock":    "requirements.lock",
					},
				},
			},
		),
	)
})

var _ = Describe("python install commands", func() {
	It("installs a poetry project without its root package", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Lock: "poetry.lock"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && test -f "poetry.lock" || { echo 'lock file poetry.lock not found in /app; the packages stage installs only what the lock pins, commit it' >&2; exit 1; } && poetry install --no-root`}))
	})

	It("syncs a uv project without downloading an interpreter", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Lock: "uv.lock"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && test -f "uv.lock" || { echo 'lock file uv.lock not found in /app; the packages stage installs only what the lock pins, commit it' >&2; exit 1; } && UV_PYTHON_DOWNLOADS=never uv sync --frozen`}))
	})

	It("lets the directive env override the uv python downloads default", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"UV_PYTHON_DOWNLOADS": "automatic"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && UV_PYTHON_DOWNLOADS=automatic uv sync --frozen`}))
	})

	It("runs the uv the preceding entry installed", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Manager: "/opt/tools/bin/uv"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && UV_PYTHON_DOWNLOADS=never "/opt/tools/bin/uv" sync --frozen`}))
	})
})

var _ = Describe("lock file guard", func() {
	It("fails the stage before installing when the lock is absent", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Lock: "poetry.lock"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && test -f "poetry.lock" || { echo 'lock file poetry.lock not found in /app; the packages stage installs only what the lock pins, commit it' >&2; exit 1; } && poetry install --no-root`}))
	})

	It("keeps the guard ahead of the env assignments a secret needs", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Lock: "uv.lock"}, Env: map[string]string{"UV_INDEX_URL": "%secret:INDEX%"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && test -f "uv.lock" || { echo 'lock file uv.lock not found in /app; the packages stage installs only what the lock pins, commit it' >&2; exit 1; } && (UV_INDEX_URL="$(</run/secrets/INDEX)"; UV_INDEX_URL="$UV_INDEX_URL" UV_PYTHON_DOWNLOADS=never uv sync --frozen)`}))
	})

	It("guards a lock named otherwise under the given name", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRubyBundler, FileBased: FileBasedSpec{Workdir: "/app", Spec: "gemfiles/rails7.gemfile", Lock: "gemfiles/rails7.gemfile.lock"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && test -f "gemfiles/rails7.gemfile.lock" || { echo 'lock file gemfiles/rails7.gemfile.lock not found in /app; the packages stage installs only what the lock pins, commit it' >&2; exit 1; } && BUNDLE_FROZEN=true BUNDLE_GEMFILE=gemfiles/rails7.gemfile bundle install`}))
	})

	It("leaves ecosystems without a lock unguarded", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}},
			{Type: PackagesDirectiveTypeLuaRock, FileBased: FileBasedSpec{Workdir: "/app", Spec: "app-0.1-1.rockspec"}},
			{Type: PackagesDirectiveTypeRubyGemspec, FileBased: FileBasedSpec{Workdir: "/app", Spec: "app.gemspec"}},
		})
		for _, cmd := range cmds {
			Expect(cmd).NotTo(ContainSubstring("test -f"))
		}
	})
})
