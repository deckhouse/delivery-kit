package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective ruby", func() {
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

		Entry("ruby-bundler defaults to Gemfile and Gemfile.lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-bundler", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeRubyBundler,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "Gemfile",
						Lock:    "Gemfile.lock",
					},
				},
			},
		),

		Entry("ruby-bundler with explicit spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-bundler", "workdir": "/app", "spec": "gemfiles/Gemfile", "lock": "gemfiles/Gemfile.lock"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeRubyBundler,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "gemfiles/Gemfile",
						Lock:    "gemfiles/Gemfile.lock",
					},
				},
			},
		),

		Entry("ruby-bundler with a spec named otherwise defaults the lock to <spec>.lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-bundler", "workdir": "/app", "spec": "gemfiles/rails7.gemfile"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeRubyBundler,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "gemfiles/rails7.gemfile",
						Lock:    "gemfiles/rails7.gemfile.lock",
					},
				},
			},
		),

		Entry("ruby-gemspec keeps empty lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-gemspec", "workdir": "/app", "spec": "app.gemspec"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeRubyGemspec,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "app.gemspec",
						Lock:    "",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails",
		func(ctx SpecContext, yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("ruby-bundler without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-bundler"},
				},
			},
		),

		Entry("ruby-gemspec without spec (no default gemspec name)",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-gemspec", "workdir": "/app"},
				},
			},
		),

		Entry("ruby-gemspec with lock is rejected (no lock semantics)",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "ruby-gemspec", "workdir": "/app", "spec": "app.gemspec", "lock": "Gemfile.lock"},
				},
			},
		),

		Entry("bundler alias is rejected (aliases not supported)",
			map[string]interface{}{
				"image": "image1",
				"from":  "ruby:3.4",
				"packages": []map[string]interface{}{
					{"type": "bundler", "workdir": "/app"},
				},
			},
		),
	)
})

var _ = Describe("ruby install commands", func() {
	It("installs a bundle frozen to its lock", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRubyBundler, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Gemfile", Lock: "Gemfile.lock"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && BUNDLE_FROZEN=true bundle install`}))
	})

	It("lets the directive env override the frozen default", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRubyBundler, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Gemfile"}, Env: map[string]string{"BUNDLE_FROZEN": "false"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && BUNDLE_FROZEN=false bundle install`}))
	})

	It("runs the bundler the preceding entry installed", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRubyBundler, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Gemfile", Manager: "/opt/tools/bin/bundle"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && BUNDLE_FROZEN=true "/opt/tools/bin/bundle" install`}))
	})

	It("builds and installs the gem a gemspec describes", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRubyGemspec, FileBased: FileBasedSpec{Workdir: "/app", Spec: "gemspecs/app.gemspec"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && gem build "gemspecs/app.gemspec" -o "/tmp/app.gem" && gem install --no-document "/tmp/app.gem"`}))
	})

	It("passes the directive env to the gem install, not to the build", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRubyGemspec, FileBased: FileBasedSpec{Workdir: "/app", Spec: "app.gemspec"}, Env: map[string]string{"GEM_HOME": "/vendor"}},
		})
		Expect(cmds).To(Equal([]string{`cd "/app" && gem build "app.gemspec" -o "/tmp/app.gem" && GEM_HOME=/vendor gem install --no-document "/tmp/app.gem"`}))
	})
})
