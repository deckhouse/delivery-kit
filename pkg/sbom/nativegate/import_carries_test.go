package nativegate

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("What an import carries", func() {
	carries := func(scope ImportScope, path string) bool {
		ginkgo.GinkgoHelper()
		answer, err := ImportCarries(scope, path)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		return answer
	}

	ginkgo.It("carries what the directive copies and nothing beside it", func() {
		scope := ImportScope{FromPath: "/app/bin", ToPath: "/usr/local/bin"}

		gomega.Expect(carries(scope, "/app/bin/tool")).To(gomega.BeTrue())
		gomega.Expect(carries(scope, "/app/bin/nested/tool")).To(gomega.BeTrue())
		gomega.Expect(carries(scope, "/app/etc/conf")).To(gomega.BeFalse())
		gomega.Expect(carries(scope, "/app/binary")).To(gomega.BeFalse(), "a sibling whose name starts the same is not under the import")
	})

	// A directive naming one file copies that file or nothing: its filters are written
	// against the file's own root rather than against a tree below it.
	ginkgo.It("carries the one file a file import names", func() {
		scope := ImportScope{FromPath: "/app/bin/tool", ToPath: "/usr/local/bin/tool"}

		gomega.Expect(carries(scope, "/app/bin/tool")).To(gomega.BeTrue())
		gomega.Expect(carries(scope, "/app/bin/other")).To(gomega.BeFalse())

		excluded := ImportScope{FromPath: "/app/bin/tool", ToPath: "/usr/local/bin/tool", ExcludePaths: []string{"."}}
		gomega.Expect(carries(excluded, "/app/bin/tool")).To(gomega.BeFalse())
	})

	// The two backends read one directive differently: the subtree copy takes a matched
	// directory whole, while rsync keeps applying the exclusions inside it.
	ginkgo.It("reads the include and exclude paths as the backend of the copy does", func() {
		directive := func(backend ImportBackend) ImportScope {
			return ImportScope{
				Backend:      backend,
				FromPath:     "/app",
				ToPath:       "/opt/app",
				IncludePaths: []string{"bin"},
				ExcludePaths: []string{"bin/secret"},
			}
		}

		gomega.Expect(carries(directive(ImportBackendCopyRecurse), "/app/bin/tool")).To(gomega.BeTrue())
		gomega.Expect(carries(directive(ImportBackendCopyRecurse), "/app/bin/secret")).To(gomega.BeTrue())
		gomega.Expect(carries(directive(ImportBackendCopyRecurse), "/app/etc/conf")).To(gomega.BeFalse())

		gomega.Expect(carries(directive(ImportBackendRsync), "/app/bin/tool")).To(gomega.BeTrue())
		gomega.Expect(carries(directive(ImportBackendRsync), "/app/bin/secret")).To(gomega.BeFalse())
		gomega.Expect(carries(directive(ImportBackendRsync), "/app/etc/conf")).To(gomega.BeFalse())
	})

	ginkgo.It("answers nothing where there is no copy to read", func() {
		_, err := ImportCarries(ImportScope{FromPath: "/app"}, "/app/bin/tool")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: the import scope carries no copy")))

		_, err = ImportCarries(ImportScope{Backend: "other", FromPath: "/app", ToPath: "/opt"}, "/app/bin/tool")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unknown copy backend")))
	})
})
