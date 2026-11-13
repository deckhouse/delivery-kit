package cyclonedxutil

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("VCSURL",
	func(in, want string) { Expect(VCSURL(in)).To(Equal(want)) },
	Entry("https unchanged", "https://github.com/x/y.git", "https://github.com/x/y.git"),
	Entry("ssh unchanged", "ssh://git@github.com/x/y.git", "ssh://git@github.com/x/y.git"),
	Entry("git unchanged", "git://git.savannah.gnu.org/make.git", "git://git.savannah.gnu.org/make.git"),
	Entry("scp-style with user", "git@github.com:x/y.git", "ssh://git@github.com/x/y.git"),
	Entry("scp-style without user", "github.com:x/y.git", "ssh://github.com/x/y.git"),
	Entry("scp-style with an absolute path keeps one slash", "git@git.example.org:/srv/git/y.git", "ssh://git@git.example.org/srv/git/y.git"),
	Entry("a Windows-looking drive is not touched", "C:/repo", "C:/repo"),
	Entry("surrounding whitespace is dropped", "  https://example.com/r  ", "https://example.com/r"),
	Entry("empty stays empty", "", ""),
)
