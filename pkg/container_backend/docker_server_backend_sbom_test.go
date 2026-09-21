package container_backend

import (
	"errors"
	"fmt"

	"github.com/docker/cli/cli"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DockerServerBackend GenerateSBOM", func() {
	DescribeTable("scannerRunErr",
		func(err error, output, expectedMessage string) {
			wrapped := scannerRunErr(err, output)
			Expect(wrapped.Error()).To(Equal(expectedMessage))
			Expect(errors.Is(wrapped, err)).To(BeTrue())
		},
		Entry("a message-less status error with scanner output carries both the code and the output",
			cli.StatusError{StatusCode: 1},
			"[0012] ERROR could not determine source: no space left on device\n",
			"run scanner: exit code 1: [0012] ERROR could not determine source: no space left on device"),
		Entry("a message-less status error without output carries the code alone",
			cli.StatusError{StatusCode: 125}, "   \n",
			"run scanner: exit code 125"),
		Entry("a status error with a message keeps it",
			cli.StatusError{StatusCode: 125, Status: "no such image"}, "",
			"run scanner: no such image"),
		Entry("any other error is left alone and still gets the output",
			fmt.Errorf("dial docker socket: %w", errors.New("connection refused")), "some output",
			"run scanner: dial docker socket: connection refused: some output"),
	)

	It("keeps the exit code reachable through the wrapping", func() {
		wrapped := scannerRunErr(cli.StatusError{StatusCode: 1}, "boom")
		code, ok := containerExitCode(wrapped)
		Expect(ok).To(BeTrue())
		Expect(code).To(Equal(1))
	})
})
