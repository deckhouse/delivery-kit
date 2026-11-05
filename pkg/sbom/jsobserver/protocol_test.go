package jsobserver

import (
	"encoding/json"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestJSObserver(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "JavaScript Observer Suite")
}

var _ = ginkgo.Describe("JavaScript observer protocol", func() {
	ginkgo.It("round trips owners separately for each output", func() {
		data := []byte(`{"version":1,"outputs":[{"path":"/app/dist/a.js","digest":"sha256:a","packages":[{"name":"@scope/first","version":"1.0.0"}]},{"path":"/app/dist/b.js","digest":"sha256:b","packages":[{"name":"second","version":"2.0.0"}]}]}`)
		var event Event
		gomega.Expect(json.Unmarshal(data, &event)).To(gomega.Succeed())
		gomega.Expect(event.Version).To(gomega.Equal(ProtocolVersion))
		gomega.Expect(event.Outputs).To(gomega.Equal([]Output{
			{Path: "/app/dist/a.js", Digest: "sha256:a", Packages: []Package{{Name: "@scope/first", Version: "1.0.0"}}},
			{Path: "/app/dist/b.js", Digest: "sha256:b", Packages: []Package{{Name: "second", Version: "2.0.0"}}},
		}))
		encoded, err := json.Marshal(event)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(encoded).To(gomega.MatchJSON(string(data)))
	})

	ginkgo.It("does not turn diagnostics into output evidence", func() {
		var event Event
		gomega.Expect(json.Unmarshal([]byte(`{"version":1,"warning":"unsupported Node runtime"}`), &event)).To(gomega.Succeed())
		gomega.Expect(event.Outputs).To(gomega.BeEmpty())
		gomega.Expect(event.Warning).To(gomega.Equal("unsupported Node runtime"))
	})
})
