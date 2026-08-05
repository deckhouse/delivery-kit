package artifact

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo/parallel"
)

var _ = Describe("getTagMutex", func() {
	It("should serialize concurrent access for the same key", func() {
		key := "test-key"
		m1 := getTagMutex(key)
		m2 := getTagMutex(key)

		Expect(m1).To(BeIdenticalTo(m2), "same key should return the same mutex pointer")

		m1.Lock()
		locked := make(chan struct{})
		go func() {
			m2.Lock()
			close(locked)
			m2.Unlock()
		}()

		Consistently(locked, "50ms").ShouldNot(BeClosed(), "second goroutine should block")
		m1.Unlock()
		Eventually(locked).Should(BeClosed(), "second goroutine should acquire lock after release")
	})

	It("should return different mutexes for different keys", func() {
		m1 := getTagMutex("key-a")
		m2 := getTagMutex("key-b")
		Expect(m1).ToNot(BeIdenticalTo(m2))
	})

	It("should be safe under concurrent calls", func() {
		keys := []string{"a", "b", "c", "d", "e"}
		parallel.Times(100, func(i int) struct{} {
			_ = getTagMutex(keys[i%len(keys)])
			return struct{}{}
		})
	})
})

var _ = Describe("tagMutexKey", func() {
	It("should produce deterministic key from repo and parentDigest", func() {
		key1 := tagMutexKey("registry.example.com/app", "sha256:abc123def456")
		key2 := tagMutexKey("registry.example.com/app", "sha256:abc123def456")
		Expect(key1).To(Equal(key2))
	})

	It("should produce different keys for different repositories", func() {
		key1 := tagMutexKey("registry.example.com/app-a", "sha256:abc123")
		key2 := tagMutexKey("registry.example.com/app-b", "sha256:abc123")
		Expect(key1).ToNot(Equal(key2))
	})

	It("should produce different keys for different parent digests", func() {
		key1 := tagMutexKey("registry.example.com/app", "sha256:abc123")
		key2 := tagMutexKey("registry.example.com/app", "sha256:def456")
		Expect(key1).ToNot(Equal(key2))
	})
})
