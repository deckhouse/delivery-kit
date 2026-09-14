package suite_init

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/utils"
)

// ContainersStorageData gives every ginkgo process its own rootless
// containers-storage. Native Buildah resolves the graph root from
// XDG_DATA_HOME and the run root from XDG_RUNTIME_DIR, so without this every
// parallel spec on the host shares one image graph and races on it.
type ContainersStorageData struct {
	Dir string
}

func NewContainersStorageData(callbacks *SynchronizedSuiteCallbacksData) *ContainersStorageData {
	data := &ContainersStorageData{}

	callbacks.AppendSynchronizedBeforeSuiteAllNodesFunc(func(_ context.Context, _ []byte) {
		if runtime.GOOS != "linux" {
			return
		}

		// Under $HOME rather than $TMPDIR: the latter is often tmpfs, and the
		// overlay driver choice depends on the filesystem the graph lives on.
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())

		data.Dir, err = os.MkdirTemp(home, ".werf-test-containers-storage-*")
		Expect(err).NotTo(HaveOccurred())

		dataHome := filepath.Join(data.Dir, "share")
		runtimeDir := filepath.Join(data.Dir, "run")
		Expect(os.Mkdir(dataHome, 0o755)).To(Succeed())
		Expect(os.Mkdir(runtimeDir, 0o700)).To(Succeed())
		Expect(os.Setenv("XDG_DATA_HOME", dataHome)).To(Succeed())
		Expect(os.Setenv("XDG_RUNTIME_DIR", runtimeDir)).To(Succeed())
	})

	callbacks.AppendSynchronizedAfterSuiteAllNodesFunc(func(ctx context.Context) {
		if data.Dir == "" {
			return
		}
		// Rootless storage holds files owned by mapped sub-UIDs, which a plain
		// RemoveAll from the parent process cannot delete.
		utils.RunSucceedCommand(ctx, "", "buildah", "unshare", "rm", "-rf", data.Dir)
	})

	return data
}
