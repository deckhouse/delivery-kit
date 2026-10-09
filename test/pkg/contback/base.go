package contback

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/onsi/ginkgo/v2"

	"github.com/werf/werf/v3/pkg/buildah/thirdparty"
)

type BaseContainerBackend struct {
	CommonCliArgs []string
	Isolation     thirdparty.Isolation
}

func expectCmdsToSucceed(ctx context.Context, r ContainerBackend, image string, cmds ...string) {
	containerName := uuid.New().String()
	ginkgo.DeferCleanup(func(cleanupCtx ginkgo.SpecContext) {
		r.Rm(cleanupCtx, containerName)
	}, ginkgo.NodeTimeout(time.Minute))
	r.RunSleepingContainer(ctx, containerName, image)
	r.Exec(ctx, containerName, cmds...)
}
