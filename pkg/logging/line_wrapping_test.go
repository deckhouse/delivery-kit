package logging_test

import (
	"bytes"
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/logging"
)

var _ = Describe("DoWithoutLineWrapping", func() {
	var ctx context.Context

	BeforeEach(func() {
		var out bytes.Buffer
		ctx = logboek.NewContext(context.Background(), logboek.NewLogger(&out, &out))
	})

	DescribeTable("restores the mode the caller had",
		func(enabledBefore bool) {
			streams := logboek.Context(ctx).Streams()
			if enabledBefore {
				streams.EnableLineWrapping()
			} else {
				streams.DisableLineWrapping()
			}

			logging.DoWithoutLineWrapping(ctx, func() {
				Expect(logboek.Context(ctx).Streams().IsLineWrappingEnabled()).To(BeFalse())
			})

			Expect(streams.IsLineWrappingEnabled()).To(Equal(enabledBefore))
		},
		Entry("wrapping enabled before the call", true),
		Entry("wrapping already disabled before the call", false),
	)
})
