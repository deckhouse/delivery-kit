package build

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/sbom/externalref"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("PURL error aggregation", func() {
	It("detects PURL resolution errors via ErrExternalRefEnrich sentinel", func() {
		purlErr := fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)
		otherErr := fmt.Errorf("some other error")

		Expect(errors.Is(purlErr, externalref.ErrExternalRefEnrich)).To(BeTrue())
		Expect(errors.Is(otherErr, externalref.ErrExternalRefEnrich)).To(BeFalse())
	})

	DescribeTable("error aggregation scenarios",
		func(sets []testImageSetData, expectedErrContains string) {
			_, err := testCollectFailuresAcrossSets(sets)
			if expectedErrContains == "" {
				Expect(err).To(Succeed())
			} else {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrContains))
			}
		},
		Entry("happy path across multiple sets: two image sets, all succeed",
			[]testImageSetData{
				{names: []string{"img1", "img2"}, errs: []error{nil, nil}},
				{names: []string{"img3"}, errs: []error{nil}},
			},
			"",
		),
		Entry("single set mixed failures: 1 set with 3 images, 2 fail",
			[]testImageSetData{
				{
					names: []string{"img1", "img2", "img3"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich), nil, fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
					compDetail: []string{
						"  - component: apk-tools: empty url",
						"",
						"  - component: autoconf: empty url",
					},
				},
			},
			"resolve external references: 2 of 3 images failed",
		),
		Entry("multiple sets with failures: 2 sets, 2 of 3 total fail",
			[]testImageSetData{
				{
					names: []string{"img1", "img2"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich), nil},
					compDetail: []string{
						"  - component: apk-tools: empty url",
						"",
					},
				},
				{
					names: []string{"img3"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
					compDetail: []string{
						"  - component: busybox: empty url",
					},
				},
			},
			"resolve external references: 2 of 3 images failed",
		),
		Entry("all fail across sets: 2 sets, each with 1 image, both fail",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
					compDetail: []string{
						"  - component: apk-tools: empty url",
					},
				},
				{
					names: []string{"img2"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
					compDetail: []string{
						"  - component: autoconf: empty url",
					},
				},
			},
			"resolve external references: 2 of 2 images failed",
		),
		Entry("single image fail: 1 of 1",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
					compDetail: []string{
						"  - component: apk-tools: empty url",
					},
				},
			},
			"resolve external references: 1 of 1 images failed",
		),
		Entry("non-PURL error returns immediately",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs:  []error{fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required")},
				},
			},
			"WERF_EXTERNAL_REFS_SERVER_URL env var is required",
		),
		Entry("non-PURL error stops processing subsequent sets",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
					compDetail: []string{
						"  - component: apk-tools: empty url",
					},
				},
				{
					names: []string{"img2"},
					errs:  []error{fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required")},
				},
			},
			"WERF_EXTERNAL_REFS_SERVER_URL env var is required",
		),
		Entry("empty image sets: no error",
			[]testImageSetData{},
			"",
		),
		Entry("empty set followed by non-empty: non-PURL error",
			[]testImageSetData{
				{names: []string{}, errs: []error{}},
				{
					names: []string{"img1"},
					errs:  []error{fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required")},
				},
			},
			"WERF_EXTERNAL_REFS_SERVER_URL env var is required",
		),
	)

	It("MockBOMPatcher wraps errors with ErrExternalRefEnrich sentinel", func() {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()

		patcher := mock.NewMockBOMPatcher(ctrl)
		expectedErr := fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)
		patcher.EXPECT().Apply(gomock.Any(), gomock.Any()).Return(nil, expectedErr)

		_, err := patcher.Apply(nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, externalref.ErrExternalRefEnrich)).To(BeTrue())
	})

	It("MockBOMPatcher returns non-PURL errors as-is", func() {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()

		patcher := mock.NewMockBOMPatcher(ctrl)
		expectedErr := fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required")
		patcher.EXPECT().Apply(gomock.Any(), gomock.Any()).Return(nil, expectedErr)

		_, err := patcher.Apply(nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, externalref.ErrExternalRefEnrich)).To(BeFalse())
	})

	It("MockBOMPatcher returns nil on success", func() {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()

		patcher := mock.NewMockBOMPatcher(ctrl)
		patcher.EXPECT().Apply(gomock.Any(), gomock.Any()).Return(nil, nil)

		bom, err := patcher.Apply(nil, nil)
		Expect(err).To(Succeed())
		Expect(bom).To(BeNil())
	})

	It("continues processing remaining images after PURL failure within a set", func() {
		sets := []testImageSetData{
			{
				names: []string{"img1", "img2", "img3"},
				errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich), nil, fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
				compDetail: []string{
					"  - component: apk-tools: empty url",
					"",
					"  - component: autoconf: empty url",
				},
			},
		}

		failures, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 2 of 3 images failed"))
		Expect(err.Error()).To(ContainSubstring("image: img1"))
		Expect(err.Error()).To(ContainSubstring("image: img3"))
		Expect(failures).To(HaveLen(2))
		Expect(failures[0].imageName).To(Equal("img1"))
		Expect(failures[1].imageName).To(Equal("img3"))
	})

	It("stops immediately on non-PURL error within a set", func() {
		sets := []testImageSetData{
			{
				names: []string{"img1", "img2"},
				errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich), fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required")},
				compDetail: []string{
					"  - component: apk-tools: empty url",
					"",
				},
			},
		}

		_, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(MatchError("WERF_EXTERNAL_REFS_SERVER_URL env var is required"))
	})

	It("remembers individual error details from multiple sets in aggregated result", func() {
		sets := []testImageSetData{
			{
				names: []string{"img1", "img2"},
				errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich), nil},
				compDetail: []string{
					"  - component: apk-tools: empty url",
					"",
				},
			},
			{
				names: []string{"img3"},
				errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
				compDetail: []string{
					"  - component: busybox: empty url",
				},
			},
		}

		failures, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 2 of 3 images failed"))
		Expect(err.Error()).To(ContainSubstring("image: img1"))
		Expect(err.Error()).To(ContainSubstring("image: img3"))
		Expect(failures).To(HaveLen(2))
		Expect(failures[0].imageName).To(Equal("img1"))
		Expect(failures[1].imageName).To(Equal("img3"))
	})

	It("aggregated error has hierarchical format with image names", func() {
		sets := []testImageSetData{
			{
				names: []string{"img1", "img2"},
				errs:  []error{fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich), fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich)},
				compDetail: []string{
					"  - component: apk-tools: empty url",
					"  - component: openssl: empty url",
				},
			},
		}

		_, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(HaveOccurred())
		errMsg := err.Error()
		Expect(errMsg).To(ContainSubstring("resolve external references: 2 of 2 images failed"))
		Expect(errMsg).To(ContainSubstring("image: img1"))
		Expect(errMsg).To(ContainSubstring("image: img2"))
	})
})

var _ = Describe("buildAggregatedPurlError", func() {
	newPurlErrors := func(entries map[string]string) *sync.Map {
		var m sync.Map
		for name, details := range entries {
			m.Store(name, details)
		}
		return &m
	}

	It("returns nil when there are no errors", func() {
		Expect(buildAggregatedPurlError(newPurlErrors(nil), 3)).To(Succeed())
	})

	It("returns aggregated error when errors present", func() {
		err := buildAggregatedPurlError(newPurlErrors(map[string]string{
			"img1": "    - component: apk-tools: empty url\n",
		}), 1)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 1 of 1 images failed"))
	})
})

var _ = Describe("logPurlResolverHelpHint", func() {
	captureHint := func(serverURL string) string {
		if serverURL == "" {
			os.Unsetenv(externalref.EnvName)
		} else {
			GinkgoT().Setenv(externalref.EnvName, serverURL)
		}

		var output bytes.Buffer
		ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&output, &output))
		logPurlResolverHelpHint(ctx)
		return output.String()
	}

	DescribeTable("help link hint",
		func(serverURL, expectedHint string) {
			out := captureHint(serverURL)
			if expectedHint == "" {
				Expect(out).To(BeEmpty())
			} else {
				Expect(out).To(ContainSubstring("External references resolution failed"))
				Expect(out).To(ContainSubstring(expectedHint))
			}
		},
		Entry("logs help link built from env var",
			"https://refs.example.com",
			"See https://refs.example.com/help for details on resolving these errors."),
		Entry("trims trailing slash from server URL",
			"https://refs.example.com/",
			"See https://refs.example.com/help for details on resolving these errors."),
		Entry("logs nothing when env var is unset",
			"",
			""),
	)
})

type testImagePurlFailure struct {
	imageName string
	err       error
}

type testImageSetData struct {
	names      []string
	errs       []error
	compDetail []string
}

func testCollectFailuresAcrossSets(sets []testImageSetData) ([]testImagePurlFailure, error) {
	var failures []testImagePurlFailure
	totalImages := 0

	for _, set := range sets {
		totalImages += len(set.names)

		for i, name := range set.names {
			err := set.errs[i]
			if err != nil {
				if errors.Is(err, externalref.ErrExternalRefEnrich) {
					details := set.compDetail[i]
					failures = append(failures, testImagePurlFailure{
						imageName: name,
						err:       fmt.Errorf("  - image: %s:\n%s", name, details),
					})
				} else {
					return nil, err
				}
			}
		}
	}

	if len(failures) > 0 {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("resolve external references: %d of %d images failed:", len(failures), totalImages))
		for _, f := range failures {
			sb.WriteString("\n")
			sb.WriteString(strings.TrimRight(f.err.Error(), "\n"))
		}
		return failures, errors.New(sb.String())
	}

	return nil, nil
}
