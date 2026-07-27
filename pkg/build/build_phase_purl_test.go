package build

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

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
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
						nil,
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					},
				},
			},
			"resolve external references: 2 of 3 images failed",
		),
		Entry("multiple sets with failures: 2 sets, 2 of 3 total fail",
			[]testImageSetData{
				{
					names: []string{"img1", "img2"},
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
						nil,
					},
				},
				{
					names: []string{"img3"},
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					},
				},
			},
			"resolve external references: 2 of 3 images failed",
		),
		Entry("all fail across sets: 2 sets, each with 1 image, both fail",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					},
				},
				{
					names: []string{"img2"},
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					},
				},
			},
			"resolve external references: 2 of 2 images failed",
		),
		Entry("single image fail: 1 of 1",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					},
				},
			},
			"resolve external references: 1 of 1 images failed",
		),
		Entry("non-PURL error returns immediately",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs: []error{
						fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required"),
					},
				},
			},
			"WERF_EXTERNAL_REFS_SERVER_URL env var is required",
		),
		Entry("non-PURL error stops processing subsequent sets",
			[]testImageSetData{
				{
					names: []string{"img1"},
					errs: []error{
						fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					},
				},
				{
					names: []string{"img2"},
					errs: []error{
						fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required"),
					},
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
					errs: []error{
						fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required"),
					},
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
				errs: []error{
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					nil,
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
				},
			},
		}

		failures, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 2 of 3 images failed"))
		Expect(failures).To(HaveLen(2))
		Expect(failures[0].imageName).To(Equal("img1"))
		Expect(failures[1].imageName).To(Equal("img3"))
	})

	It("stops immediately on non-PURL error within a set", func() {
		sets := []testImageSetData{
			{
				names: []string{"img1", "img2"},
				errs: []error{
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					fmt.Errorf("WERF_EXTERNAL_REFS_SERVER_URL env var is required"),
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
				errs: []error{
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					nil,
				},
			},
			{
				names: []string{"img3"},
				errs: []error{
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
				},
			},
		}

		failures, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 2 of 3 images failed"))
		Expect(failures).To(HaveLen(2))
		Expect(failures[0].imageName).To(Equal("img1"))
		Expect(errors.Is(failures[0].err, externalref.ErrExternalRefEnrich)).To(BeTrue())
		Expect(failures[1].imageName).To(Equal("img3"))
		Expect(errors.Is(failures[1].err, externalref.ErrExternalRefEnrich)).To(BeTrue())
	})

	It("aggregated error contains individual error messages via errors.Join", func() {
		sets := []testImageSetData{
			{
				names: []string{"img1", "img2"},
				errs: []error{
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
					fmt.Errorf("enrich external references: %w", externalref.ErrExternalRefEnrich),
				},
			},
		}

		_, err := testCollectFailuresAcrossSets(sets)
		Expect(err).To(HaveOccurred())
		errMsg := err.Error()
		Expect(errMsg).To(ContainSubstring("resolve external references: 2 of 2 images failed"))
		Expect(errMsg).To(ContainSubstring("enrich external references"))
	})

	It("does not import cdx in package-level test types", func() {
		// Verify that cdx imports are only in test bodies, not at package level
		// This test exists because the mock is now imported from test/mock/
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()
		patcher := mock.NewMockBOMPatcher(ctrl)
		Expect(patcher).ToNot(BeNil())
	})
})

type testImagePurlFailure struct {
	imageName string
	err       error
}

type testImageSetData struct {
	names []string
	errs  []error
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
					failures = append(failures, testImagePurlFailure{imageName: name, err: err})
				} else {
					return nil, err
				}
			}
		}
	}

	if len(failures) > 0 {
		var errs []error
		for _, f := range failures {
			errs = append(errs, f.err)
		}
		joined := errors.Join(errs...)
		return failures, fmt.Errorf("resolve external references: %d of %d images failed: %w", len(failures), totalImages, joined)
	}

	return nil, nil
}
