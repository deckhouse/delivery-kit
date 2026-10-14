package attestation

import (
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = Describe("reading an attestation kind", func() {
	const (
		imageName = "app"

		werfOwn  = `{"doc":"werf"}`
		userOwn  = `{"doc":"user"}`
		notFound = "no attestation of the requested predicate type found"
		unsigned = "present but unsigned (legacy format)"
	)

	var (
		server       *httptest.Server
		repo         string
		parentDigest string
		store        *artifact.OCIStore
		signer       signature.Signer
		verifier     signature.Verifier
		otherSigner  signature.Signer
	)

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		repo = strings.TrimPrefix(server.URL, "http://") + "/test/app"

		parent, err := random.Image(256, 1)
		Expect(err).To(Succeed())
		parentRef, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(parentRef, parent, remote.WithContext(ctx))).To(Succeed())
		dgst, err := parent.Digest()
		Expect(err).To(Succeed())
		parentDigest = dgst.String()

		store = artifact.NewOCIStore(repo, imageName)
		signer, verifier = generateKeyPair()
		otherSigner, _ = generateKeyPair()
	})

	AfterEach(func() {
		server.Close()
	})

	envelopeOf := func(ctx SpecContext, predicate, predicateType string, withSignature bool) []byte {
		digestHex, err := artifact.DigestHex(parentDigest)
		Expect(err).To(Succeed())
		stmtBytes, err := WrapInInTotoStatement([]byte(predicate), predicateType, repo, digestHex)
		Expect(err).To(Succeed())
		envelopeSigner := signer
		if !withSignature {
			envelopeSigner = nil
		}
		envelopeJSON, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, envelopeSigner)
		Expect(err).To(Succeed())
		return envelopeJSON
	}

	attachWerfUnsigned := func(ctx SpecContext, kind PredicateKind, annotation string) {
		envelopeJSON := envelopeOf(ctx, werfOwn, kind.UnsignedType, false)
		Expect(store.Attach(ctx, parentDigest, DSSEMediaType, envelopeJSON, "checksum-v1", "", annotation)).To(Succeed())
	}

	attachWerfSigned := func(ctx SpecContext, kind PredicateKind) {
		envelopeJSON := envelopeOf(ctx, werfOwn, kind.SignedType, true)
		pubKey, err := signer.PublicKey()
		Expect(err).To(Succeed())
		bundleBytes, err := WrapInBundle(envelopeJSON, pubKey)
		Expect(err).To(Succeed())
		Expect(store.Attach(ctx, parentDigest, BundleMediaType, bundleBytes, "checksum-v1", "", kind.SignedType)).To(Succeed())
	}

	attachUserSigned := func(ctx SpecContext, predicateType string, userSigner signature.Signer) {
		Expect(Sign(ctx, []byte(userOwn), predicateType, repo, parentDigest, imageName, userSigner)).To(Succeed())
	}

	publishWerf := func(ctx SpecContext, kind PredicateKind, werfSigner signature.Signer) {
		Expect(PublishAttestation(ctx, kind, []byte(werfOwn), repo, parentDigest, imageName, PublishAttestationOptions{
			Signer:   werfSigner,
			Checksum: "checksum-v1",
		})).To(Succeed())
	}

	buildState := func(ctx SpecContext, kind PredicateKind, state string) {
		for _, part := range strings.Split(state, "+") {
			switch part {
			case "":
			case "werf-unsigned":
				attachWerfUnsigned(ctx, kind, kind.UnsignedType)
			case "werf-signed":
				attachWerfSigned(ctx, kind)
			case "user-signed":
				attachUserSigned(ctx, kind.SignedType, signer)
			case "user-signed-short-name":
				attachUserSigned(ctx, kind.Name, signer)
			case "user-signed-other-key":
				attachUserSigned(ctx, kind.SignedType, otherSigner)
			case "werf-build-unsigned":
				publishWerf(ctx, kind, nil)
			case "legacy":
				attachWerfUnsigned(ctx, kind, "")
			default:
				Fail("unknown state part " + part)
			}
		}
	}

	DescribeTable("answers get by the predicate type asked for",
		func(ctx SpecContext, kind PredicateKind, state, request, expected string) {
			buildState(ctx, kind, state)

			predicate, err := Get(ctx, repo, parentDigest, imageName, request)
			if expected == werfOwn || expected == userOwn {
				Expect(err).To(Succeed())
				Expect(predicate).To(MatchJSON(expected))
				return
			}
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(expected))
		},
		Entry("cyclonedx: nothing attached", PredicateKindCycloneDX, "", "cyclonedx", notFound),
		Entry("cyclonedx: nothing attached, signed URI", PredicateKindCycloneDX, "", PredicateKindCycloneDX.SignedType, notFound),
		Entry("cyclonedx: nothing attached, unsigned URI", PredicateKindCycloneDX, "", PredicateKindCycloneDX.UnsignedType, notFound),

		Entry("cyclonedx: unsigned build, short name reports the type it found", PredicateKindCycloneDX, "werf-unsigned", "cyclonedx", `does not match requested`),
		Entry("cyclonedx: unsigned build, unsigned URI returns werf's document", PredicateKindCycloneDX, "werf-unsigned", PredicateKindCycloneDX.UnsignedType, werfOwn),

		Entry("cyclonedx: signed build, short name returns werf's document", PredicateKindCycloneDX, "werf-signed", "cyclonedx", werfOwn),
		Entry("cyclonedx: signed build, unsigned URI reports the type it found", PredicateKindCycloneDX, "werf-signed", PredicateKindCycloneDX.UnsignedType, `does not match requested`),

		Entry("cyclonedx: user attestation alone, short name returns it", PredicateKindCycloneDX, "user-signed", "cyclonedx", userOwn),

		Entry("cyclonedx: user attestation beside an unsigned build, short name returns the user's", PredicateKindCycloneDX, "werf-unsigned+user-signed", "cyclonedx", userOwn),
		Entry("cyclonedx: user attestation beside an unsigned build, unsigned URI returns werf's", PredicateKindCycloneDX, "werf-unsigned+user-signed", PredicateKindCycloneDX.UnsignedType, werfOwn),
		Entry("cyclonedx: user attestation beside a signed build, short name returns werf's", PredicateKindCycloneDX, "werf-signed+user-signed", "cyclonedx", werfOwn),

		Entry("cyclonedx: legacy annotation-less entry, unsigned URI returns it", PredicateKindCycloneDX, "legacy", PredicateKindCycloneDX.UnsignedType, werfOwn),

		Entry("openvex: short name resolves to the versioned URI of an unsigned build", PredicateKindOpenVEX, "werf-unsigned", "openvex", werfOwn),
		Entry("openvex: short name returns werf's signed document", PredicateKindOpenVEX, "werf-signed", "openvex", werfOwn),
		Entry("openvex: user attestation alone", PredicateKindOpenVEX, "user-signed", "openvex", userOwn),
		Entry("openvex: user attestation beside an unsigned build, short name returns werf's", PredicateKindOpenVEX, "werf-unsigned+user-signed", "openvex", werfOwn),
		Entry("openvex: user attestation beside an unsigned build, unversioned URI returns the user's", PredicateKindOpenVEX, "werf-unsigned+user-signed", PredicateKindOpenVEX.SignedType, userOwn),
		Entry("openvex: legacy annotation-less entry", PredicateKindOpenVEX, "legacy", "openvex", werfOwn),

		Entry("cyclonedx: a build does not replace what the user signed under the short name", PredicateKindCycloneDX, "user-signed-short-name+werf-build-unsigned", "cyclonedx", userOwn),
		Entry("openvex: a build replaces what the user signed under the short name, which shares its slot", PredicateKindOpenVEX, "user-signed-short-name+werf-build-unsigned", "openvex", werfOwn),
		Entry("openvex: a build does not replace what the user signed under the unversioned URI", PredicateKindOpenVEX, "user-signed+werf-build-unsigned", PredicateKindOpenVEX.SignedType, userOwn),
	)

	DescribeTable("answers verify by the predicate type asked for",
		func(ctx SpecContext, kind PredicateKind, state, request, expected string) {
			buildState(ctx, kind, state)

			predicate, err := Verify(ctx, repo, parentDigest, imageName, request, []signature.Verifier{verifier})
			if expected == werfOwn || expected == userOwn {
				Expect(err).To(Succeed())
				Expect(predicate).To(MatchJSON(expected))
				return
			}
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(expected))
		},
		Entry("cyclonedx: nothing attached", PredicateKindCycloneDX, "", "cyclonedx", notFound),
		Entry("cyclonedx: unsigned build keeps the rebuild hint", PredicateKindCycloneDX, "werf-unsigned", "cyclonedx", unsigned),
		Entry("cyclonedx: legacy annotation-less entry keeps the rebuild hint", PredicateKindCycloneDX, "legacy", "cyclonedx", unsigned),
		Entry("cyclonedx: signed build verifies", PredicateKindCycloneDX, "werf-signed", "cyclonedx", werfOwn),
		Entry("cyclonedx: user attestation alone verifies", PredicateKindCycloneDX, "user-signed", "cyclonedx", userOwn),
		Entry("cyclonedx: user attestation beside an unsigned build verifies", PredicateKindCycloneDX, "werf-unsigned+user-signed", "cyclonedx", userOwn),
		Entry("cyclonedx: user attestation beside a signed build verifies werf's", PredicateKindCycloneDX, "werf-signed+user-signed", "cyclonedx", werfOwn),

		Entry("openvex: unsigned build keeps the rebuild hint", PredicateKindOpenVEX, "werf-unsigned", "openvex", unsigned),
		Entry("openvex: signed build verifies", PredicateKindOpenVEX, "werf-signed", "openvex", werfOwn),
		Entry("openvex: user attestation beside an unsigned build verifies the signed neighbor", PredicateKindOpenVEX, "werf-unsigned+user-signed", "openvex", userOwn),
		Entry("openvex: a neighbor signed by another key reports the signature failure, not the rebuild hint", PredicateKindOpenVEX, "werf-unsigned+user-signed-other-key", "openvex", "verify DSSE signature"),
	)
})
