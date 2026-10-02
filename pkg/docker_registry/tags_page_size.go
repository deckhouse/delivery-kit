package docker_registry

import (
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const (
	defaultTagsPageSize  = 1_000_000
	fallbackTagsPageSize = 1000

	publicAwsEcrHost = "public.ecr.aws"

	paginationNumberInvalidErrorCode transport.ErrorCode = "PAGINATION_NUMBER_INVALID"
)

// ECR rejects pages larger than its own limit with an UNSUPPORTED diagnostic instead of the
// pagination error code: https://github.com/google/go-containerregistry/issues/681
var awsEcrMaxResultsRejectionRegexp = regexp.MustCompile(`(?i)parameter at 'maxresults'.*less than or equal to \d+`)

var fallbackTagsPageSizeHosts sync.Map

func tagsPageSizeForRegistryHost(registryHost string) int {
	if isAwsEcrRegistryHost(registryHost) {
		return fallbackTagsPageSize
	}

	if _, capped := fallbackTagsPageSizeHosts.Load(registryHost); capped {
		return fallbackTagsPageSize
	}

	return defaultTagsPageSize
}

func isAwsEcrRegistryHost(registryHost string) bool {
	hostname := registryHost
	if host, _, err := net.SplitHostPort(registryHost); err == nil {
		hostname = host
	}

	return hostname == publicAwsEcrHost || awsEcrPatternRegexp.MatchString(hostname)
}

func isTagsPageSizeRejectedErr(err error) bool {
	var registryErr *transport.Error
	if !errors.As(err, &registryErr) {
		return false
	}

	switch registryErr.StatusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
	default:
		return false
	}

	if req := registryErr.Request; req != nil {
		if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/tags/list") {
			return false
		}
	}

	for _, diagnostic := range registryErr.Errors {
		if diagnostic.Code == paginationNumberInvalidErrorCode {
			return true
		}
		if awsEcrMaxResultsRejectionRegexp.MatchString(diagnostic.Message) {
			return true
		}
	}

	return false
}
