package image

import (
	"fmt"
	"strings"
	"time"

	"github.com/distribution/reference"

	"github.com/werf/common-go/pkg/util"
)

const (
	DockerHubRepositoryPrefix      = "docker.io/library/"
	IndexDockerHubRepositoryPrefix = "index.docker.io/library/"
)

type Info struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	// FIXME remove RepoDigest from Info and use Digest everywhere instead cause it's more clear and repo part is not needed.
	// repo@sha256:digest
	RepoDigest string `json:"repoDigest"`

	OnBuild           []string            `json:"onBuild"`
	Env               []string            `json:"env"`
	ID                string              `json:"ID"`
	Labels            map[string]string   `json:"labels"`
	Size              int64               `json:"size"`
	CreatedAtUnixNano int64               `json:"createdAtUnixNano"`
	Volumes           map[string]struct{} `json:"volumes"`

	IsIndex bool
	Index   []*Info
}

func (info *Info) GetDigest() string {
	if info.RepoDigest == "" {
		return ""
	}

	parts := strings.Split(info.RepoDigest, "@")
	if len(parts) != 2 {
		panic(fmt.Sprintf("bad repo digest %q", info.RepoDigest))
	}

	return parts[1]
}

func (info *Info) SetCreatedAtUnix(seconds int64) {
	info.CreatedAtUnixNano = seconds * 1000_000_000
}

func (info *Info) SetCreatedAtUnixNano(seconds int64) {
	info.CreatedAtUnixNano = seconds
}

func (info *Info) GetCreatedAt() time.Time {
	return time.Unix(info.CreatedAtUnixNano/1000_000_000, info.CreatedAtUnixNano%1000_000_000)
}

func (info *Info) GetCopy() *Info {
	res := &Info{
		Name:              info.Name,
		Repository:        info.Repository,
		Tag:               info.Tag,
		RepoDigest:        info.RepoDigest,
		OnBuild:           util.CopyArr(info.OnBuild),
		Env:               util.CopyArr(info.Env),
		ID:                info.ID,
		Labels:            util.CopyMap(info.Labels),
		Size:              info.Size,
		CreatedAtUnixNano: info.CreatedAtUnixNano,
		Volumes:           util.CopyMap(info.Volumes),

		IsIndex: info.IsIndex,
	}

	for _, i := range info.Index {
		res.Index = append(res.Index, i.GetCopy())
	}

	return res
}

func (info *Info) LogName() string {
	if info.Name == "<none>:<none>" {
		return info.ID
	} else {
		return info.Name
	}
}

func MustParseTimestampString(timestampString string) time.Time {
	t, err := time.Parse(time.RFC3339, timestampString)
	if err != nil {
		panic(fmt.Sprintf("got bad timestamp %q: %s", timestampString, err))
	}
	return t
}

func ParseRepositoryAndTag(ref string) (string, string) {
	repository, tag, _ := ParseRef(ref)
	return repository, tag
}

// ParseRef splits an image reference into repository, tag and digest, handling
// every reference form: "repo", "repo:tag", "repo@algo:hex", "repo:tag@algo:hex".
// A reference that is not a valid distribution reference (e.g. werf-internal
// names with uppercase characters) keeps the historical last-colon split, since
// the result participates in stage digests and must stay stable.
func ParseRef(ref string) (repository, tag, digest string) {
	parsed, err := reference.Parse(ref)
	if err != nil {
		repository, tag = splitRepositoryAndTagLegacy(ref)
		return repository, tag, ""
	}

	if named, ok := parsed.(reference.Named); ok {
		repository = named.Name()
	}
	if tagged, ok := parsed.(reference.Tagged); ok {
		tag = tagged.Tag()
	}
	if digested, ok := parsed.(reference.Digested); ok {
		digest = digested.Digest().String()
	}
	return repository, tag, digest
}

func splitRepositoryAndTagLegacy(ref string) (string, string) {
	parts := strings.SplitN(util.Reverse(ref), ":", 2)
	if len(parts) != 2 {
		return ref, ""
	}
	return util.Reverse(parts[1]), util.Reverse(parts[0])
}

func NormalizeRepository(repository string) (res string) {
	res = repository
	res = strings.TrimPrefix(res, IndexDockerHubRepositoryPrefix)
	res = strings.TrimPrefix(res, DockerHubRepositoryPrefix)
	return
}

// ExtractRepoDigest return repo@digest from the list.
func ExtractRepoDigest(inspectRepoDigests []string, repository string) string {
	for _, inspectRepoDigest := range inspectRepoDigests {
		repoAndDigest := strings.SplitN(inspectRepoDigest, "@sha256:", 2)
		repo := NormalizeRepository(repoAndDigest[0])
		if len(repoAndDigest) == 2 && NormalizeRepository(repository) == repo {
			return fmt.Sprintf("%s@sha256:%s", repo, repoAndDigest[1])
		}
	}
	return ""
}
