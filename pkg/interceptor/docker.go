package interceptor

import (
	"fmt"
	"regexp"

	docker "github.com/fsouza/go-dockerclient"
)

var (
	pingRegexp           = dockerAPIEndpoint("_ping")
	authRegexp           = dockerAPIEndpoint("auth")
	buildImageRegexp     = dockerAPIEndpoint("build")
	pushImageRegexp      = dockerAPIEndpoint("images/([\\w\\-/\\:\\.]+?)/push")
	tagImageRegexp       = dockerAPIEndpoint("images/([\\w\\-/\\:\\.]+?)/tag")
	removeImageRegexp    = dockerAPIEndpoint("images/([\\w\\-/\\:\\.]+?)")
	listImagesRegexp     = dockerAPIEndpoint("images/json")
	listContainersRegexp = dockerAPIEndpoint("containers/json")
)

func dockerAPIEndpoint(endpoint string) *regexp.Regexp {
	return regexp.MustCompile("^(/v[0-9\\.]*)?/" + endpoint + "$")
}

func IsPingEndpoint(path string) bool           { return pingRegexp.MatchString(path) }
func IsAuthEndpoint(path string) bool           { return authRegexp.MatchString(path) }
func IsBuildImageEndpoint(path string) bool     { return buildImageRegexp.MatchString(path) }
func IsPushImageEndpoint(path string) bool      { return pushImageRegexp.MatchString(path) }
func IsTagImageEndpoint(path string) bool       { return tagImageRegexp.MatchString(path) }
func IsRemoveImageEndpoint(path string) bool    { return removeImageRegexp.MatchString(path) }
func IsListImagesEndpoint(path string) bool     { return listImagesRegexp.MatchString(path) }
func IsListContainersEndpoint(path string) bool { return listContainersRegexp.MatchString(path) }

func PushImageEndpointParameters(path string) (string, bool) {
	matches := pushImageRegexp.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", false
	}
	return matches[2], true
}

func TagImageEndpointParameters(path string) (string, bool) {
	matches := tagImageRegexp.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", false
	}
	return matches[2], true
}

func RemoveImageEndpointParameters(path string) (string, bool) {
	matches := removeImageRegexp.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", false
	}
	return matches[2], true
}

func ReplacePushImageEndpointParameters(path, name string) (string, bool) {
	matches := pushImageRegexp.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", false
	}
	return fmt.Sprintf("%s/images/%s/push", matches[1], name), true
}

func ReplaceTagImageEndpointParameters(path, name string) (string, bool) {
	matches := tagImageRegexp.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", false
	}
	return fmt.Sprintf("%s/images/%s/tag", matches[1], name), true
}

func ReplaceRemoveImageEndpointParameters(path, name string) (string, bool) {
	matches := removeImageRegexp.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", false
	}
	return fmt.Sprintf("%s/images/%s", matches[1], name), true
}

type BuildImageOptions struct {
	Names               []string          `qs:"t"`
	Dockerfile          string            `qs:"dockerfile"`
	NoCache             bool              `qs:"nocache"`
	SuppressOutput      bool              `qs:"q"`
	Pull                bool              `qs:"pull"`
	RmTmpContainer      bool              `qs:"rm"`
	ForceRmTmpContainer bool              `qs:"forcerm"`
	Memory              int64             `qs:"memory"`
	Memswap             int64             `qs:"memswap"`
	CPUShares           int64             `qs:"cpushares"`
	CPUQuota            int64             `qs:"cpuquota"`
	CPUPeriod           int64             `qs:"cpuperiod"`
	CPUSetCPUs          string            `qs:"cpusetcpus"`
	Labels              map[string]string `qs:"labels"`
	Remote              string            `qs:"remote"`
	ContextDir          string            `qs:"-"`
	Ulimits             []docker.ULimit   `qs:"ulimits"`
	BuildArgs           []docker.BuildArg `qs:"buildargs"`
	NetworkMode         string            `qs:"networkmode"`
	CgroupParent        string            `qs:"cgroupparent"`

	// parameters that are not in go-dockerclient yet
	ExtraHosts string   `qs:"extrahosts"`
	CPUSetMems string   `qs:"cpusetmems"`
	CacheFrom  []string `qs:"cachefrom"`
	ShmSize    int64    `qs:"shmsize"`
	Squash     bool     `qs:"squash"`
	Isolation  string   `qs:"isolation"`
}

type ListImagesOptions struct {
	All     bool                `qs:"all"`
	Filters map[string][]string `qs:"filters"`
	Digests bool                `qs:"digests"`
	Filter  string              `qs:"filter"`
}

type ListContainersOptions struct {
	All     bool                `qs:"all"`
	Size    bool                `qs:"size"`
	Limit   int                 `qs:"limit"`
	Since   string              `qs:"since"`
	Before  string              `qs:"before"`
	Filters map[string][]string `qs:"filters"`
}

type PushImageOptions struct {
	Name string `qs:"-"`
	Tag  string `qs:"tag"`
}

type ImageTagOptions struct {
	Name string `qs:"-"`
	Repo string `qs:"repo"`
	Tag  string `qs:"tag"`
}

type RemoveImageOptions struct {
	Name    string `qs:"-"`
	NoPrune bool   `qs:"noprune"`
	Force   bool   `qs:"force"`
}

type AuthOptions struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ServerAddress string `json:"serveraddress"`
}
