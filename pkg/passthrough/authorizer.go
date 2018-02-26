package passthrough

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"

	"github.com/openshift/image-build-daemon/pkg/interceptor"
)

// DefaultAuthorizer allows build requests to be made within the specified podUID by looking up
// a container in that pod from the Docker runtime and forcing the build to run from that container.
// It assumes a Docker runtime.
type DefaultAuthorizer struct {
	Client *docker.Client
	PodUID string
}

var (
	_ interceptor.BuildAuthorizer = &DefaultAuthorizer{}
	_ interceptor.ImageAuthorizer = &DefaultAuthorizer{}
)

func (a *DefaultAuthorizer) AuthorizeBuildRequest(ctx context.Context, build *interceptor.BuildImageOptions, auth map[string]interceptor.AuthOptions) (*interceptor.BuildImageOptions, error) {
	safeBuild, err := copySafe(build)
	if err != nil {
		return nil, err
	}
	if err := setPodSecurityInfoForBuild(ctx, a.Client, a.PodUID, safeBuild); err != nil {
		return nil, err
	}

	// TODO: names may need to be translated in the future, keep them an explicit copy
	safeBuild.Names = build.Names

	return safeBuild, nil
}

func (a *DefaultAuthorizer) AuthorizeImageAccess(ctx context.Context, names ...string) ([]string, error) {
	var internalNames []string
	for _, name := range names {
		if len(name) == 0 {
			return nil, fmt.Errorf("tag names may not be empty")
		}
		hash := sha256.New()
		if _, err := hash.Write([]byte(name)); err != nil {
			return nil, fmt.Errorf("unable to encode tag")
		}
		sum := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

		internalNames = append(internalNames, fmt.Sprintf("internalbuilder/%s:internal-%s", a.PodUID, sum))
	}
	return internalNames, nil
}

func (a *DefaultAuthorizer) ContainerFilters() map[string]string {
	return map[string]string{
		"io.kubernetes.pod.uid": a.PodUID,
	}
}

// copySafe returns only the options that have no security impact. All other fields must be explicitly copied.
func copySafe(build *interceptor.BuildImageOptions) (*interceptor.BuildImageOptions, error) {
	return &interceptor.BuildImageOptions{
		// Names
		Dockerfile:          build.Dockerfile,
		NoCache:             build.NoCache,
		SuppressOutput:      build.SuppressOutput,
		Pull:                build.Pull,
		RmTmpContainer:      build.RmTmpContainer,
		ForceRmTmpContainer: build.ForceRmTmpContainer,
		//Memory
		//Memswap
		//CPUShares
		//CPUQuota
		//CPUPeriod
		//CPUSetCPUs
		Labels:     build.Labels,
		Remote:     build.Remote,
		ContextDir: build.ContextDir,
		// Ulimits
		BuildArgs: build.BuildArgs,
		// NetworkMode
		// CgroupParent

		// parameters that are not in go-dockerclient yet
		ExtraHosts: build.ExtraHosts,
		// CPUSetMems
		// CacheFrom
		// ShmSize
		Squash: build.Squash,
		// Isolation
	}, nil
}

// setPodSecurityInfoForBuild loads one of the running containers for a given pod and takes the network mode and
// cgroup parent for that container to use with the build. It returns an error if it cannot find a container, if any
// values are missing in the container information, or if an error occurs communicating with the client.
func setPodSecurityInfoForBuild(ctx context.Context, client *docker.Client, podUID string, safeBuild *interceptor.BuildImageOptions) error {
	// find a container within the pod to use as the parent cgroup
	containers, err := client.ListContainers(docker.ListContainersOptions{
		Context: ctx,
		Filters: map[string][]string{
			"label": []string{fmt.Sprintf("io.kubernetes.pod.uid=%s", podUID)},
		},
	})
	if err != nil {
		return fmt.Errorf("could not find running containers for a pod: %v", err)
	}
	glog.V(4).Infof("Found %d running containers for pod %s", len(containers), podUID)
	for _, container := range containers {
		if container.Labels["io.kubernetes.pod.uid"] != podUID {
			continue
		}
		container, err := client.InspectContainerWithContext(container.ID, ctx)
		if err != nil {
			if _, ok := err.(*docker.NoSuchContainer); ok {
				continue
			}
			return fmt.Errorf("could not verify cgroup parent container exists: %v", err)
		}
		glog.V(5).Infof("Found container for pod %s: %#v", podUID, container)
		if container.Config.Labels["io.kubernetes.pod.uid"] != podUID {
			return fmt.Errorf("requested container by cgroup is not in the correct pod")
		}
		if len(container.HostConfig.NetworkMode) == 0 {
			return fmt.Errorf("the container does not have a limiting network mode and is not a valid build target")
		}
		if len(container.HostConfig.CgroupParent) == 0 {
			return fmt.Errorf("the container does not have a parent cgroup and is not a valid build target")
		}

		// copy the appropriate security information from the existing container into the build
		safeBuild.NetworkMode = container.HostConfig.NetworkMode
		safeBuild.CgroupParent = container.HostConfig.CgroupParent
		return nil
	}

	return fmt.Errorf("could not find a container in pod %s to verify build information", podUID)
}
