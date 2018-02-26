image-build-daemon
==================

This project is in early `alpha` and may change significantly in the
future.

The image-build-daemon acts as a Kubernetes-aware Docker build endpoint
that limits what operations clients can perform to a safe subset and
ensures the resources those clients consume are charged back to their
pod. It automatically injects a Docker-API compatible unix domain socket
into any pod that mounts a read-write emptydir to `/var/run/docker/`,
and then accepts the following Docker API calls:

* `build`: Perform Docker builds that are placed into the calling pod's
  cgroup
* `tag`: Tag an image that was created by a build with a different name
* `list-images`: List any images built by this pod
* `remove-image`: Remove an image created by this pod
* `push`: Push an image created by this pod

The daemon performs cleanup, quota, and scoping to the calling pod,
ensuring that resources consumed by a build pod are fairly used. The
normal Docker CLI or API client can create operations, although not all
parameters are supported.

The daemon also supports multiple backends with the future goal of
removing the need for a Docker daemon on the host, specified with
`--mode`:

* `passthrough` - Use the host's Docker socket to perform operations
* `imagebuilder` - Use the
  [imagebuilder](https://github.com/openshift/imagebuilder) library to
perform more efficient builds
* FUTURE: `buildah` - Avoid using a shared daemon and instead execute
  builds under the calling pod's context.

## Trying it out

Clone the source into your GOPATH and build with:

    make

To test locally without a running Kubernetes server, start your Docker 
daemon and then run:

    ./image-build-daemon -v=5 --bind-local=/tmp &

To start the daemon running in the background. Then launch a fake
Kubernetes container with

    make fake

The container named `daemon-test` will be started, and 
`image-build-daemon` will create `/tmp/docker.sock` (due to 
`--bind-local` being passed).

To test against the daemon, run 

    export DOCKER_HOST=unix:///tmp/docker.sock 
    docker build vendor/github.com/openshift/imagebuilder/dockerclient/testdata/volume/

And you should see a build created.