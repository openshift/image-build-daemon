package daemon

import (
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"
	gorillacontext "github.com/gorilla/context"

	"github.com/openshift/image-build-daemon/pkg/dockerproxy"
	"github.com/openshift/image-build-daemon/pkg/notifier"
	dockernotifier "github.com/openshift/image-build-daemon/pkg/notifier/docker"
	"github.com/openshift/image-build-daemon/pkg/passthrough"
	"github.com/openshift/image-build-daemon/pkg/passthrough/imagebuilder"
)

type Server struct {
	Mode   string
	Client *docker.Client

	BindDirectory string

	servers map[serverName]*http.Server
}

type serverName struct {
	UID           string
	ContainerName string
}

func (s *Server) Start() error {
	if s.Client == nil {
		c, err := docker.NewClientFromEnv()
		if err != nil {
			return err
		}
		s.Client = c
	}
	if s.servers == nil {
		s.servers = make(map[serverName]*http.Server)
	}

	n := dockernotifier.New(s.Client, s)
	if err := n.Run(make(chan struct{})); err != nil {
		return err
	}
	select {}
	return nil
}

func (s *Server) MountSync(infos []*notifier.ContainerInfo) {
	missing := make(map[serverName]struct{})
	for k := range s.servers {
		missing[k] = struct{}{}
	}
	for _, info := range infos {
		delete(missing, serverName{UID: info.PodUID, ContainerName: info.ContainerName})
	}
	for k := range missing {
		s.closeServer(k)
	}
	// TODO: other cleanup
}

func (s *Server) MountAdded(info *notifier.ContainerInfo) {
	if len(s.BindDirectory) > 0 {
		info.MountPath = s.BindDirectory
	}
	server := s.newServer(info)
	s.servers[serverName{UID: info.PodUID, ContainerName: info.ContainerName}] = server
	glog.Infof("Starting server for pod %s in namespace %s", info.PodName, info.PodNamespace)
	listener, err := listenerForContainer(info)
	if err != nil {
		glog.Errorf("Unable to create Unix socket for pod %s in namespace %s: %v", info.PodName, info.PodNamespace, err)
		return
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			glog.Errorf("Server startup failed for pod %s in namespace %s: %v", info.PodName, info.PodNamespace, err)
		}
	}()
}

func (s *Server) MountRemoved(info *notifier.ContainerInfo) {
	name := serverName{UID: info.PodUID, ContainerName: info.ContainerName}
	s.closeServer(name)
}

func (s *Server) closeServer(name serverName) {
	server, ok := s.servers[name]
	if !ok {
		return
	}
	glog.Infof("Stopping server for container %s in pod %s", name.ContainerName, name.UID)
	if err := server.Close(); err != nil {
		glog.Errorf("Server shutdown reported error for container %s in pod %s: %v", name.ContainerName, name.UID, err)
	}
	delete(s.servers, name)
}

func (s *Server) newServer(info *notifier.ContainerInfo) *http.Server {
	authorizer := &passthrough.DefaultAuthorizer{
		Client: s.Client,
		PodUID: info.PodUID,
	}

	p := dockerproxy.BaseProxy(dockerproxy.Config{Client: s.Client})
	var handler http.Handler = passthrough.Server{
		Proxy:  p,
		PodUID: info.PodUID,
	}
	switch s.Mode {
	case "passthrough":
		// use the base passthrough for Docker
	case "imagebuilder":
		// wrap specifically the build call, everything else stays the same
		handler = imagebuilder.Server{
			Handler: handler,
			Client:  s.Client,
			TempDir: info.MountPath,
		}
	default:
		handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "No registered proxy mode", http.StatusInternalServerError)
		})
	}
	handler = NewAuthorizingDockerAPIFilter(handler, authorizer, authorizer, authorizer)
	handler = gorillacontext.ClearHandler(handler)

	return &http.Server{Handler: handler}
}

func listenerForContainer(info *notifier.ContainerInfo) (net.Listener, error) {
	socketPath := filepath.Join(info.MountPath, "docker.sock")
	if err := syscall.Unlink(socketPath); err != nil && !os.IsNotExist(err) {
		glog.Errorf("Unable to unlink socket path prior to binding %s: %v", socketPath, err)
	}
	if shortName, mustSymlink := shortenSocketPath(socketPath, info); mustSymlink {
		if err := os.Remove(shortName); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.Symlink(socketPath, shortName); err != nil {
			return nil, err
		}
		socketPath = shortName
	}
	return net.Listen("unix", socketPath)
}

func shortenSocketPath(path string, info *notifier.ContainerInfo) (shortName string, mustSymlink bool) {
	if len(path) <= 104 {
		return "", false
	}
	shortName = fmt.Sprintf("socket-%s-%s", info.PodUID, filepath.Base(info.MountPath))
	if len(shortName) <= 104 {
		return shortName, true
	}
	fn := fnv.New128()
	fn.Write([]byte(shortName))
	hash := base64.RawURLEncoding.EncodeToString(fn.Sum(nil))
	shortName = shortName[:104-len(hash)-1] + "-" + hash
	return shortName, true
}
