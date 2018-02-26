package imagebuilder

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	dockertypes "github.com/docker/docker/api/types"
	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"
	"github.com/openshift/imagebuilder"
	"github.com/openshift/imagebuilder/dockerclient"

	"github.com/openshift/image-build-daemon/pkg/interceptor"
	"github.com/openshift/image-build-daemon/pkg/interceptor/archive"
)

type Server struct {
	Handler http.Handler
	Client  *docker.Client
	TempDir string
}

func (s Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch path := req.URL.Path; {
	case req.Method == "POST" && interceptor.IsBuildImageEndpoint(path):
		if err := handleBuildImageRequest(s.Client, w, req, s.TempDir); err != nil {
			glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
			err.ServeHTTP(w, req)
		}
		return
	}

	s.Handler.ServeHTTP(w, req)
}

var errFoundDockerfile = fmt.Errorf("found Dockerfile")

// handleBuildImageRequest applies the necessary authorization to an incoming build request based on authorizer.
// Authorizer may mutate the build request, which will then be applied back to the passed request URLs for
// continuing the action.
func handleBuildImageRequest(client *docker.Client, w http.ResponseWriter, req *http.Request, tempDir string) interceptor.ErrorHandler {
	var auth docker.AuthConfigurations
	if header := req.Header.Get("X-Registry-Config"); len(header) > 0 {
		data, err := base64.StdEncoding.DecodeString(header)
		if err != nil {
			return interceptor.NewForbiddenError(fmt.Errorf("build request rejected because X-Registry-Config header not valid base64: %v", err))
		}
		if err := json.Unmarshal(data, &auth.Configs); err != nil {
			return interceptor.NewForbiddenError(fmt.Errorf("build request rejected because X-Registry-Config header not parseable: %v", err))
		}
	}

	options := &interceptor.BuildImageOptions{}
	if err := interceptor.StrictDecodeFromQuery(options, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("build request rejected because of an unrecogized query param: %v", err))
	}

	dockerfilePath := options.Dockerfile
	if len(dockerfilePath) == 0 {
		dockerfilePath = "Dockerfile"
	}
	dockerfilePath = path.Clean(dockerfilePath)
	arguments := make(map[string]string)
	for _, arg := range options.BuildArgs {
		arguments[arg.Name] = arg.Value
	}

	// save the compressed build archive to disk inside of the provided temporary directory,
	// allows permissions to be preserved
	archiveFile, err := ioutil.TempFile(tempDir, "imagebuilder-")
	if err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("build context cannot be saved to disk: %v", err))
	}
	//defer func() { os.RemoveAll(archiveFile.Name()) }()
	if _, err := io.Copy(archiveFile, req.Body); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("build context cannot be saved to disk: %v", err))
	}
	if err := archiveFile.Close(); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("build context cannot be saved to disk (write failed): %v", err))
	}
	// we are done with the body
	req.Body.Close()
	// reopen the file for reading
	archiveFile, err = os.Open(archiveFile.Name())
	if err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("unable to open saved build context for reading: %v", err))
	}
	defer archiveFile.Close()

	e := dockerclient.NewClientExecutor(client)
	e.ContextArchive = archiveFile.Name()
	e.TempDir = tempDir
	e.AuthFn = func(name string) ([]dockertypes.AuthConfig, bool) {
		cfg, ok := auth.Configs[name]
		return []dockertypes.AuthConfig{
			{Username: cfg.Username, Password: cfg.Password, Email: cfg.Email, ServerAddress: cfg.ServerAddress},
		}, ok
	}
	e.AllowPull = options.Pull
	e.HostConfig = &docker.HostConfig{
		NetworkMode:  options.NetworkMode,
		CgroupParent: options.CgroupParent,
	}
	if len(options.Names) > 0 {
		e.Tag = options.Names[0]
		e.AdditionalTags = options.Names[1:]
	}

	for _, name := range options.Names {
		if err := client.RemoveImage(name); err != nil {
			if err != docker.ErrNoSuchImage {
				glog.V(4).Infof("Unable to remove previously tagged image %s", name)
			}
		}
	}

	// TODO: handle signals
	defer func() {
		for _, err := range e.Release() {
			glog.V(2).Infof("Unable to clean up build: %v\n", err)
		}
	}()

	uncompressedArchiveFile, err := dockerarchive.DecompressStream(archiveFile)
	if err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("unable to decompress build context: %v", err))
	}
	var dockerfileReader io.Reader
	err = archive.Walk(uncompressedArchiveFile, func(h *tar.Header, in io.Reader) error {
		if h.Name != dockerfilePath {
			return nil
		}
		glog.V(4).Infof("Found Dockerfile %s: %#v", dockerfilePath, h)
		if h.Size > 100*1024 {
			return fmt.Errorf("Dockerfile in uploaded build context too large, %d bytes", h.Size)
		}
		dockerfileReader = in
		return errFoundDockerfile
	})
	if err == errFoundDockerfile {
		err = nil
	}
	if err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("unable to find Dockerfile: %v", err))
	}
	if dockerfileReader == nil {
		return interceptor.NewForbiddenError(fmt.Errorf("no Dockerfile found at %s", dockerfilePath))
	}

	b := imagebuilder.NewBuilder(arguments)
	node, err := imagebuilder.ParseDockerfile(dockerfileReader)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}
	stages := imagebuilder.NewStages(node, b)

	out := &streamWriter{encoder: json.NewEncoder(w)}
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	e.LogFn = func(format string, args ...interface{}) {
		fmt.Fprintf(out, "--> "+format+"\n", args...)
	}
	e.Out = out
	e.ErrOut = out

	var stageExecutor *dockerclient.ClientExecutor
	for _, stage := range stages {
		stageExecutor = e.WithName(stage.Name)
		if err := stageExecutor.Prepare(stage.Builder, stage.Node, ""); err != nil {
			fmt.Fprintf(out, "error: %v", err)
			return nil
		}
		if err := stageExecutor.Execute(stage.Builder, stage.Node); err != nil {
			fmt.Fprintf(out, "error: %v", err)
			return nil
		}
	}
	if len(options.Names) > 0 {
		if err := stageExecutor.Commit(stages[len(stages)-1].Builder); err != nil {
			fmt.Fprintf(out, "error: %v", err)
			return nil
		}
	}
	return nil
}

type streamWriter struct {
	encoder *json.Encoder
	r       streamResponse
}

type streamResponse struct {
	Stream string `json:"stream"`
}

func (w *streamWriter) Write(data []byte) (n int, err error) {
	w.r.Stream = string(data)
	if err := w.encoder.Encode(&w.r); err != nil {
		return 0, err
	}
	return len(data), nil
}
