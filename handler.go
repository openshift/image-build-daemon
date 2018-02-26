package daemon

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/builder/dockerfile/parser"
	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/golang/glog"

	"github.com/openshift/image-build-daemon/pkg/interceptor"
	"github.com/openshift/image-build-daemon/pkg/interceptor/archive"
)

// NewAuthorizingDockerAPIFilter allows a subset of the Docker API to be invoked on the nested handler and only
// after the provided authorizer validates/transforms the provided request.
func NewAuthorizingDockerAPIFilter(h http.Handler, authorizer interceptor.BuildAuthorizer, containerAuthorizer interceptor.ContainerAuthorizer, imageAuthorizer interceptor.ImageAuthorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == "GET" && interceptor.IsPingEndpoint(req.URL.Path):
			h.ServeHTTP(w, req)

		// The interceptor allows the /auth endpoint to be hit to provide a convenience for local testing.
		// If the incoming server address matches the fake builder, we return 204 to let docker use those
		// credentials. Otherwise, we reject the call
		case req.Method == "POST" && interceptor.IsAuthEndpoint(req.URL.Path):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			fmt.Fprintln(w, `{"Status":"Login succeeded"}`)
			return

		case req.Method == "POST" && interceptor.IsBuildImageEndpoint(req.URL.Path):
			if err := filterBuildImageRequest(w, req, authorizer, imageAuthorizer); err != nil {
				glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
				err.ServeHTTP(w, req)
				return
			}

			h.ServeHTTP(w, req)

		case req.Method == "POST" && interceptor.IsPushImageEndpoint(req.URL.Path):
			if err := filterPushImageRequest(req, imageAuthorizer); err != nil {
				glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
				err.ServeHTTP(w, req)
				return
			}

			h.ServeHTTP(w, req)

		case req.Method == "POST" && interceptor.IsTagImageEndpoint(req.URL.Path):
			if err := filterTagImageRequest(req, imageAuthorizer); err != nil {
				glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
				err.ServeHTTP(w, req)
				return
			}

			h.ServeHTTP(w, req)

		case req.Method == "DELETE" && interceptor.IsRemoveImageEndpoint(req.URL.Path):
			if err := filterRemoveImageRequest(req, imageAuthorizer); err != nil {
				glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
				err.ServeHTTP(w, req)
				return
			}

			h.ServeHTTP(w, req)

		case req.Method == "GET" && interceptor.IsListContainersEndpoint(req.URL.Path):
			if err := filterListContainersRequest(req, containerAuthorizer); err != nil {
				glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
				err.ServeHTTP(w, req)
				return
			}

			h.ServeHTTP(w, req)

		case req.Method == "GET" && interceptor.IsListImagesEndpoint(req.URL.Path):
			if err := filterListImagesRequest(req, imageAuthorizer); err != nil {
				glog.V(2).Infof("%s %s forbidden: %v", req.Method, req.URL, err)
				err.ServeHTTP(w, req)
				return
			}

			h.ServeHTTP(w, req)

		default:
			glog.V(2).Infof("%s %s forbidden", req.Method, req.URL)
			interceptor.NewForbiddenError(fmt.Errorf("only build or ping requests are allowed")).ServeHTTP(w, req)
		}
	})
}

// filterBuildImageRequest applies the necessary authorization to an incoming build request based on authorizer.
// Authorizer may mutate the build request, which will then be applied back to the passed request URLs for
// continuing the action.
func filterBuildImageRequest(w http.ResponseWriter, req *http.Request, authorizer interceptor.BuildAuthorizer, imageAuthorizer interceptor.ImageAuthorizer) interceptor.ErrorHandler {
	info, err := interceptor.ParseBuildAuthorization(req)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}

	build := &interceptor.BuildImageOptions{}
	if err := interceptor.StrictDecodeFromQuery(build, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("build request rejected because of an unrecogized query param: %v", err))
	}

	names, err := imageAuthorizer.AuthorizeImageAccess(req.Context(), build.Names...)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}
	build.Names = names

	authCtx, cancelFn := context.WithDeadline(req.Context(), time.Now().Add(10*time.Second))
	updatedBuild, err := authorizer.AuthorizeBuildRequest(authCtx, build, info)
	cancelFn()
	if err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("build request could not be authorized: %v", err))
	}

	// transform the incoming request into the authorized form
	updateRequest(req, req.URL.Path, interceptor.EncodeToQuery(updatedBuild).Encode())
	// wrap the request body to ensure the dockerfile is safe
	// req.Body = filterBuildArchive(req.Body, updatedBuild)

	glog.V(4).Infof("Authorized to build %#v", updatedBuild)
	return nil
}

func filterBuildArchive(in io.Reader, options *interceptor.BuildImageOptions, imageAuthorizer interceptor.ImageAuthorizer) io.ReadCloser {
	dockerfilePath := options.Dockerfile
	if len(dockerfilePath) == 0 {
		dockerfilePath = "Dockerfile"
	}
	pr, pw := io.Pipe()
	go func() {
		r, err := dockerarchive.DecompressStream(in)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		err = archive.FilterArchive(r, pw, func(h *tar.Header, in io.Reader) ([]byte, bool, error) {
			if h.Name != dockerfilePath {
				return nil, false, nil
			}
			glog.V(4).Infof("Intercepted %s: %#v", dockerfilePath, h)
			if h.Size > 100*1024 {
				return nil, false, fmt.Errorf("Dockerfile in uploaded build context too large, %d bytes", h.Size)
			}
			data, err := ioutil.ReadAll(in)
			if err != nil {
				return nil, false, err
			}
			root, err := parser.Parse(bytes.NewBuffer(data))
			if err != nil {
				return nil, false, fmt.Errorf("unable to parse %s in archive: %v", h.Name, err)
			}
			// TODO: alter FROM images?
			glog.V(4).Infof("Found dockerfile:\n%s", root.AST.Dump())
			return data, true, nil
		})
		pw.CloseWithError(err)
	}()
	return pr
}

// filterListContainersRequest applies the necessary authorization to an incoming container list.
func filterListContainersRequest(req *http.Request, containerAuthorizer interceptor.ContainerAuthorizer) interceptor.ErrorHandler {
	opt := &interceptor.ListContainersOptions{}
	if err := interceptor.StrictDecodeFromQuery(opt, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("list containers request rejected because of an unrecogized query param: %v", err))
	}

	options := &interceptor.ListContainersOptions{
		All:    opt.All,
		Size:   opt.Size,
		Limit:  opt.Limit,
		Since:  opt.Since,
		Before: opt.Before,
	}

	filters := opt.Filters
	if filters == nil {
		filters = make(map[string][]string)
	}
	// extract labels
	labels := make(map[string]string)
	for _, value := range filters["label"] {
		pair := strings.SplitN(value, "=", 2)
		if len(pair) == 2 {
			labels[pair[0]] = pair[1]
		} else {
			labels[pair[0]] = ""
		}
	}
	// override explicit labels
	for k, v := range containerAuthorizer.ContainerFilters() {
		if set, ok := labels[k]; ok && set != v && len(v) > 0 {
			return interceptor.NewForbiddenError(fmt.Errorf("list containers request rejected because filter %q must be %q", k, v))
		}
		labels[k] = v
	}
	// write labels out
	var allLabels []string
	for k, v := range labels {
		if v == "" {
			allLabels = append(allLabels, k)
		} else {
			allLabels = append(allLabels, fmt.Sprintf("%s=%s", k, v))
		}
	}
	sort.Strings(allLabels)
	filters["label"] = allLabels
	options.Filters = filters

	updateRequest(req, req.URL.Path, interceptor.EncodeToQuery(options).Encode())

	glog.V(4).Infof("Authorized to list containers %#v", options)
	return nil
}

// filterListImagesRequest applies the necessary authorization to an incoming image list.
func filterListImagesRequest(req *http.Request, imageAuthorizer interceptor.ImageAuthorizer) interceptor.ErrorHandler {
	originalOptions := &interceptor.ListImagesOptions{}
	if err := interceptor.StrictDecodeFromQuery(originalOptions, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("list images request rejected because of an unrecogized query param: %v", err))
	}

	options := &interceptor.ListImagesOptions{}

	updateRequest(req, req.URL.Path, interceptor.EncodeToQuery(options).Encode())

	glog.V(4).Infof("Authorized to list images %#v", options)
	return nil
}

// filterPushImageRequest applies the necessary authorization to an incoming push request.
func filterPushImageRequest(req *http.Request, imageAuthorizer interceptor.ImageAuthorizer) interceptor.ErrorHandler {
	push := &interceptor.PushImageOptions{}
	if err := interceptor.StrictDecodeFromQuery(push, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("push request rejected because of an unrecogized query param: %v", err))
	}
	name, ok := interceptor.PushImageEndpointParameters(req.URL.Path)
	if !ok || len(name) == 0 {
		return interceptor.NewForbiddenError(fmt.Errorf("push request rejected: unable to find endpoint path"))
	}

	names, err := imageAuthorizer.AuthorizeImageAccess(req.Context(), name)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}

	if len(push.Tag) == 0 {
		tag := findTag(name)
		if len(tag) == 0 {
			tag = "latest"
		}
		push.Tag = tag
	}
	push.Name = names[0]

	// transform the incoming request into the authorized form
	newPath, ok := interceptor.ReplacePushImageEndpointParameters(req.URL.Path, push.Name)
	if !ok {
		return interceptor.NewForbiddenError(fmt.Errorf("push request rejected: unable to generate new endpoint path"))
	}
	updateRequest(req, newPath, interceptor.EncodeToQuery(push).Encode())

	glog.V(4).Infof("Authorized to push %#v", push)
	return nil
}

// filterRemoveImageRequest applies the necessary authorization to an incoming image removal.
func filterRemoveImageRequest(req *http.Request, imageAuthorizer interceptor.ImageAuthorizer) interceptor.ErrorHandler {
	removeImage := &interceptor.RemoveImageOptions{}
	if err := interceptor.StrictDecodeFromQuery(removeImage, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("remove image request rejected because of an unrecogized query param: %v", err))
	}
	name, ok := interceptor.RemoveImageEndpointParameters(req.URL.Path)
	if !ok || len(name) == 0 {
		return interceptor.NewForbiddenError(fmt.Errorf("remove image rejected: unable to find endpoint path"))
	}
	names, err := imageAuthorizer.AuthorizeImageAccess(req.Context(), name)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}

	removeImage = &interceptor.RemoveImageOptions{
		Name: names[0],
		// prevent users from leaving unused content
		Force:   true,
		NoPrune: false,
	}

	// transform the incoming request into the authorized form
	newPath, ok := interceptor.ReplaceRemoveImageEndpointParameters(req.URL.Path, removeImage.Name)
	if !ok {
		return interceptor.NewForbiddenError(fmt.Errorf("remove image request rejected: unable to generate new endpoint path"))
	}
	updateRequest(req, newPath, interceptor.EncodeToQuery(removeImage).Encode())

	glog.V(4).Infof("Authorized to remove %#v", removeImage)
	return nil
}

// filterTagImageRequest applies the necessary authorization checks to an incoming tag image request.
func filterTagImageRequest(req *http.Request, imageAuthorizer interceptor.ImageAuthorizer) interceptor.ErrorHandler {
	imageTag := &interceptor.ImageTagOptions{}
	if err := interceptor.StrictDecodeFromQuery(imageTag, req.URL.Query()); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("tag request rejected because of an unrecogized query param: %v", err))
	}
	if len(imageTag.Repo) == 0 {
		return interceptor.NewForbiddenError(fmt.Errorf("tag request rejected, no destination repository parameter provided"))
	}
	if len(imageTag.Tag) == 0 {
		imageTag.Tag = "latest"
	}

	name, ok := interceptor.TagImageEndpointParameters(req.URL.Path)
	if !ok || len(name) == 0 {
		return interceptor.NewForbiddenError(fmt.Errorf("tag request rejected: unable to find endpoint path"))
	}
	repoName := imageTag.Repo + ":" + imageTag.Tag

	names, err := imageAuthorizer.AuthorizeImageAccess(req.Context(), name)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}
	repoNames, err := imageAuthorizer.AuthorizeImageAccess(req.Context(), repoName)
	if err != nil {
		return interceptor.NewForbiddenError(err)
	}
	imageTag = &interceptor.ImageTagOptions{
		Name: names[0],
		Tag:  findTag(repoNames[0]),
		Repo: removeTagOrDigest(repoNames[0]),
	}

	// transform the incoming request into the authorized form
	newPath, ok := interceptor.ReplaceTagImageEndpointParameters(req.URL.Path, imageTag.Name)
	if !ok {
		return interceptor.NewForbiddenError(fmt.Errorf("push request rejected: unable to generate new push endpoint path"))
	}
	updateRequest(req, newPath, interceptor.EncodeToQuery(imageTag).Encode())

	glog.V(4).Infof("Authorized to tag %#v", imageTag)
	return nil
}

func updateRequest(req *http.Request, path, rawQuery string) {
	copiedURL := *req.URL
	copiedURL.Path = path
	copiedURL.RawQuery = rawQuery
	req.URL = &copiedURL
	req.RequestURI = copiedURL.Path
	if len(copiedURL.RawQuery) > 0 {
		req.RequestURI = "?" + copiedURL.RawQuery
	}
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func cookieToMappedTags(cookie map[interface{}]interface{}) (map[string][]string, error) {
	result := make(map[string][]string)
	for keyObj, valueObj := range cookie {
		key, ok := keyObj.(string)
		if !ok {
			continue
		}
		values, ok := valueObj.([]string)
		if !ok {
			continue
		}
		for _, value := range values {
			result[value] = append(result[value], key)
		}
	}
	return result, nil
}

func removeTagOrDigest(value string) string {
	last := strings.LastIndex(value, "/")
	if suffix := strings.LastIndexAny(value, "@:"); suffix != -1 && last < suffix {
		value = value[:suffix]
	}
	return value
}

func findTag(value string) string {
	last := strings.LastIndex(value, "/")
	if suffix := strings.LastIndexAny(value, ":"); suffix != -1 && last < suffix {
		return value[suffix+1:]
	}
	return ""
}
