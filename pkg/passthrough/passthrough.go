package passthrough

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang/glog"

	"github.com/openshift/image-build-daemon/pkg/interceptor"
)

type Server struct {
	Proxy  interceptor.Proxy
	PodUID string
}

func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var i interceptor.Interface = interceptor.Allow

	switch path := r.URL.Path; {
	case r.Method == "GET" && interceptor.IsListImagesEndpoint(path):
		i = &listImagesInterceptor{PodUID: s.PodUID}
	}

	s.Proxy.Intercept(i, w, r)
}

type listImagesInterceptor struct {
	PodUID string
}

func (i *listImagesInterceptor) InterceptRequest(req *http.Request) error {
	return nil
}

func (i *listImagesInterceptor) InterceptResponse(r *http.Response) error {
	if r.StatusCode != http.StatusOK {
		return nil
	}

	d := json.NewDecoder(r.Body)
	var closer io.Closer = r.Body
	defer closer.Close()
	var items []interface{}
	if err := d.Decode(&items); err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("unable to decode successful image list response: %v", err))
	}
	var filtered []interface{}
	for _, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tags, ok := obj["RepoTags"].([]interface{})
		if !ok {
			continue
		}
		var matchingTags []interface{}
		for _, tag := range tags {
			name, ok := tag.(string)
			if !ok {
				continue
			}
			if strings.HasPrefix(name, fmt.Sprintf("internalbuilder/%s:internal-", i.PodUID)) {
				matchingTags = append(matchingTags, name)
			}
		}
		if len(matchingTags) == 0 {
			continue
		}
		obj["RepoTags"] = matchingTags
		filtered = append(filtered, item)
	}
	data, err := json.Marshal(filtered)
	if err != nil {
		return interceptor.NewForbiddenError(fmt.Errorf("unable to encoded filtered image list response: %v", err))
	}
	r.TransferEncoding = nil
	r.ContentLength = int64(len(data))
	r.Body = ioutil.NopCloser(bytes.NewReader(data))
	glog.V(5).Infof("Intercepted image list: %#v", r)
	return nil
}
