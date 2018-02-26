package interceptor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

func ParseAuthorizationRequest(req *http.Request, maxLength int64) (*AuthRequest, error) {
	data, err := ioutil.ReadAll(io.LimitReader(req.Body, maxLength))
	if err != nil {
		return nil, fmt.Errorf("unable to parse authorization request, may be too large: %v", err)
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	auth := &AuthRequest{}
	if err := json.Unmarshal(data, auth); err != nil {
		return nil, fmt.Errorf("authorization request rejected because body was not parseable to JSON: %v", err)
	}
	return auth, nil
}

func ParseBuildAuthorization(req *http.Request) (map[string]AuthOptions, error) {
	var config map[string]AuthOptions
	auth := req.Header.Get("X-Registry-Config")
	if len(auth) > 0 {
		data, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return nil, fmt.Errorf("build request rejected because X-Registry-Config header not valid base64: %v", err)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("build request rejected because X-Registry-Config header not parseable: %v", err)
		}
	}
	return config, nil
}
