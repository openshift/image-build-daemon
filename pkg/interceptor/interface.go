package interceptor

import (
	"context"
	"fmt"
	"net/http"
)

type BuildAuthorizer interface {
	AuthorizeBuildRequest(ctx context.Context, build *BuildImageOptions, auth map[string]AuthOptions) (*BuildImageOptions, error)
}

type ImageAuthorizer interface {
	// AuthorizeImageAccess checks whether the caller may access the provided names, returning
	// an error if they may not. If the caller is authorized to access those names, the method
	// will return the names that should be passed to the lower levels.
	AuthorizeImageAccess(ctx context.Context, names ...string) ([]string, error)
}

type ContainerAuthorizer interface {
	// ContainerFilters returns a set of label filters that must be true for a set of containers.
	ContainerFilters() map[string]string
}

type Interface interface {
	InterceptRequest(*http.Request) error
	InterceptResponse(*http.Response) error
}

type Proxy interface {
	Intercept(Interface, http.ResponseWriter, *http.Request)
}

var Allow Interface = allow{}

type allow struct{}

func (allow) InterceptRequest(r *http.Request) error   { return nil }
func (allow) InterceptResponse(r *http.Response) error { return nil }

type ErrorHandler interface {
	error
	http.Handler
}

func NewForbiddenError(err error) ErrorHandler {
	return forbiddenError{err: err}
}

type forbiddenError struct {
	err error
}

func (e forbiddenError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return "forbidden"
}

func (e forbiddenError) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.err != nil {
		http.Error(w, fmt.Sprintf("This call is forbidden: %v", e.err), http.StatusForbidden)
	} else {
		http.Error(w, "This call is forbidden", http.StatusForbidden)
	}
}
