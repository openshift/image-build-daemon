// package daemon implements a Docker build daemon that can answer requests
// via the Docker engine build, push, commit, and tag API for containerized
// callers to use safely.
//
// Clients request a domain socket be placed into their container at a
// pre-arranged location by creating an appropriate volume mount. A socket
// emulating the Docker engine API for a limited set of operations and
// imposing additional restrictions will respond to that container.
package daemon
