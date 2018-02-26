
build:
	go build ./cmd/image-build-daemon
.PHONY: build

check:
	go test ./...
.PHONY: check

deps:
	glide update -v --skip-test
.PHONY: deps

fake:
	docker run --name daemon-test -d -v /var/run/docker \
		-l io.kubernetes.pod.uid=123 \
		-l io.kubernetes.pod.namespace=test \
		-l io.kubernetes.pod.name=daemon \
		-l io.kubernetes.container.name=sleep \
		--cgroup-parent system.slice \
		centos:7 /bin/bash -c 'exec sleep 10000'
.PHONY: fake
