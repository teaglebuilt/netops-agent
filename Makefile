IMAGE       ?= ghcr.io/teaglebuilt/netops-agent
TAG         ?= dev
PLATFORM    ?= linux/amd64

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-20s %s\n", $$1, $$2}'

BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	-I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

.PHONY: bpf
bpf: internal/bpf/netops.bpf.o internal/bpf/trace_pcie.bpf.o

internal/bpf/netops.bpf.o: internal/bpf/src/netops.bpf.c
	clang $(BPF_CFLAGS) -c $< -o $@

internal/bpf/trace_pcie.bpf.o: internal/bpf/src/trace_pcie.bpf.c
	clang $(BPF_CFLAGS) -c $< -o $@

.PHONY: build
build:
	docker buildx build --platform=$(PLATFORM) --load -t $(IMAGE):$(TAG) .

.PHONY: push
push:
	docker push $(IMAGE):$(TAG)

.PHONY: cismoke
cismoke: bpf
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/cismoke ./cmd/cismoke

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: test
test:
	go test ./...

.PHONY: helm-lint
helm-lint:
	helm lint deploy/helm/netops

.PHONY: helm-template
helm-template:
	helm template netops deploy/helm/netops --namespace netops-stage

.PHONY: clean
clean:
	rm -f internal/bpf/*.o