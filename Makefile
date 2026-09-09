IMAGE       ?= ghcr.io/teaglebuilt/netops-agent
GIT_SHA     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
GIT_DIRTY   := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo -dirty)
TAG         ?= $(GIT_SHA)$(GIT_DIRTY)
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
	docker buildx build --no-cache --platform=$(PLATFORM) --load \
		--build-arg VERSION=$(TAG) \
		--build-arg REVISION=$(GIT_SHA)$(GIT_DIRTY) \
		-t $(IMAGE):$(TAG) .

.PHONY: push
push:
	docker push $(IMAGE):$(TAG)

.PHONY: image
image:
	@echo $(IMAGE):$(TAG)

.PHONY: digest
digest:
	@docker buildx imagetools inspect $(IMAGE):$(TAG) --raw \
	  | python3 -c "import sys,json;print(next(m['digest'] for m in json.load(sys.stdin)['manifests'] if m.get('platform',{}).get('architecture')=='$(word 2,$(subst /, ,$(PLATFORM)))'))"

.PHONY: smoke-test
smoke-test: bpf
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/test ./cmd/test

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
