# syntax=docker/dockerfile:1.9

ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
ARG GO_IMAGE=golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

FROM ${DEBIAN_IMAGE} AS bpf-builder

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev; \
    rm -rf /var/lib/apt/lists/*; \
    clang --version

WORKDIR /src

COPY internal/bpf/src/ ./internal/bpf/src/

ARG TARGETARCH
ARG TARGETPLATFORM
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) BPF_TARGET_ARCH=x86;   MULTIARCH=x86_64-linux-gnu  ;; \
      arm64) BPF_TARGET_ARCH=arm64; MULTIARCH=aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH} (TARGETPLATFORM=${TARGETPLATFORM})" >&2; exit 1 ;; \
    esac; \
    test -d "/usr/include/${MULTIARCH}/asm" \
      || { echo "missing UAPI headers at /usr/include/${MULTIARCH}/asm" >&2; exit 1; }; \
    mkdir -p /out; \
    for src in netops trace_pcie; do \
      clang \
        -O2 -g -Wall -Werror \
        -target bpf \
        -D__TARGET_ARCH_${BPF_TARGET_ARCH} \
        -I/usr/include/bpf \
        -I/usr/include/${MULTIARCH} \
        -c "internal/bpf/src/${src}.bpf.c" \
        -o "/out/${src}.bpf.o"; \
      llvm-strip -g "/out/${src}.bpf.o"; \
      llvm-readelf --section-headers "/out/${src}.bpf.o" | grep -q '\.BTF' \
        || { echo "BTF section missing from ${src}.bpf.o" >&2; exit 1; }; \
    done; \
    ls -l /out/*.bpf.o

FROM --platform=${BUILDPLATFORM} ${GO_IMAGE} AS go-builder

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS=-buildvcs=false

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

COPY --from=bpf-builder /out/netops.bpf.o ./internal/bpf/netops.bpf.o
COPY --from=bpf-builder /out/trace_pcie.bpf.o ./internal/bpf/trace_pcie.bpf.o

ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=go-build-${TARGETARCH},target=/root/.cache/go-build,sharing=locked \
    set -eux; \
    export GOARCH="${TARGETARCH}"; \
    go build -trimpath -ldflags="-s -w" -o /out/netops-agent ./cmd/network; \
    go build -trimpath -ldflags="-s -w" -o /out/netops-test ./cmd/test; \
    ls -l /out

FROM ${RUNTIME_IMAGE} AS final

ARG VERSION=dev
ARG REVISION=unknown
ARG RUNTIME_IMAGE

LABEL org.opencontainers.image.title="netops" \
      org.opencontainers.image.description="eBPF network observability agent: tcx ingress byte counts, TCP retransmits, TCP sRTT and DNS latency histograms, plus host PCI/Thunderbolt GPU fabric gauges, exported as Prometheus metrics on :9101." \
      org.opencontainers.image.source="https://github.com/teaglebuilt/netops" \
      org.opencontainers.image.url="https://github.com/teaglebuilt/netops" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="teaglebuilt" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.base.name="${RUNTIME_IMAGE}"

COPY --from=go-builder /out/netops-agent /usr/local/bin/netops-agent
COPY --from=go-builder /out/netops-test /usr/local/bin/netops-test

USER 0:0

EXPOSE 9101

ENTRYPOINT ["/usr/local/bin/netops-agent"]
