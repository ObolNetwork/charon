# Container for building Go binary. It always runs on the build platform and
# cross-compiles for the target platform, so multi-platform builds don't compile
# under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie AS builder
ARG BUILDARCH
ARG TARGETOS
ARG TARGETARCH
# Install dependencies, plus a cgo cross compiler when the target arch differs
# from the build arch (herumi bls requires cgo).
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git \
  && if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
    case "$TARGETARCH" in \
      arm64) apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
      amd64) apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" && exit 1 ;; \
    esac; \
  fi

# Prep and copy source
WORKDIR /app/charon

COPY . .

# Populate GO_BUILD_FLAG with a build arg to provide an optional go build flag.
ARG GO_BUILD_FLAG
ENV GO_BUILD_FLAG=${GO_BUILD_FLAG}
RUN echo "Building for ${TARGETOS}/${TARGETARCH} on ${BUILDARCH} with GO_BUILD_FLAG='${GO_BUILD_FLAG}'"

# Build with Go module and Go build caches (the build cache keys entries by
# GOARCH, so both target arches can share it).
RUN \
  --mount=type=cache,target=/go/pkg \
  --mount=type=cache,target=/root/.cache/go-build \
  if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
    case "$TARGETARCH" in \
      arm64) export CC=aarch64-linux-gnu-gcc ;; \
      amd64) export CC=x86_64-linux-gnu-gcc ;; \
    esac; \
  fi \
  && CGO_ENABLED=1 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -o charon "${GO_BUILD_FLAG}" .

# Copy final binary into light stage.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates fio wget \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
# Distrust the emSign ECC Root CA - G3 and AAA Certificate Services roots in the
# system store (used by wget and other non-Go tools in the image) until Debian's
# ca-certificates drops them. Remove once the base image ships the update.
RUN sed -i -E 's#^(mozilla/(emSign_ECC_Root_CA_-_G3|Comodo_AAA_Services_root)\.crt)$#!\1#' /etc/ca-certificates.conf \
  && update-ca-certificates --fresh
ARG GITHUB_SHA=local
ENV GITHUB_SHA=${GITHUB_SHA}

COPY --from=builder /app/charon/charon /usr/local/bin/
# Sanity check the binary on the target platform (the builder can't run a
# cross-compiled binary).
RUN version="$(/usr/local/bin/charon version)" && echo "Built charon version=${version}"

# Don't run container as root
ENV USER=charon
ENV UID=1000
ENV GID=1000
RUN addgroup --gid "$GID" "$USER" \
  && adduser \
  --disabled-password \
  --gecos "charon" \
  --home "/opt/$USER" \
  --ingroup "$USER" \
  --no-create-home \
  --uid "$UID" \
  "$USER" \
  && chown "$USER" /usr/local/bin/charon \
  && chmod u+x /usr/local/bin/charon

WORKDIR "/opt/$USER"
RUN chown charon "/opt/$USER"
USER charon

ENTRYPOINT ["/usr/local/bin/charon"]
CMD ["run"]

# Used by GitHub to associate container with repo.
LABEL org.opencontainers.image.source="https://github.com/obolnetwork/charon"
LABEL org.opencontainers.image.title="charon"
LABEL org.opencontainers.image.description="Proof of Stake Ethereum Distributed Validator Client"
LABEL org.opencontainers.image.licenses="BUSL"
LABEL org.opencontainers.image.documentation="https://docs.obol.org/"
