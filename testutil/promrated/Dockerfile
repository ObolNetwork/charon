# Build on the build platform and cross-compile for the target platform, so
# multi-platform builds don't compile under QEMU emulation. promrated has no cgo
# dependencies, so a pure Go build cross-compiles without a C toolchain.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS builder

# Install dependencies (git for VCS build info)
RUN apk add --no-cache git

WORKDIR /app

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
  go build -o promrated github.com/obolnetwork/charon/testutil/promrated/promrated

FROM alpine:3.24

COPY --from=builder /app/promrated /app/promrated

# Don't run container as root
ENV USER=promrated
ENV UID=1000
ENV GID=1000
RUN addgroup -g "$GID" "$USER"
RUN adduser \
    --disabled-password \
    --gecos "promrated" \
    --home "/opt/$USER" \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER"
RUN chown promrated /app/promrated
RUN chmod u+x /app/promrated
WORKDIR "/opt/$USER"
USER promrated

CMD ["/app/promrated"]

# Used by GitHub to associate container with repo.
LABEL org.opencontainers.image.source="https://github.com/obolnetwork/charon/testutil/promrated"
LABEL org.opencontainers.image.title="promrated"
LABEL org.opencontainers.image.licenses="GPL v3"
