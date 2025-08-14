# Container for building Go binary.
FROM golang:1.25.0-bookworm AS builder
# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git

# Prep and copy source
WORKDIR /app/charon

COPY . .

# Populate GO_BUILD_FLAG with a build arg to provide an optional go build flag.
ARG GO_BUILD_FLAG
ENV GO_BUILD_FLAG=${GO_BUILD_FLAG}
RUN echo "Building with GO_BUILD_FLAG='${GO_BUILD_FLAG}'"

# Build with Go module and Go build caches.
RUN \
   --mount=type=cache,target=/go/pkg \
   --mount=type=cache,target=/root/.cache/go-build \
   go build -o charon "${GO_BUILD_FLAG}" .
RUN echo "Built charon version=$(./charon version)"

# Copy final binary into light stage.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates fio wget \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
ARG GITHUB_SHA=local
ENV GITHUB_SHA=${GITHUB_SHA}

COPY --from=builder /app/charon/charon /usr/local/bin/

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
LABEL org.opencontainers.image.documentation="https://github.com/ObolNetwork/charon/tree/main/docs"
