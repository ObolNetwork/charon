# Container for building Go binary.
FROM golang:1.18-alpine AS builder
# Install dependencies
RUN apk add --no-cache build-base git
# Prep and copy source
WORKDIR /app
COPY . .
# Build with Go module and Go build caches.
RUN \
   --mount=type=cache,target=/go/pkg \
   --mount=type=cache,target=/root/.cache/go-build \
   go build -o charon .

# Copy final binary into light stage.
FROM alpine:3
ARG GITHUB_SHA=local
ENV GITHUB_SHA=${GITHUB_SHA}
COPY --from=builder /app/charon /usr/local/bin/
# Don't run container as root
ENV USER=charon
ENV UID=1000
ENV GID=1000
RUN addgroup -g "$GID" "$USER"
RUN adduser \
    --disabled-password \
    --gecos "charon" \
    --home "/opt/$USER" \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER"
RUN chown charon /usr/local/bin/charon
RUN chmod u+x /usr/local/bin/charon
WORKDIR "/opt/$USER"
USER charon
ENTRYPOINT ["/usr/local/bin/charon"]
CMD ["run"]
# Used by GitHub to associate container with repo.
LABEL org.opencontainers.image.source="https://github.com/obolnetwork/charon"
LABEL org.opencontainers.image.title="charon"
LABEL org.opencontainers.image.description="Proof of Stake Ethereum Distributed Validator Client"
LABEL org.opencontainers.image.licenses="GPL v3"
LABEL org.opencontainers.image.documentation="https://github.com/ObolNetwork/charon/tree/main/docs"
