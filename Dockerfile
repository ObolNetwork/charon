#syntax=docker/dockerfile:1.2

# Container for building Go binary.
FROM golang:1.17-alpine AS builder
# Cgo support
RUN apk add --no-cache build-base
# Copy app.
WORKDIR /app
COPY . .
# Build with Go module and Go build caches.
RUN \
   --mount=type=cache,target=/go/pkg \
   --mount=type=cache,target=/root/.cache/go-build \
   go build -o charon ./cmd

# Copy final binary into light stage.
FROM alpine:3
COPY --from=builder /app/charon /usr/local/bin/
CMD ["/usr/local/bin/charon"]
# Used by GitHub to associate container with repo.
LABEL org.opencontainers.image.source="https://github.com/ObolNetwork/charon"
