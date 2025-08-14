FROM golang:1.25.0-alpine AS builder

# Install dependencies
RUN apk add --no-cache build-base git

WORKDIR /app

COPY . .

# Build with Go module and Go build caches.
RUN go build -o promrated github.com/obolnetwork/charon/testutil/promrated/promrated

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
