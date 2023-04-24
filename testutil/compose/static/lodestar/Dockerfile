# TODO(dhruv): use official release version tag.
FROM chainsafe/lodestar:next

RUN apk update && apk add curl jq wget

ENV YQ_VERSION=v4.23.1
ENV YQ_BINARY=yq_linux_amd64

RUN wget https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY} -O /usr/bin/yq \
    && chmod +x /usr/bin/yq

ENTRYPOINT ["/compose/lodestar/run.sh"]
