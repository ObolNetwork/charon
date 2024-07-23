FROM sigp/lighthouse:v5.2.1

ENV YQ_VERSION=v4.42.1

RUN apt-get update && apt-get install -y curl jq wget

RUN \
    march="$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/)"; \
    case "$march" in \
        arm64) export YQ_BINARY=yq_linux_arm64 ;; \
        amd64) export YQ_BINARY=yq_linux_amd64 ;; \
    esac; \
    wget https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY} -O /usr/bin/yq \
    && chmod +x /usr/bin/yq

ENTRYPOINT ["/compose/lighthouse/run.sh"]
