FROM wealdtech/ethdo:1.35.2 as ethdo

FROM attestant/vouch:1.11.0

COPY --from=ethdo /app/ethdo /app/ethdo

RUN apt-get update && apt-get install -y curl jq wget

ENTRYPOINT ["/compose/vouch/run.sh"]
