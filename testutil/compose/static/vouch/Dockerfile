FROM wealdtech/ethdo:1.30.0 as ethdo

FROM attestant/vouch:1.7.5

COPY --from=ethdo /app/ethdo /app/ethdo

RUN apt-get update && apt-get install -y curl jq wget

ENTRYPOINT ["/compose/vouch/run.sh"]
