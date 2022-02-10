# Lessons and Bugs

The following is a collection of bugs and gotchas encountered while developing with the Charon codebase, maybe these can help people that get stuck on similar issues.

## Lessons Learned

- I don't want to wait to sync a full testnet, what can I do?
    - You can use what's called weak subjectivity sync, which basically accepts a checkpoint from another node and starts from there. You can get a checkpoint from infura by calling (with the appropriate env vars set):
    ```log
    curl https://${INFURA_PROJECT_ID}:${INFURA_PROJECT_SECRET}@eth2-beacon-prater.infura.io/eth/v1/beacon/states/finalized/finality_checkpoints
    ```
    - Then take the state root from this response + the epoch and set them in the `TEKU_WS_CHECKPOINT` env var and restart your docker-compose. Teku should start a sync from the checkpoint epoch you've given it instead of from the start.

## Bugs encountered / gotchas

- Teku fails to start on a new chain if there is data in the temporary db stored in `./local/.data/teku/`. Error is like:
    ```log
    beacon  | Supplied deposit contract (0x77f7bed277449f51505a4c54550b074030d989bc) does not match the stored database (). Check that the existing database matches the current network settings.
    ```
    - Fixed by `rm -rf ./local/.data/teku`

- `charon test beacon` errors with an error something like: `panic: parse 192.168.2.2:5051: first path segment in URL cannot contain colon`.
    - The issue is `beacon-node` URIs need to specify a `scheme`, prepend IP addresses with `http://`.

- If you put your laptop into standby while running the local containers (e.g. overnight), when your computer un-suspends, prometheus will fail to scrape endpoints with errors like `unable to append`, `out of bounds`, `time too far into the past or too far into the future`.
    - The issue is the containers system clocks get way out of sync. Fix by turning them off and on again, classic.
