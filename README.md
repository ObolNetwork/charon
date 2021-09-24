![Obol Logo](https://obol.tech/obolnetwork.png)

<h1 align="center">Obol Client</h1>

This repo contains the source code for the Obol Client, a middleware HTTP client and server for Ethereum Staking that enables HA validation through the use of the Shared Secret Validator staking model.

Obol is used by Enterprises and DAOs to distribute the responsibility of running Ethereum Validators.

## Quickstart

This repo contains the GoLang source code for the middleware, a docker-compose file for deploying the client in a local dev environment, and deployment files for deploying this client to a test cluster. To get started:

```bash
# Setup env vars, copy .env.template and then manually enter the correct secrets for the likes of Eth1 nodes etc.
cp .env.template .env

# Local development
make up
```

## To Do List
- [ ] Beacon client syncing
- [ ] Validator client connected
- [ ] Nginx pass through proxy server
- [ ] GoLang pass through proxy server
- [ ] Docker Compose file for running an SSV
- [ ] Github CI for GoLang build of source
- [ ] Github CI for Docker build

## Lessons Learned

- I don't want to wait to sync a full testnet, what can I do?
    - You can use what's called wak subjectivity sync, which basically accepts a checkpoint from another node and starts from there. You can get a checkpoint from infura by calling (with the appropriate env vars set):
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