# Charon Networking

This document describes the Charon DVT networking model.

## Overview

The networking model can therefore be divided into two parts:
- **Internal Validator Stack**: `Validator client -> Charon -> Beacon node -> Execution client`
  - Charon is middleware DVT client and is therefore connected to an upstream beacon node and a downstream validator client is connected to it.
  - Each operator should run the whole validator stack (all 4 client software types), either on the same machine or on different machines.
  - The networking between the nodes should be private and not exposed to the public internet.
  - Charon is configured to connect to the beacon node via the `--beacon-node-endpoints` flag.
  - Charon is configured to listen and serve requests from the validator client via the `--validator-api-address` flag.
- **External P2P Network**: `Charon <-> Charon <-> Charon <-> Charon`
  - The Charon nodes in a DVT cluster are connected to each other via a small p2p network consisting of only the nodes in the cluster.
  - Peer addresses are discovered via an external "relay" server. Obol hosts public relay server for this purpose, but anyone can host their own.
  - The p2p networking is over the public internet so the charon p2p port must be publicly accessible.
  - Charon is configured to listen and serve p2p requests via the `--p2p-tcp-addresses` flag.
  - Charon is configured to connect to one or more relay servers via the `--p2p-relays` flag.

![Example Obol Cluster](./images/DVCluster.png)
