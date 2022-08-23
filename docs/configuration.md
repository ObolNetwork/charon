# Charon Configuration

This document describes the configuration options for running a charon node and cluster locally or in production.

## Cluster Config Files

A charon cluster is configured in two steps:
- `cluster-definition.json` which defines the intended cluster configuration without validator keys.
- `cluster-lock.json` which includes and extends `cluster-definition.json` with distributed validator bls public key shares.

The `charon create dkg` command is used to create `cluster-definition.json` file which is used as input to `charon dkg`.

The `charon create cluster` command combines both steps into one and just outputs the final `cluster-lock.json` without a DKG step.

The schema of the `cluster-definition.json` is defined as:
```json
{
  "name": "best cluster",                       // Optional cosmetic identifier
  "operators": [
    {
      "address": "0x123..abfc",                 // ETH1 address of the operator
      "enr": "enr://abcdef...12345",            // Charon node ENR
      "nonce": 1,                               // Nonce (incremented each time the ENR is added/signed)
      "config_signature": "0x123456...abcdef",    // EIP712 Signature of config_hash by ETH1 address priv key
      "enr_signature": "0x123654...abcedf"        // EIP712 Signature of ENR by ETH1 address priv key
    }
  ],
  "uuid": "1234-abcdef-1234-abcdef",            // Random unique identifier.
  "version": "v1.2.0",                          // Schema version
  "timestamp": "2022-01-01T12:00:00+00:00",     // Creation timestamp
  "num_validators": 100,                        // Number of distributed validators to be created in cluster.lock
  "threshold": 3,                               // Optional threshold required for signature reconstruction
  "fee_recipient_address":"0x123..abfc",        // ETH1 fee_recipient address
  "withdrawal_address": "0x123..abfc",          // ETH1 withdrawal address
  "dkg_algorithm": "foo_dkg_v1" ,               // Optional DKG algorithm for key generation
  "fork_version": "0x00112233",                 // Chain/Network identifier
  "config_hash": "abcfde...acbfed",             // Hash of the static (non-changing) fields
  "definition_hash": "abcdef...abcedef"         // Final hash of all fields
}
```

The above `cluster-definition.json` is provided as input to the DKG which generates keys and the `cluster-lock.json` file.

The `cluster-lock.json` has the following schema:
```json
{
  "cluster_definition": {...},                              // Cluster definiition json, identical schema to above,
  "distributed_validators": [                               // Length equal to num_validators.
    {
      "distributed_public_key":  "0x123..abfc",             // DV root pubkey
      "public_shares": [ "abc...fed", "cfd...bfe"],         // length of num_operators
      "fee_recipient": "0x123..abfc"                        // Defaults to withdrawal address if not set, can be edited manually
    }
  ],
  "lock_hash": "abcdef...abcedef",                          // Config_hash plus distributed_validators
  "signature_aggregate": "abcdef...abcedef"                 // BLS aggregate signature of the lock hash signed by each DV pubkey.
}
```

`charon run` just requires a `cluster-lock.json` file to configure the cluster.

### Cluster Config Change Log

The following is the historical change log of the cluster config:
- `v1.2.0` **draft**:
  - Refactored all base64 fields to Ethereum's standard 0x prefixed hex.
    - Refactored definition operator signatures: `config_signature` and `enr_signature`.
    - Refactored definition fields: `config_hash` and `definition_hash`.
    - Refactored lock fields: `lock_hash`, `signature_aggregate` and `distributed_validators.public_shares`.
  - See example [definition.json](../cluster/testdata/definition_v1_2_0.json) and [lock.json](../cluster/testdata/lock_v1_2_0.json)
- `v1.1.0` **default**:
  - Added cosmetic `Timestamp` field to cluster definition to help identification by humans.
  - See example [definition.json](../cluster/testdata/definition_v1_1_0.json) and [lock.json](../cluster/testdata/lock_v1_1_0.json)
- `v1.0.0`:
  - Initial definition and lock versions.
  - See example [definition.json](../cluster/testdata/definition_v1_0_0.json) and [lock.json](../cluster/testdata/lock_v1_0_0.json)

This version of Charon (logic) supports the following cluster config versions (files): `v1.0.0`, `v1.1.0`, `v1.2.0`.

## Flag Precedence

Charon uses [viper](https://github.com/spf13/viper) for configuration combined with [cobra](https://github.com/spf13/cobra)
for cli commands.

In descending order, the Charon node checks the following places for configuration:
- From environment vars beginning with `CHARON_`, with hyphens substituted for underscores. e.g. `CHARON_BEACON_NODE=http://....`
- From the config file specified with the `-config-file` flag as YAML, e.g. `beacon-node: http://...`
- From CLI params, e.g. `--beacon-node http://...`

## Configuration Options
The following is the output of `charon run --help` and provides the available configuration options.

<!-- Code below generated by cmd/cmd_internal_test.go#TestConfigReference. DO NOT EDIT -->
````
Starts the long-running Charon middleware process to perform distributed validator duties.

Usage:
  charon run [flags]

Flags:
      --beacon-node-endpoint string     Beacon node endpoint URL. Deprecated, please use beacon-node-endpoints.
      --beacon-node-endpoints strings   Comma separated list of one or more beacon node endpoint URLs.
      --builder-api                     Enables the builder api. Will only produce builder blocks. Builder API must also be enabled on the validator client. Beacon node must be connected to a builder-relay to access the builder network.
      --data-dir string                 The directory where charon will store all its internal data (default ".charon")
      --feature-set string              Minimum feature set to enable by default: alpha, beta, or stable. Warning: modify at own risk. (default "stable")
      --feature-set-disable strings     Comma-separated list of features to disable, overriding the default minimum feature set.
      --feature-set-enable strings      Comma-separated list of features to enable, overriding the default minimum feature set.
  -h, --help                            Help for run
      --jaeger-address string           Listening address for jaeger tracing.
      --jaeger-service string           Service name used for jaeger tracing. (default "charon")
      --lock-file string                The path to the cluster lock file defining distributed validator cluster. (default ".charon/cluster-lock.json")
      --log-format string               Log format; console, logfmt or json (default "console")
      --log-level string                Log level; debug, info, warn or error (default "info")
      --monitoring-address string       Listening address (ip and port) for the monitoring API (prometheus, pprof). (default "127.0.0.1:3620")
      --no-verify                       Disables cluster definition and lock file verification.
      --p2p-allowlist string            Comma-separated list of CIDR subnets for allowing only certain peer connections. Example: 192.168.0.0/16 would permit connections to peers on your local network only. The default is to accept all connections.
      --p2p-bootnode-relay              Enables using bootnodes as libp2p circuit relays. Useful if some charon nodes are not have publicly accessible.
      --p2p-bootnodes strings           Comma-separated list of discv5 bootnode URLs or ENRs. (default [http://bootnode.lb.gcp.obol.tech:3640/enr])
      --p2p-bootnodes-from-lockfile     Enables using cluster lock ENRs as discv5 bootnodes. Allows skipping explicit bootnodes if key generation ceremony included correct IPs.
      --p2p-denylist string             Comma-separated list of CIDR subnets for disallowing certain peer connections. Example: 192.168.0.0/16 would disallow connections to peers on your local network. The default is to accept all connections.
      --p2p-external-hostname string    The DNS hostname advertised by libp2p. This may be used to advertise an external DNS.
      --p2p-external-ip string          The IP address advertised by libp2p. This may be used to advertise an external IP.
      --p2p-tcp-address strings         Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. (default [127.0.0.1:3610])
      --p2p-udp-address string          Listening UDP address (ip and port) for discv5 discovery. (default "127.0.0.1:3630")
      --simnet-beacon-mock              Enables an internal mock beacon node for running a simnet.
      --simnet-validator-mock           Enables an internal mock validator client when running a simnet. Requires simnet-beacon-mock.
      --validator-api-address string    Listening address (ip and port) for validator-facing traffic proxying the beacon-node API. (default "127.0.0.1:3600")

````
<!-- Code above generated by cmd/cmd_internal_test.go#TestConfigReference. DO NOT EDIT -->
