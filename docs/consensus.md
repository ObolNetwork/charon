# Consensus

This document describes how Charon handles various consensus protocols.

## Overview

Historically, Charon has supported the single consensus protocol QBFT v2.0.
However, now the consensus layer has pluggable interface which allows running different consensus protocols as long as they are available and accepted by cluster's quorum.

## Consensus Protocol Selection

The cluster nodes must agree on the preferred consensus protocol to use, otherwise the entire consensus would fail.
Each node, depending on its configuration and software version may prefer one or more consensus protocols in a specific order of preference.
Charon runs the special protocol called Priority which achieves consensus on the preferred consensus protocol to use.
Under the hood this protocol uses the existing QBFT v2.0 algorithm that is known to be present since v0.19 up until now and must not be deprecated.

### Priority Protocol Input and Output

The input to the Priority protocol is a list of protocols defined in the order of precedence, e.g.:

```json
[
    "/charon/consensus/hotstuff/1.0.0", // Highest precedence
    "/charon/consensus/abft/2.0.0",
    "/charon/consensus/abft/1.0.0",
    "/charon/consensus/qbft/2.0.0",     // Lowest precedence and the last resort
]
```

The output of the Priority protocol is the common "subset" of all inputs respecting the initial order of precedence, e.g.:

```json
[
    "/charon/consensus/abft/1.0.0", // This means the quorum of nodes has this protocol in common
    "/charon/consensus/qbft/2.0.0",
]
```

Eventually, more nodes will upgrade and therefore start preferring newest protocols, which will change the output. Because we know that all nodes must at least support QBFT v2.0, it becomes the last resort option in the list and the "default" protocol. This way, Priority protocol would never get stuck and can't produce an empty output.

The Priority protocol runs once per epoch and changes its output depending on the inputs. If another protocol started to appear at the top of the list, Charon would switch the consensus protocol to that one with the next epoch.

### Changing Consensus Protocol Preference

A cluster creator can specify the preferred consensus protocol in the cluster configuration file. This new field `consensus_protocol` appeared in the cluster definition file from v1.9 onwards. The field is optional and if not specified, the cluster definition will not impact the consensus protocol selection.

A node operator can also specify the preferred consensus protocol using the new CLI flag `--consensus-protocol` which has the same effect as the cluster configuration file, but it has a higher precedence. The flag is also optional.

In both cases, a user is supposed to specify the protocol family name, e.g. `abft` string and not a fully-qualified ID. The precise version of the protocol is to be determined by the Priority protocol.
To list all available consensus protocols (with versions), a user can run the command `charon version --verbose`.

When a node starts, it sequentially mutates the list of preferred consensus protocols by processing the cluster configuration file and then the mentioned CLI flag. The final list of preferred protocols is then passed to the Priority protocol for cluster-wide consensus. Until the Priority protocol reaches consensus, the cluster will use the default QBFT v2.0 protocol.

## Observability

The four existing metrics are reflecting the consensus layer behavior:

- `core_consensus_decided_rounds`
- `core_consensus_duration_seconds`
- `core_consensus_error_total`
- `core_consensus_timeout_total`

With the new capability to run different consensus protocols, all these metrics now populate the `protocol` label which allows distinguishing between different protocols.
Note that a cluster may run at most two different consensus protocols at the same time, e.g. QBFT v2.0 for Priority and HotStuff v1.0 for validator duties.
Therefore the mentioned metrics will have at most two unique values in the `protocol` label.

## Debugging

Charon will handle `/debug/consensus` HTTP endpoint that would respond with `consensus_messages.pb.gz` file containing some number of the last consensus messages (protobuf format).
All consensus messages are tagged with the corresponding protocol id, in case of multiple protocols running at the same time.
