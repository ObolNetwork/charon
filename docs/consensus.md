# Consensus

This document describes how Charon handles various consensus protocols.

## Overview

Historically, Charon has supported the single consensus protocol QBFT v2.0.
However, now the consensus layer has a pluggable interface that allows running different consensus protocols as long as they are available and accepted by the majority of the cluster. Moreover, the cluster can run multiple consensus protocols at the same time, e.g., for different purposes.

## Consensus Protocol Selection

The cluster nodes must agree on the preferred consensus protocol to use, otherwise, the entire consensus will fail.
Each node, depending on its configuration and software version, may prefer one or more consensus protocols in a specific order of precedence.
Charon runs a special protocol called Priority, which achieves consensus on the preferred consensus protocol to use.
Under the hood, this protocol uses the existing QBFT v2.0 algorithm that has been present since v0.19 and must not be deprecated.
This way, the existing QBFT v2.0 remains present for all future Charon versions to serve two purposes: running the Priority protocol and being a fallback protocol if no other protocol is selected.

### Priority Protocol Input and Output

The input to the Priority protocol is a list of protocols defined in order of precedence, e.g.:

```json
[
  "/charon/consensus/hotstuff/1.0.0", // Highest precedence
  "/charon/consensus/abft/2.0.0",
  "/charon/consensus/abft/1.0.0",
  "/charon/consensus/qbft/2.0.0" // Lowest precedence and the fallback since it is always present
]
```

The output of the Priority protocol is the common "subset" of all inputs, respecting the initial order of precedence, e.g.:

```json
[
  "/charon/consensus/abft/1.0.0", // This means the majority of nodes have this protocol available
  "/charon/consensus/qbft/2.0.0"
]
```

Eventually, more nodes will upgrade and therefore start preferring newer protocols, which will change the output. Because we know that all nodes must at least support QBFT v2.0, it becomes the fallback option in the list and the "default" protocol. This way, the Priority protocol will never get stuck and can't produce an empty output.

The Priority protocol runs once per epoch (the last slot of each epoch) and changes its output depending on the inputs. If another protocol starts to appear at the top of the list, Charon will switch the consensus protocol to that one starting in the next epoch.

### Changing Consensus Protocol Preference

A cluster creator can specify the preferred consensus protocol in the cluster configuration file. This new field `consensus_protocol` appeared in the cluster definition file from v1.9 onwards. The field is optional and if not specified, the cluster definition will not impact the consensus protocol selection.

A node operator can also specify the preferred consensus protocol using the new CLI flag `--consensus-protocol` which has the same effect as the cluster configuration file, but it has a higher precedence. The flag is also optional.

In both cases, a user is supposed to specify the protocol family name, e.g. `abft` string and not a fully-qualified protocol ID.
The precise version of the protocol is to be determined by the Priority protocol, which will try picking the latest version.
To list all available consensus protocols (with versions), a user can run the command `charon version --verbose`.

When a node starts, it sequentially mutates the list of preferred consensus protocols by processing the cluster configuration file and then the mentioned CLI flag. The final list of preferred protocols is then passed to the Priority protocol for cluster-wide consensus. Until the Priority protocol reaches consensus, the cluster will use the default QBFT v2.0 protocol for any duties.

## Consensus Round Duration

Round timing is defined by timers and extensions. All nodes in a cluster must use the same timers and extensions, since their rounds must end at the same times.

### Timers

A timer is a named configuration of round timing, defined by:

- its **round durations**: the first round lasts `first`, the next `steps` rounds last `step` each, and every later round grows by a further `growth`;
- its **anchor**, when its rounds start: either the **duty start**, the duty's offset into the slot, where the first round starts at that absolute time and later rounds follow on, aligning round start times across peers; or the legacy **local duty start**, where the first round starts when the duty starts on this node and each later round when this node enters it, so rounds drift apart across peers;
- its **extensions**, such as how a round is extended when it is armed again. QBFT arms a round again upon a justified pre-prepare for it.

| Timer | first | step | steps | growth | Round durations | Anchor | Extensions |
|---|---|---|---|---|---|---|---|
| `inc` | 1s | 1s | 0 | 250ms | 1s, 1.25s, 1.5s, ... | local duty start | `reset_on_rearm` |
| `linear` | 1s | 200ms | 0 | 200ms | 1s, 400ms, 600ms, ... | local duty start | `reset_on_rearm` |
| `eager_dlinear` | 1s | 1s | 0 | 0 | 1s, 1s, 1s, ... | duty start | `double_on_rearm` |

Timers are selected per duty by feature set flags:

- `eager_dlinear` is the default, enabled by the stable `eager_double_linear` feature.
- `inc` is used when `eager_double_linear` is disabled (`--feature-set-disable "eager_double_linear"`).
- `linear` is used for proposer duties when the alpha `linear` feature is enabled (`--feature-set-enable "linear"`), taking precedence over the other timers. Its first round includes fetching the proposal. Peers already have their proposal in later rounds, which start shorter, skipping underperforming leaders quicker.

### Extensions

Extensions can be plugged into any timer: timers declare their own extensions, and the selection adds extensions for duties. An extension never changes a timer's definition: its `first`, `step`, `steps` and `growth` values stay as listed above. Instead, it acts on top of them when a round is armed or re-armed, and that still changes how long the affected rounds actually last.

Each extension states when it acts, under what condition and what it changes:

| Extension | Acts | Condition | Changes | In practice |
|---|---|---|---|---|
| `proposal_timeout` | When the first round is armed | Proposer duties, enabled by default as the `proposal_timeout` feature is stable | Adds 500ms to the first round's duration | Applicable to every timer by default |
| `reset_on_rearm` | When a round is re-armed | Always on for the `inc` and `linear` timers | The round's timer resets | Only clusters that disabled `eager_double_linear` or enabled the alpha `linear` timer (proposer duties only). Only used whenever a node receives the round leader's justified pre-prepare |
| `double_on_rearm` | When a round is re-armed | Always on for the `eager_dlinear` timer | Extends the round by the time from the first round's start to its deadline | Every duty by default, as `eager_dlinear` is the default timer. Only used whenever a node receives the round leader's justified pre-prepare |

`proposal_timeout` applies to whichever timer is selected for a proposer duty. On `eager_dlinear`, since its rounds follow on, the longer first round moves every round end 500ms later (1.5s, 2.5s, 3.5s, ...).

`double_on_rearm` keeps round end times aligned across peers. Resetting the round's timer instead has no effect on the leader, who resets at the start of the round, while it has a large effect on the other peers, who reset when they receive the justified pre-prepare.

The timer and extensions of each consensus instance are logged when it starts, e.g. `timer=eager_dlinear timer_extensions=[double_on_rearm proposal_timeout]`.

## Observability

The four existing metrics are reflecting the consensus layer behavior:

- `core_consensus_decided_rounds`
- `core_consensus_decided_leader_index`
- `core_consensus_duration_seconds`
- `core_consensus_error_total`
- `core_consensus_timeout_total`

With the new capability to run different consensus protocols, all these metrics now populate the `protocol` label which allows distinguishing between different protocols.
Note that a cluster may run at most two different consensus protocols at the same time, e.g. QBFT v2.0 for Priority and HotStuff v1.0 for validator duties. But this can be changed in the future and more different protocols can be running at the same time.
Therefore the mentioned metrics may have different unique values for the `protocol` label.

Some protocols may export their own metrics. We agreed that all such metrics should be prefixed with the protocol name, e.g. `core_consensus_hotstuff_xyz`.

## Debugging

Charon handles `/debug/consensus` HTTP endpoint that responds with `consensus_messages.pb.gz` file containing certain number of the last consensus messages (in protobuf format).
All consensus messages are tagged with the corresponding protocol ID, in case of multiple protocols running at the same time.

## Protocol Specific Configuration

Each consensus protocol may have its own configuration parameters. For instance, QBFT v2.0 has two parameters: `eager_double_linear` and `consensus_participate` that users control via Feature set.
For future protocols we decided to follow the same design and allow users to control the protocol-specific parameters via Feature set.
Charon will set the recommended default values to all such parameters, so node operators don't need to override them unless they know what they are doing. Note that Priority protocol does not take into account any variations caused by different parameters, therefore node operators must be careful when changing them and make sure all nodes have the same configuration.
