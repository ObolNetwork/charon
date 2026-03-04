---
name: consensus-leader
description: Calculate consensus leader sequence for a given slot and cluster
user-invokable: true
---

# Consensus Leader

Calculate the consensus leader sequence for a given slot number using the QBFT leader election formula.

## Arguments

The user must provide:
- **cluster name** (required): e.g. `Lido x Obol: Ethereal Elf`
- **slot number** (required): e.g. `13813408`
- **network** (optional, default: `mainnet`): e.g. `mainnet`, `hoodi`
- **duty type** (optional, default: `proposer`): e.g. `proposer`, `attester`, `randao`, `sync_message`

## Duty Types

Valid duty types (from `core/types.go`):
- `proposer` (1) - block proposal
- `attester` (2) - attestation
- `signature` (3) - generic signature
- `exit` (4) - voluntary exit
- `builder_registration` (6) - MEV builder registration
- `randao` (7) - RANDAO reveal
- `prepare_aggregator` (8) - aggregator preparation
- `aggregator` (9) - attestation aggregation
- `sync_message` (10) - sync committee message
- `prepare_sync_contribution` (11) - sync contribution preparation
- `sync_contribution` (12) - sync committee contribution
- `info_sync` (13) - info sync

## Execution

Run the script with the required arguments:
```bash
bash scripts/consensus-leader.sh "<cluster_name>" <slot> [network] [duty_type]
```

## Leader Election Formula

The consensus leader for each round is calculated as:
```
leader_index = (slot + duty_type + round) % num_nodes
```

Where:
- `slot` is the beacon chain slot number
- `duty_type` is the numeric value of the duty type
- `round` is the QBFT consensus round (1, 2, or 3)
- `num_nodes` is the number of operators in the cluster

## Output

Present the results to the user including:
- **Slot Info**: slot number, epoch, slot within epoch, absolute time (UTC)
- **Network**: the Ethereum network
- **Duty**: the duty type being calculated
- **Leaders**: table showing round number, leader index, and peer name for rounds 1-3

This helps diagnose consensus issues by identifying which node was responsible for leading each round.
