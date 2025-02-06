# Charon Distributed Validator Key Generation

## Contents

- Overview
- Actors involved
- Carrying out the DKG ceremony
- Backing up ceremony artifacts
- Preparing for validator activation
- DKG verification
- Appendix

## Overview

To make a distributed validator with fault-tolerance (i.e., allowing some nodes to go offline while others stay online), the key shares need to be generated together. This is especially necessary due to the BLS signature scheme used by Proof of Stake Ethereum. While each key share could be chosen by operators independently, creating a distributed validator that remains operational when some nodes go offline requires coordinated generation of key shares. This process is known as Distributed Key Generation (DKG).

The Charon client is responsible for securely completing a distributed key generation ceremony with its counterparty nodes. The ceremony configuration is outlined in the [cluster configuration](https://docs.obol.tech/docs/dv/distributed-validator-cluster-manifest).

## Actors Involved

A distributed key generation ceremony involves `Operators` and their `Charon clients`.

- An `Operator` is identified by their Ethereum address. They will sign with this address's private key to authenticate their Charon client ahead of the ceremony. The signature will be of a hash of the Charon client’s ENR public key, the `cluster_definition_hash`, and an incrementing `nonce`, allowing for a direct linkage between a user, their Charon client, and the cluster this client is intended to service, while retaining the ability to update the Charon client by incrementing the nonce value and re-signing, in line with the standard ENR spec.

- A `Charon client` is also identified by a public/private key pair. In this instance, the public key is represented as an [Ethereum Node Record](https://eips.ethereum.org/EIPS/eip-778) (ENR), a standard identity format for both EL and CL clients. These ENRs are used by each Charon node to identify its cluster peers over the internet and to communicate in an [end-to-end encrypted manner](https://github.com/libp2p/go-libp2p-noise). These keys need to be created by each operator before they can participate in a cluster creation.

## Cluster Definition Creation

This cluster-definition file is created with the help of the [Distributed Validator Launchpad](https://docs.obol.tech/docs/dvk/distributed_validator_launchpad). The creation process involves several steps:

- A `leader` Operator, wishing to coordinate the creation of a new Distributed Validator Cluster, navigates to the launchpad and selects "Create new Cluster".
- The `leader` uses the interface to configure important details, including:
  - The `withdrawal address` for the created validators.
  - The `feeRecipient` for block proposals (if different from the withdrawal address).
  - The number of distributed validators to create.
  - The list of participants in the cluster (specified by Ethereum address/ENS).
  - The threshold of fault tolerance required (if not using the safe default).
  - The network (fork_version/chainId) that this cluster will validate on.
- These key pieces of information form the basis of the cluster configuration. These fields (along with technical fields like the DKG algorithm to use) are serialized and merklized to produce the manifest `cluster_definition_hash`. This Merkle root ensures no ambiguity or deviation between manifests when provided to Charon nodes.
- Once the leader is satisfied with the configuration, they publish it to the launchpad's data availability layer for other participants to access. (Initially, the launchpad uses a centralized backend DB to store the cluster configuration. Later, solutions like IPFS or Arweave may offer better decentralization.)
- The leader shares the URL to this ceremony with their intended participants.
- Anyone clicking the ceremony URL, or inputting the `config_hash` on the landing page, is directed to the ceremony status page (after completing disclaimers and advisories).
- A "Connect Wallet" button appears beneath the ceremony status container. If a participant connects a wallet not in the participant list, the button disables as there is nothing to do. If the participant connects a wallet in the list, they are prompted to input the ENR of their Charon node.
  - Once the ENR field is populated and validated, the participant can click the "Confirm Cluster Configuration" button. This triggers one or two signatures:
    - The participant signs the `config_hash` to confirm their consent.
    - The participant signs their Charon node's ENR to authenticate and authorize that node to participate on their behalf.
  - These signatures are sent to the data availability layer for validation. If the signatures are correct, the `config_hash` and the ENR + signature are saved to the cluster definition object.
- All participants must sign the `config_hash` and submit a signed ENR before the DKG ceremony begins. The status page will show which signatures are still pending.
- Once all participants have signed and submitted their Charon node ENRs, the cluster-definition file can be downloaded by clicking `Download Cluster Definition`.
- At this point, each participant must load this cluster-definition into their Charon client, which will attempt to complete the DKG.

## Carrying out the DKG ceremony

Once participants have their cluster-definition file, they will pass it to Charon's `dkg` command. Charon will read the ENRs in the cluster-definition, confirm that its own ENR is present, and reach out to bootnodes to find other ENRs on the network. (New ENRs have only a public key and an IP address of 0.0.0.0 until loaded into a live Charon client, which will update the IP address and increment the ENR's nonce, resigning with the client’s private key. If an ENR with a higher nonce is detected, the Charon client will update its address book.)

Once all clients in the cluster establish connections with one another and complete a handshake (confirming everyone has a matching `cluster_definition_hash`), the ceremony begins.

No user input is required. Charon does the work and outputs the following files to each machine before exiting:

```sh
./cluster-definition.json   # The original cluster definition file from the DV Launchpad
./cluster-lock.json         # New lockfile based on cluster-definition.json with validator group public keys and public shares included
./charon/enr_private_key    # Created before the ceremony took place [Backup this file]
./charon/validator_keys/    # Folder of key shares to be backed up and moved to validator clients [Backup these files]
./charon/deposit_data*      # JSON files of deposit data for the distributed validators
./charon/exit_data          # JSON file of exit data that ethdo can broadcast
```

## Backing up the ceremony artifacts

Once the ceremony is complete, all participants should back up the created files. In future versions of Charon, if a participant loses access to their key shares, it will be possible to use a key re-sharing protocol to replace the old keys with new ones, allowing the cluster to recover from lost key shares. However, without a backup, the safest option is to exit the validator.

## Preparing for validator activation

After the ceremony is complete and secure backups of key shares have been made, each operator must load these key shares into their validator clients and run the `charon run` command to activate the validator.

All operators should confirm that their Charon client logs indicate that all nodes are online and connected. They should also verify the readiness of their beacon and validator clients. Charon's Grafana dashboard is a helpful tool for monitoring the readiness of the full cluster.

Once all operators are satisfied with network connectivity, one member can use the Obol Distributed Validator deposit flow to send the required ether and deposit data to the deposit contract, initiating the process of distributed validator activation. Good luck!

## DKG Verification

For many use cases, the funder/depositor of the validator may not be the same person as the key creators or node operators. This handover introduces a point of trust. How can someone verify that a proposed validator’s `deposit data` corresponds to a real, fair DKG with the participants the depositor expects?

Here are some verification steps that can be performed:

- **Do the public key shares combine to form the group public key?**
  - This can be verified on-chain, without requiring a pairing operation.
  - This check ensures that a BLS public key represents a Distributed Validator but doesn’t address key custody. (For example, did a Sybil attack occur, or was there collusion to reconstitute the group private key?)
  
- **Do the created BLS public keys attest to their `cluster_definition_hash`?**
  - This provides a backwards link between BLS public keys and the Ethereum addresses of operators involved in their creation.
  - If the BLS group public key can produce a signature for the `cluster_definition_hash`, it indicates that at least a threshold of operators signed this data.
  - Since the `cluster_definition_hash` is the same for all validators in the ceremony, signatures can be aggregated into a group signature, verifying all group keys at once and reducing the cost of on-chain verification.

- **Is there a VSS or PVSS proof of a fair DKG ceremony?**
  - VSS (Verifiable Secret Sharing) allows only operators to verify fairness, requiring knowledge of one of the secrets.
  - PVSS (Publicly Verifiable Secret Sharing) allows anyone to verify fairness, typically using Zero Knowledge Proofs.
  - A PVSS of a fair DKG makes it more difficult for operators to collude and compromise the Distributed Validator's security.
  - Zero Knowledge Proof verification on-chain is currently expensive but achievable through the ongoing work of ZK-based teams in the industry.

## Appendix

### Using DKG without the launchpad

Charon clients can perform a DKG with a cluster-definition file that does not contain operator signatures if the `--no-verify` flag is passed to `charon dkg`. This is useful for testing purposes when strict signature verification is not required.

### Sample Configuration and Lock Files

Refer to the details [here](./configuration.md).

### Concerns

- What if one cluster wants each validator to have differing withdrawal addresses? How will the cluster-definition structure change? Will the launchpad allow this flexibility, or should it be done via CLI by advanced users? If it's a CLI feature, should participants still sign the config_hash and their client ENR? Should the launchpad expose a page for advanced users, allowing them to paste a custom cluster-definition file and input their Charon node and a "Sign" button?
