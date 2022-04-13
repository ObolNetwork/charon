# Charon Distributed Validator Key Generation

## Contents

- Overview
- Actors involved
- Manifest creation
- Carrying out the DKG ceremony
- Backing up ceremony artifacts
- Preparing for validator activation

## Overview

To make a distributed validator with no fault-tolerance (i.e. all nodes need to be online to sign every message), due to the BLS signature scheme used by Proof of Stake Ethereum, each key share could be chosen by operators independently. However, to create a distributed validator that can stay online despite a subset of its nodes going offline, the key shares need to be generated together. (4 randomly chosen points on a graph don't all neccessarily sit on the same order three curve.) To do this in a secure manner with no one party being trusted to distribute the keys requires what is known as a distributed key generation ceremony.

The charon client has the responsibility of securely completing a distributed key generation ceremony with its counterparty nodes. The ceremony configuration is outlined in a [cluster manifest](https://docs.obol.tech/docs/dv/distributed-validator-cluster-manifest).

## Actors Involved

A distributed key generation ceremony involves `Operators` and their `Charon clients`.

- An `Operator` is identified by their Ethereum address. They will sign with this address's private key to authenticate their charon client ahead of the ceremony. The signature will be of; a hash of the charon clients ENR public key, the `manifest_configuration_hash`, and an incrementing `nonce`, allowing for a direct linkage between a user, their charon client, and the cluster this client is intended to service, while retaining the ability to update the charon client by incrementing the nonce value and re-signing like the standard ENR spec.

- A `Charon client` is also identified by a public/private key pair, in this instance, the public key is represented as an [Ethereum Node Record](https://eips.ethereum.org/EIPS/eip-778) (ENR). This is a standard identity format for both EL and CL clients. These ENRs are used by each charon node to identify its cluster peers over the internet, and to communicate with one another in an [end to end encrypted manner](https://github.com/libp2p/go-libp2p-noise). These keys need to be created by each operator before they can participate in a cluster creation.

## Manifest Creation

This manifest file is created with the help of the [Distributed Validator Launchpad](https://docs.obol.tech/docs/dvk/distributed_validator_launchpad). The creation process involves a number of steps.

- A `leader` Operator, that wishes to co-ordinate the creation of a new Distributed Validator Cluster navigates to the launch pad and selects "Create new Cluster"
- The `leader` uses the user interface to configure all of the important details about the cluster including:
  - The `withdrawal address` for the created validators
  - The `feeRecipient` for block proposals if it differs from the withdrawal address
  - The number of distributed validators to create
  - The list of participants in the cluster specified by Ethereum address(/ENS)
  - The threshold of fault tolerance required (if not choosing the safe default)
  - The network (fork_version/chainId) that this cluster will validate on
- These key pieces of information form the basis of the cluster configuration. These fields (and some technical fields like DKG algorithm to use) are serialised and merklised to produce the manifests `manifest_configuration_hash`. This merkle root will be used to confirm that their is no ambiguity or deviation between manifests when they are provided to charon nodes.
- Once the leader is satisfied with the configuration they publish it to the launchpad's data availability layer for the other participants to access. (For early development the launchpad will use a centralised backend db to store the cluster configuration. Near production, solutions like IPFS or arweave may be more suitable for the long term decentralisation of the launchpad.)
- The leader will then share the URL to this ceremony with their intended participants.
- Anyone that clicks the ceremony url, or inputs the `manifest_configuration_hash` when prompted on the landing page will be brought to the ceremony status page. (After completing all disclaimers and advisories)
- A "Connect Wallet" button will be visible beneath the ceremony status container, a participant can click on it to connect their wallet to the site
  - If the participant connects a wallet that is not in the participant list, the button disables, as there is nothing to do
  - If the participant connects a wallet that is in the participant list, they get prompted to input the ENR of their charon node.
  - If the ENR field is populated and validated the participant can now see a "Confirm Cluster Configuration" button. This button triggers one/two signatures.
    - The participant signs the `manifest_configuration_hash`, to prove they are consensting to this exact configuration.
    - The participant signs their charon node's ENR, to authenticate and authorise that specific charon node to participate on their behalf in the distributed validator cluster.
  - These/this signature is sent to the data availability layer, where it verifies the signatures are correct for the given participants ethereum address. If the signatures pass validation, the signature of the manifest hash and the the ENR + signature get saved to the manifest object.
- All participants in the list must sign the manifest hash and submit a signed ENR before a DKG ceremony can begin. The outstanding signatures can be easily displayed on the status page.
- Finally, once all participants have signed their approval, and submitted a charon node ENR to act on their behalf, the manifest data can be downloaded as a file if the users click a newly displayed button, `Download Manifest`.
- At this point each participant must load this manifest into their charon client, and the client will attempt to complete the DKG.

## Carrying out the DKG ceremony

Once participant has their manifest file prepared, they will pass the file to charon's `dkg` command. Charon will read the ENRs in the manifest, confirm that its ENR is present, and then will reach out to bootnodes that are deployed to find the other ENRs on the network. (Fresh ENRs just have a public key and an IP address of 0.0.0.0 until they are loaded into a live charon client, which will update the IP address and increment the ENRs nonce and resign with the clients private key. If an ENR with a higher nonce is seen be a charon client, they will update the IP address of that ENR in their address book.)

Once all clients in the cluster can establish a connection with one another and they each complete a handshake (confirm everyone has a matching `manifest_configuration_hash`), the ceremony begins.

No user input is required, charon does the work and outputs the following files to each machine and then exits.

```sh
./cluster_manifest.yaml     # The original manifest file from the DV Launchpad
./cluster_manifest.lock     # New lockfile based on cluster_manifest.yaml with validator group public keys and threshold BLS verifiers included with the initial cluster config
./charon/enr_private_key    # Created before the ceremony took place [Back this up]
./charon/validator_keys/    # Folder of key shares to be backed up and moved to validator client [Back this up]
./charon/deposit_data       # JSON file of deposit data for the distributed validators
./charon/exit_data          # JSON file of exit data that ethdo can broadcast
```

## Backing up the ceremony artifacts

Once the ceremony is complete, all participants should take a backup of the created files. In future versions of charon, if a participant loses access to these key shares, it will be possible to use a key re-sharing protocol to swap the participants old keys out of a distributed validator in favour of new keys, allowing the rest of a cluster to recover from a set of lost key shares. However for now, without a backup, the safest thing to do would be to exit the validator.

## Preparing for validator activation

Once the ceremony is complete, and secure backups of key shares have been made by each operator. They must now load these key shares into their validator clients, and run the `charon run` command to turn it into operational mode.

All operators should confirm that their charon client logs indicate all nodes are online and connected. They should also verify the readiness of their beacon clients and validator clients. Charon's grafana dashboard is a good way to see the readiness of the full cluster from its perspective.

Once all operators are satisfied with network connectivity, one member can use the Obol Distributed Validator deposit flow to send the required ether and deposit data to the deposit contract, beginning the process of a distributed validator activation. Good luck.

## Appendix

### Using DKG without the launchpad

Charon clients can do a DKG with a manifest file that does not contain operator signatures if you pass a `--no-verify` flag to `charon dkg`. This can be used for testing purposes when strict signature verification is not of the utmost importance.

### Sample Manifest File [TBC]

Before any participants add ENRs or signatures of the root.

```yaml
version: v1
name: Test #Free text is needed to setup many clusters with the exact same config, otherwise hashes would be identical.
grafitti:
manifest_configuration_hash: 0x1234abc
withdrawal_address: 0x0dead
feeRecipient: 0x0
validator_count: 100
participants:
  - 0x0
  - 0x1
  - 0x2
  - 0x3
threshold: 3
dkg_algorithm: adkg_1_0_0
```

With some participants having submitted signed manifest_configuration_hash-es and signed ENRs. [To Do]

```yaml
version: v1
manifest_configuration_hash: 0x1234abc
withdrawal_address: 0x0dead
feeRecipient: 0x0
validator_count: 100
participants:
  - 0x0
  - 0x1
  - 0x2
  - 0x3
threshold: 3
dkg_algorithm: adkg_1_0_0
```

### Concerns

- What if one cluster wants each validator to have differing withdrawal addresses? How will the manifest structure change? Will the launchpad offer this flexibility or should it be done on the CLI by advanced users? If this is a CLI feature, do we have participants still sign the manifest root and their client enr? Should we expose an extra page in the launchpad for advanced users, and it is basically just a form field for pasting a custom manifest file in and an input for their charon node and a "Sign button"?
