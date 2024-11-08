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

To make a distributed validator with no fault-tolerance (i.e. all nodes need to be online to sign every message), due to the BLS signature scheme used by Proof of Stake Ethereum, each key share could be chosen by operators independently. However, to create a distributed validator that can stay online despite a subset of its nodes going offline, the key shares need to be generated together. (4 randomly chosen points on a graph don't all necessarily sit on the same order three curve.) To do this in a secure manner with no one party being trusted to distribute the keys requires what is known as a distributed key generation ceremony.

The charon client has the responsibility of securely completing a distributed key generation ceremony with its counterparty nodes. The ceremony configuration is outlined in a [cluster configuration](https://docs.obol.tech/docs/dv/distributed-validator-cluster-manifest).

## Actors Involved

A distributed key generation ceremony involves `Operators` and their `Charon clients`.

- An `Operator` is identified by their Ethereum address. They will sign with this address's private key to authenticate their charon client ahead of the ceremony. The signature will be of; a hash of the charon clients ENR public key, the `cluster_definition_hash`, and an incrementing `nonce`, allowing for a direct linkage between a user, their charon client, and the cluster this client is intended to service, while retaining the ability to update the charon client by incrementing the nonce value and re-signing like the standard ENR spec.

- A `Charon client` is also identified by a public/private key pair, in this instance, the public key is represented as an [Ethereum Node Record](https://eips.ethereum.org/EIPS/eip-778) (ENR). This is a standard identity format for both EL and CL clients. These ENRs are used by each charon node to identify its cluster peers over the internet, and to communicate with one another in an [end to end encrypted manner](https://github.com/libp2p/go-libp2p-noise). These keys need to be created by each operator before they can participate in a cluster creation.

## Cluster Definition Creation

This cluster-definition file is created with the help of the [Distributed Validator Launchpad](https://docs.obol.tech/docs/dvk/distributed_validator_launchpad). The creation process involves a number of steps.

- A `leader` Operator, that wishes to coordinate the creation of a new Distributed Validator Cluster navigates to the launch pad and selects "Create new Cluster"
- The `leader` uses the user interface to configure all the important details about the cluster including:
  - The `withdrawal address` for the created validators
  - The `feeRecipient` for block proposals if it differs from the withdrawal address
  - The number of distributed validators to create
  - The list of participants in the cluster specified by Ethereum address(/ENS)
  - The threshold of fault tolerance required (if not choosing the safe default)
  - The network (fork_version/chainId) that this cluster will validate on
- These key pieces of information form the basis of the cluster configuration. These fields (and some technical fields like DKG algorithm to use) are serialised and merklised to produce the manifests `cluster_definition_hash`. This merkle root will be used to confirm that there is no ambiguity or deviation between manifests when they are provided to charon nodes.
- Once the leader is satisfied with the configuration they publish it to the launchpad's data availability layer for the other participants to access. (For early development the launchpad will use a centralised backend db to store the cluster configuration. Near production, solutions like IPFS or arweave may be more suitable for the long term decentralisation of the launchpad.)
- The leader will then share the URL to this ceremony with their intended participants.
- Anyone that clicks the ceremony url, or inputs the `config_hash` when prompted on the landing page will be brought to the ceremony status page. (After completing all disclaimers and advisories)
- A "Connect Wallet" button will be visible beneath the ceremony status container, a participant can click on it to connect their wallet to the site
  - If the participant connects a wallet that is not in the participant list, the button disables, as there is nothing to do
  - If the participant connects a wallet that is in the participant list, they get prompted to input the ENR of their charon node.
  - If the ENR field is populated and validated the participant can now see a "Confirm Cluster Configuration" button. This button triggers one/two signatures.
    - The participant signs the `config_hash`, to prove they are consenting to this exact configuration.
    - The participant signs their charon node's ENR, to authenticate and authorise that specific charon node to participate on their behalf in the distributed validator cluster.
  - These/this signature is sent to the data availability layer, where it verifies the signatures are correct for the given participants ethereum address. If the signatures pass validation, the signature of the config_hash and the ENR + signature get saved to the cluster definition object.
- All participants in the list must sign the config_hash and submit a signed ENR before a DKG ceremony can begin. The outstanding signatures can be easily displayed on the status page.
- Finally, once all participants have signed their approval, and submitted a charon node ENR to act on their behalf, the cluster-definition file can be downloaded as a file if the users click a newly displayed button, `Download Cluster Definition`.
- At this point each participant must load this cluster-definition into their charon client, and the client will attempt to complete the DKG.

## Carrying out the DKG ceremony

Once participant has their cluster-definition file prepared, they will pass the file to charon's `dkg` command. Charon will read the ENRs in the cluster-definition, confirm that its ENR is present, and then will reach out to bootnodes that are deployed to find the other ENRs on the network. (Fresh ENRs just have a public key and an IP address of 0.0.0.0 until they are loaded into a live charon client, which will update the IP address and increment the ENRs nonce and resign with the clients private key. If an ENR with a higher nonce is seen to be a charon client, they will update the IP address of that ENR in their address book.)

Once all clients in the cluster can establish a connection with one another and they each complete a handshake (confirm everyone has a matching `cluster_definition_hash`), the ceremony begins.

No user input is required, charon does the work and outputs the following files to each machine and then exits.

```sh
./cluster-definition.json   # The original cluster definition file from the DV Launchpad
./cluster-lock.json         # New lockfile based on cluster-definition.json with validator group public keys and public shares included with the initial cluster config
./charon/enr_private_key    # Created before the ceremony took place [Back this up]
./charon/validator_keys/    # Folder of key shares to be backed up and moved to validator client [Back this up]
./charon/deposit_data*      # JSON files of deposit data for the distributed validators
./charon/exit_data          # JSON file of exit data that ethdo can broadcast
```

## Backing up the ceremony artifacts

Once the ceremony is complete, all participants should take a backup of the created files. In future versions of charon, if a participant loses access to these key shares, it will be possible to use a key re-sharing protocol to swap the participants old keys out of a distributed validator in favour of new keys, allowing the rest of a cluster to recover from a set of lost key shares. However for now, without a backup, the safest thing to do would be to exit the validator.

## Preparing for validator activation

Once the ceremony is complete, and secure backups of key shares have been made by each operator. They must now load these key shares into their validator clients, and run the `charon run` command to turn it into operational mode.

All operators should confirm that their charon client logs indicate all nodes are online and connected. They should also verify the readiness of their beacon clients and validator clients. Charon's grafana dashboard is a good way to see the readiness of the full cluster from its perspective.

Once all operators are satisfied with network connectivity, one member can use the Obol Distributed Validator deposit flow to send the required ether and deposit data to the deposit contract, beginning the process of a distributed validator activation. Good luck.

## DKG Verification

For many use cases of distributed validators, the funder/depositor of the validator may not be the same person as the key creators/node operators, as (outside of the base protocol) stake delegation is a common phenomenon. This handover of information introduces a point of trust. How does someone verify that a proposed validator `deposit data` corresponds to a real, fair, DKG with participants the depositor expects?

There are a number of aspects to this trust surface that can be mitigated with a "Don't trust, verify" model. Verification for the time being is easier off chain, until things like a [BLS precompile](https://eips.ethereum.org/EIPS/eip-2537) are brought into the EVM, along with cheap ZKP verification on chain. Some of the questions that can be asked of Distributed Validator Key Generation Ceremonies include:

- Do the public key shares combine together to form the group public key?
  - This can be checked on chain as it does not require a pairing operation
  - This can give confidence that a BLS pubkey represents a Distributed Validator, but does not say anything about the custody of the keys. (e.g. Was the ceremony sybil attacked, did they collude to reconstitute the group private key etc.)
- Do the created BLS public keys attest to their `cluster_definition_hash`?
  - This is to create a backwards link between newly created BLS public keys and the operator's eth1 addresses that took part in their creation.
  - If a proposed distributed validator BLS group public key can produce a signature of the `cluster_definition_hash`, it can be inferred that at least a threshold of the operators signed this data.
  - As the `cluster_definition_hash` is the same for all distributed validators created in the ceremony, the signatures can be aggregated into a group signature that verifies all created group keys at once. This makes it cheaper to verify a number of validators at once on chain.
- Is there either a VSS or PVSS proof of a fair DKG ceremony?
  - VSS (Verifiable Secret Sharing) means only operators can verify fairness, as the proof requires knowledge of one of the secrets.
  - PVSS (Publicly Verifiable Secret Sharing) means anyone can verify fairness, as the proof is usually a Zero Knowledge Proof.
  - A PVSS of a fair DKG would make it more difficult for operators to collude and undermine the security of the Distributed Validator.
  - Zero Knowledge Proof verification on chain is currently expensive, but is becoming achievable through the hard work and research of the many ZK based teams in the industry.

## Appendix

### Using DKG without the launchpad

Charon clients can do a DKG with a cluster-definition file that does not contain operator signatures if you pass a `--no-verify` flag to `charon dkg`. This can be used for testing purposes when strict signature verification is not of the utmost importance.

### Sample Configuration and Lock Files

Refer to the details [here](./configuration.md).

### Concerns

- What if one cluster wants each validator to have differing withdrawal addresses? How will the cluster-definition structure change? Will the launchpad offer this flexibility or should it be done on the CLI by advanced users? If this is a CLI feature, do we have participants still sign the config_hash and their client enr? Should we expose an extra page in the launchpad for advanced users, and it is basically just a form field for pasting a custom cluster-definition file in and an input for their charon node and a "Sign button"?
