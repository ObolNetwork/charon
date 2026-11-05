# Known Issues

This document lists findings that have already been submitted and reviewed for Charon. Each item below is a *class* of finding. The Obol Security Team has evaluated every class and found it to be one of: resolved, accepted as a design trade-off, or not a vulnerability.

**Please do not resubmit these findings or close variants of them.** Duplicate submissions will not be eligible for a reward.

Before you submit a report, read the [bug bounty program](https://docs.obol.org/advanced-and-troubleshooting/security/bug-bounty) and the trust model below. Behavior that falls within these assumptions is not a vulnerability.

If you believe you have found a new, distinct issue, report it to the Obol Security Team at [security@obol.tech](mailto:security@obol.tech).

## Trust Model

* **Cluster members are trusted-position actors.** The cluster lock authenticates every operator's node by its p2p key. A distributed validator tolerates up to `f` faulty or malicious members by design.
* **Configured relays are trusted-position actors.** Charon only accepts p2p connections from cluster peers and from the relays it is configured to use, and relay operators can see and influence relayed traffic. Run your own relay if you do not trust the default ones.
* **Insider attacks on liveness have capped severity.** Resource exhaustion, delays, or missed duties that require a cluster-member or relay position are rated per the bounty rubric. A member who degrades the cluster beyond simply going offline is rated at most **Medium**, provided keys stay secret and validators cannot be slashed.
* **Legacy lock formats are retained for compatibility.** Charon must keep loading the existing cluster locks of running clusters. Some lock formats from before v1.7 carry fewer signatures than current ones.
* **`--no-verify` is out of scope.** This flag disables cluster definition and lock verification. Findings that depend on an operator running with it are not eligible.
* **Operators control their own node and its inputs.** Operators choose their own beacon node, validator client, configuration, and cluster lock file. Findings that depend on an operator running a lock, configuration, or binary they did not produce or verify themselves are not eligible.
* **Access to the operator's host is out of scope.** Findings that require reading files, archives, logs, or command output on the operator's machine assume the host is already compromised and are not eligible. Examples include the file permissions of cluster or DKG archives created with `--zipped`, and secrets visible in local logs or test output. Since v1.11.3, Charon redacts credentials and API keys in configured endpoint URLs before logging them.

## Cluster Definition & Lock

* **Legacy lock and definition versions with fewer signatures:** Locks at v1.0/v1.1 can omit the aggregate signature, and definitions before v1.3 carry no EIP-712 operator signatures. Charon still loads these formats so that existing clusters keep running. Obol's API and SDK accept only v1.10.0 and later for new clusters. Rewriting an existing lock to an older version changes its lock and definition hashes, so the result is a different cluster that operators would have to adopt knowingly.
* **Creator-signed and unsigned-operator definitions:** A definition can have no operator signatures at all, for example in solo or single-operator flows where one party runs every node, or it can be signed only by its creator. This is the intended trust model for those flows: whoever runs the nodes chose the definition. Definitions where only some operators signed are rejected.

## Validator Duties & Fee Recipients

* **Fee recipient or gas limit mismatch is warn-only:** Charon logs a warning and increments a metric when a proposal or a validator client's proposer preferences carry a different fee recipient or gas limit than the node expects. The block comes from the beacon node of the node that leads that slot, which is a trusted-position component. Rejecting the block at that point would turn a misconfiguration into a missed proposal. Proposer preferences are aggregated on whichever value reaches threshold, so staggered configuration changes across operators still work. Builder (blinded) payloads are committed to by the builder and are not compared.
* **A malicious member degrading duty outcomes:** Classes where a single cluster member makes honest peers miss, delay, or fail a duty are capped as described in the trust model. Examples include sending well-signed partial signatures or consensus messages with inconsistent auxiliary data, or stalling leader rounds. These classes do not expose key material or create slashable messages. Aggregated signatures are verified against the distributed validator's public key before they are broadcast.
* **A leader proposing a value honest nodes cannot use:** A member leading a consensus round can propose a value that is well-formed on the wire but whose contents honest nodes cannot decode into duty data. Proposed values are decoded into duty data only after the cluster decides them, so the cluster decides such a value and misses that duty. Nodes running the alpha `chain_split_halt` feature compare a leader's attestation proposal to their local attestation data and duties before accepting it. This is a cluster-member liveness issue, capped as described in the trust model: it does not expose key material or create slashable messages.
* **QBFT round progression:** Claims that consensus can be held in unbounded round changes are not a vulnerability. A round change needs messages from `f+1` members. Every consensus instance ends at the duty's deadline. All consensus messages are signed by cluster members.
* **Cost of verifying partial signatures:** Partial signatures received from peers are BLS-verified before they are stored, so a peer can make a node spend CPU on verification. Each message is bounded by the number of validators in the lock, and only cluster members (or relays relaying cluster traffic) can send them.

## Validator API

* **The validator API is unauthenticated:** Charon serves the validator API on `--validator-api-address` (default `127.0.0.1:3600`) for the operator's own validator client on a trusted network. It has no authentication. TLS can be enabled with `--vc-tls-cert-file` and `--vc-tls-key-file`, which encrypts the connection but does not authenticate clients. Keeping the port reachable only by the validator client is the operator's responsibility (see the trust model).
* **Proxying to the beacon node with the operator's credentials:** Requests to routes that Charon does not implement itself are reverse-proxied to the operator's beacon node, with any credentials in the beacon node URL and any configured beacon node headers applied. Anything that can reach the validator API can therefore use that beacon node as the operator. Validator clients rely on this proxy for beacon node endpoints that Charon does not serve.
* **Resource exhaustion through the validator API:** Some routes limit the request body size, and the server sets a timeout for reading request headers. The validator API is not designed to serve untrusted clients. Findings that exhaust memory, CPU, or connections through it require network access to it, and are treated as operator exposure rather than a Charon vulnerability.
* **Reachability in Obol's Docker Compose stacks:** Obol's Docker Compose repositories (charon-distributed-validator-node and lido-charon-distributed-validator-node) set `CHARON_VALIDATOR_API_ADDRESS=0.0.0.0:3600` inside the container but do not publish port 3600 on the host, so by default the validator API is reachable only from the Compose network. A finding against the validator API must show that it is reachable from outside that network.

## P2P Networking & Relays

* **Allocation size of p2p messages:** Charon's p2p protocols accept length-prefixed messages up to a per-protocol limit, and Charon allocates frames incrementally as bytes arrive, so declaring a large length without sending the data does not reserve a large buffer. Only cluster peers and configured relays can open these streams.
* **Relays opening protocol streams or appearing as peers:** A configured relay can connect to a node directly and open Charon protocol streams, including during DKG sync. In DKG, such a relay can disrupt or abort the ceremony. Relays are trusted-position actors (see the trust model). Abuse by a relay is limited to liveness: it cannot produce operator signatures, key shares, or valid cluster messages.
* **Libp2p resource manager disabled:** Charon runs libp2p without a resource manager. Connections are restricted to cluster peers and configured relays, so exhaustion attacks that rely on this require a trusted position.

## Exits

* **Exit API authorization tokens do not expire:** The token a node uses to submit and fetch partial exits from the Obol API is a signature that does not expire. To obtain one, an attacker needs access to the operator's machine or to the API's traffic. The token only authorizes access to exit messages that the cluster's operators have already chosen to sign.
