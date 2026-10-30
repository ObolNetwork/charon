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

## Cluster Definition & Lock

* **Legacy lock and definition versions with fewer signatures:** Locks at v1.0/v1.1 can omit the aggregate signature, and definitions before v1.3 carry no EIP-712 operator signatures. Charon still loads these formats so that existing clusters keep running. Obol's API and SDK accept only v1.10.0 and later for new clusters. Rewriting an existing lock to an older version changes its lock and definition hashes, so the result is a different cluster that operators would have to adopt knowingly.
* **Creator-signed and unsigned-operator definitions:** A definition can have no operator signatures at all, for example in solo or single-operator flows where one party runs every node, or it can be signed only by its creator. This is the intended trust model for those flows: whoever runs the nodes chose the definition. Definitions where only some operators signed are rejected.

## Validator Duties & Fee Recipients

* **Fee recipient or gas limit mismatch is warn-only:** Charon logs a warning and increments a metric when a proposal or a validator client's proposer preferences carry a different fee recipient or gas limit than the node expects. The block comes from the beacon node of the node that leads that slot, which is a trusted-position component. Rejecting the block at that point would turn a misconfiguration into a missed proposal. Proposer preferences are aggregated on whichever value reaches threshold, so staggered configuration changes across operators still work. Builder (blinded) payloads are committed to by the builder and are not compared.
* **A malicious member degrading duty outcomes:** Classes where a single cluster member makes honest peers miss, delay, or fail a duty are capped as described in the trust model. Examples include sending well-signed partial signatures or consensus messages with inconsistent auxiliary data, or stalling leader rounds. These classes do not expose key material or create slashable messages. Aggregated signatures are verified against the distributed validator's public key before they are broadcast.
* **QBFT round progression:** Claims that consensus can be held in unbounded round changes are not a vulnerability. A round change needs messages from `f+1` members. Every consensus instance ends at the duty's deadline. All consensus messages are signed by cluster members.
* **Cost of verifying partial signatures:** Partial signatures received from peers are BLS-verified before they are stored, so a peer can make a node spend CPU on verification. Each message is bounded by the number of validators in the lock, and only cluster members (or relays relaying cluster traffic) can send them.

## P2P Networking & Relays

* **Allocation size of p2p messages:** Charon's p2p protocols accept length-prefixed messages up to a per-protocol limit, and Charon allocates frames incrementally as bytes arrive, so declaring a large length without sending the data does not reserve a large buffer. Only cluster peers and configured relays can open these streams.
* **Relays opening protocol streams or appearing as peers:** A configured relay can connect to a node directly and open Charon protocol streams, including during DKG sync. In DKG, such a relay can disrupt or abort the ceremony. Relays are trusted-position actors (see the trust model). Abuse by a relay is limited to liveness: it cannot produce operator signatures, key shares, or valid cluster messages.
* **Libp2p resource manager disabled:** Charon runs libp2p without a resource manager. Connections are restricted to cluster peers and configured relays, so exhaustion attacks that rely on this require a trusted position.

## Exits

* **Exit API authorization tokens do not expire:** The token a node uses to submit and fetch partial exits from the Obol API is a signature that does not expire. To obtain one, an attacker needs access to the operator's machine or to the API's traffic. The token only authorizes access to exit messages that the cluster's operators have already chosen to sign.
