# Duty Failure Reasons

This document enumerates and explains various duty failure reasons instrumented by the tracker component in charon.

These reasons are logged and reported via the `core_tracker_failed_duty_reasons_total`
prometheus counter when the tracker component detects duty failures.

By understanding these failure reasons, operators can better monitor, troubleshoot, and
maintain system performance.


### Failure Reason: `agg_sig_db`
  - *Summary*: bug: failed to store aggregated signature in aggsigdb
  - *Details*: Reason `agg_sig_db` indicates a bug in the aggregated signature database as it is unexpected.

### Failure Reason: `bcast`
  - *Summary*: failed to broadcast duty to beacon node
  - *Details*: Reason `bcast` indicates that beacon node returned an error while submitting aggregated duty signature to beacon node.

### Failure Reason: `chain_inclusion`
  - *Summary*: duty not included on-chain
  - *Details*: Reason `chain_inclusion` indicates that even though charon broadcasted the duty successfully, it wasn`t included in the beacon chain. This is expected for up to 20% of attestations. It may however indicate problematic charon broadcast delays or beacon node network problems.

### Failure Reason: `consensus`
  - *Summary*: consensus algorithm didn`t complete
  - *Details*: Reason `consensus` indicates a duty failed in consensus step. This could indicate that insufficient honest peers participated in consensus or p2p network connection problems.

### Failure Reason: `duty_db`
  - *Summary*: bug: failed to store duty data in DutyDB
  - *Details*: Reason `duty_db` indicates a bug in the DutyDB database as it is unexpected.

### Failure Reason: `fetcher_aggregator_failed_prepare`
  - *Summary*: couldn`t aggregate attestation due to failed prepare aggregator duty
  - *Details*: Reason `fetcher_aggregator_failed_prepare` indicates an attestation aggregation duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed.

### Failure Reason: `fetcher_aggregator_few_prepares`
  - *Summary*: couldn`t aggregate attestation due to insufficient partial beacon committee selections
  - *Details*: Reason `fetcher_aggregator_few_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to insufficient partial beacon committee selections submitted by the cluster validator clients.

### Failure Reason: `fetcher_aggregator_no_att_data`
  - *Summary*: couldn`t aggregate attestation due to failed attester duty
  - *Details*: Reason `fetcher_aggregator_no_att_data` indicates an attestation aggregation duty failed in the fetcher step since it couldn`t fetch the prerequisite attestation data. This indicates the associated attestation duty failed to obtain a cluster agreed upon value.

### Failure Reason: `fetcher_aggregator_no_external_prepares`
  - *Summary*: couldn`t aggregate attestation due to no partial beacon committee selections received from peers
  - *Details*: Reason `fetcher_aggregator_no_external_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections received from peers.

### Failure Reason: `fetcher_aggregator_zero_prepares`
  - *Summary*: couldn`t aggregate attestation due to zero partial beacon committee selections
  - *Details*: Reason `fetcher_aggregator_zero_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections submitted by the cluster validator clients.

### Failure Reason: `fetcher_bn`
  - *Summary*: couldn`t fetch duty data from the beacon node
  - *Details*: Reason `fetcher_bn` indicates a duty failed in the fetcher step when it failed to fetch the required data from the beacon node API. This indicates a problem with the upstream beacon node.

### Failure Reason: `fetcher_error`
  - *Summary*: couldn`t fetch due to unexpected error
  - *Details*: Reason `fetcher_error` indicates duty failed in fetcher step with some unexpected error. This indicates a problem in charon as it is unexpected.

### Failure Reason: `fetcher_proposer_failed_randao`
  - *Summary*: couldn`t propose block due to failed randao duty
  - *Details*: msgFetcherProposerZeroRandaos indicates a block proposer duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed.

### Failure Reason: `fetcher_proposer_few_randaos`
  - *Summary*: couldn`t propose block due to insufficient partial randao signatures
  - *Details*: Reason `fetcher_proposer_few_randaos` indicates a block proposer duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to insufficient partial randao signatures submitted by the cluster validator clients.

### Failure Reason: `fetcher_proposer_no_external_randaos`
  - *Summary*: couldn`t propose block due to no partial randao signatures received from peers
  - *Details*: Reason `fetcher_proposer_no_external_randaos` indicates a block proposer duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures received from peers.

### Failure Reason: `fetcher_proposer_zero_randaos`
  - *Summary*: couldn`t propose block due to zero partial randao signatures
  - *Details*: Reason `fetcher_proposer_zero_randaos` indicates a block proposer duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures submitted by the cluster validator clients.

### Failure Reason: `fetcher_sync_contribution_failed_prepare`
  - *Summary*: couldn`t fetch sync contribution due to failed prepare sync contribution duty
  - *Details*: Reason `fetcher_sync_contribution_failed_prepare` indicates a sync contribution duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed.

### Failure Reason: `fetcher_sync_contribution_few_prepares`
  - *Summary*: couldn`t fetch sync contribution due to insufficient partial sync contribution selections
  - *Details*: Reason `fetcher_sync_contribution_few_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to insufficient partial sync contribution selections submitted by the cluster validator clients.

### Failure Reason: `fetcher_sync_contribution_no_external_prepares`
  - *Summary*: couldn`t fetch sync contribution due to no partial sync contribution selections received from peers
  - *Details*: Reason `fetcher_sync_contribution_no_external_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections received from peers.

### Failure Reason: `fetcher_sync_contribution_no_sync_msg`
  - *Summary*: couldn`t fetch sync contribution due to failed sync message duty
  - *Details*: Reason `fetcher_sync_contribution_no_sync_msg` indicates a sync contribution duty failed in the fetcher step since it couldn`t fetch the prerequisite sync message. This indicates the associated sync message duty failed to obtain a cluster agreed upon value.

### Failure Reason: `fetcher_sync_contribution_zero_prepares`
  - *Summary*: couldn`t fetch sync contribution due to zero partial sync contribution selections
  - *Details*: Reason `fetcher_sync_contribution_zero_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn`t fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections submitted by the cluster validator clients.

### Failure Reason: `par_sig_db_external`
  - *Summary*: bug: failed to store external partial signatures in parsigdb
  - *Details*: Reason `par_sig_db_external` indicates a bug in the partial signature database as it is unexpected.

### Failure Reason: `par_sig_db_inconsistent`
  - *Summary*: bug: inconsistent partial signatures received
  - *Details*: Reason `par_sig_db_inconsistent` indicates that partial signed data for the duty were inconsistent. This indicates a bug in charon as it is unexpected (for non-sync-committee-duties).

### Failure Reason: `par_sig_db_inconsistent_sync`
  - *Summary*: known limitation: inconsistent sync committee signatures received
  - *Details*: Reason `par_sig_db_inconsistent_sync` indicates that partial signed data for the sync committee duty were inconsistent. This is known limitation in this version of charon.

### Failure Reason: `par_sig_db_insufficient`
  - *Summary*: insufficient partial signatures received, minimum required threshold not reached
  - *Details*: Reason `par_sig_db_insufficient` indicates that insufficient partial signatures for the duty was received from peers. This indicates problems with peers or p2p network connection problems.

### Failure Reason: `par_sig_db_internal`
  - *Summary*: partial signature database didn`t trigger partial signature exchange, this is unexpected
  - *Details*: Reason `par_sig_db_internal` indicates a bug in the partial signature database as it is unexpected. Note this may happen due to expiry race.

### Failure Reason: `par_sig_ex_receive`
  - *Summary*: no partial signatures received from peers
  - *Details*: Reason `par_sig_ex_receive` indicates that no partial signature for the duty was received from any peer. This indicates all peers are offline or p2p network connection problems.

### Failure Reason: `sig_agg`
  - *Summary*: bug: threshold aggregation of partial signatures failed due to inconsistent signed data
  - *Details*: Reason `sig_agg` indicates that BLS threshold aggregation of sufficient partial signatures failed. This indicates inconsistent signed data. This indicates a bug in charon as it is unexpected.

### Failure Reason: `unknown`
  - *Summary*: unknown error
  - *Details*: Reason `unknown` indicates an unknown error occurred.

### Failure Reason: `validator_api`
  - *Summary*: signed duty not submitted by local validator client
  - *Details*: Reason `validator_api` indicates that partial signature we never submitted by the local validator client. This could indicate that the local validator client is offline, or has connection problems with charon, or has some other problem. See validator client logs for more details.
