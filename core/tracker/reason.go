// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

// reason is a reason for a duty failing.
type reason struct {
	// Code is a short code for the reason.
	Code string
	// Short is a short description of the reason.
	Short string
	// Long is a long description of the reason.
	Long string
}

var (
	reasonUnknown = reason{
		Code:  "unknown",
		Short: "unknown error",
		Long:  "Reason `unknown` indicates an unknown error occurred.",
	}

	reasonFetcherBN = reason{
		Code:  "fetcher_bn",
		Short: "couldn't fetch duty data from the beacon node",
		Long:  "Reason `fetcher_bn` indicates a duty failed in the fetcher step when it failed to fetch the required data from the beacon node API. This indicates a problem with the upstream beacon node.",
	}

	reasonFetcherAggregatorNoAttData = reason{
		Code:  "fetcher_aggregator_no_att_data",
		Short: "couldn't aggregate attestation due to failed attester duty",
		Long:  "Reason `fetcher_aggregator_no_att_data` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite attestation data. This indicates the associated attestation duty failed to obtain a cluster agreed upon value.",
	}

	reasonFetcherAggregatorFewPrepares = reason{
		Code:  "fetcher_aggregator_few_prepares",
		Short: "couldn't aggregate attestation due to insufficient partial beacon committee selections",
		Long:  "Reason `fetcher_aggregator_few_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to insufficient partial beacon committee selections submitted by the cluster validator clients.",
	}

	reasonFetcherAggregatorZeroPrepares = reason{
		Code:  "fetcher_aggregator_zero_prepares",
		Short: "couldn't aggregate attestation due to zero partial beacon committee selections",
		Long:  "Reason `fetcher_aggregator_zero_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections submitted by the cluster validator clients.",
	}

	reasonFetcherAggregatorFailedPrepare = reason{
		Code:  "fetcher_aggregator_failed_prepare",
		Short: "couldn't aggregate attestation due to failed prepare aggregator duty",
		Long:  "Reason `fetcher_aggregator_failed_prepare` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed.",
	}

	reasonFetcherAggregatorNoExternalPrepares = reason{
		Code:  "fetcher_aggregator_no_external_prepares",
		Short: "couldn't aggregate attestation due to no partial beacon committee selections received from peers",
		Long:  "Reason `fetcher_aggregator_no_external_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections received from peers.",
	}

	reasonFetcherProposerFewRandaos = reason{
		Code:  "fetcher_proposer_few_randaos",
		Short: "couldn't propose block due to insufficient partial randao signatures",
		Long:  "Reason `fetcher_proposer_few_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to insufficient partial randao signatures submitted by the cluster validator clients.",
	}

	reasonFetcherProposerZeroRandaos = reason{
		Code:  "fetcher_proposer_zero_randaos",
		Short: "couldn't propose block due to zero partial randao signatures",
		Long:  "Reason `fetcher_proposer_zero_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures submitted by the cluster validator clients.",
	}

	reasonFetcherProposerFailedRandao = reason{
		Code:  "fetcher_proposer_failed_randao",
		Short: "couldn't propose block due to failed randao duty",
		Long:  "msgFetcherProposerZeroRandaos indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed.",
	}

	reasonFetcherProposerNoExternalRandaos = reason{
		Code:  "fetcher_proposer_no_external_randaos",
		Short: "couldn't propose block due to no partial randao signatures received from peers",
		Long:  "Reason `fetcher_proposer_no_external_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures received from peers.",
	}

	reasonFetcherSyncContributionNoSyncMsg = reason{
		Code:  "fetcher_sync_contribution_no_sync_msg",
		Short: "couldn't fetch sync contribution due to failed sync message duty",
		Long:  "Reason `fetcher_sync_contribution_no_sync_msg` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite sync message. This indicates the associated sync message duty failed to obtain a cluster agreed upon value.",
	}

	reasonFetcherSyncContributionFewPrepares = reason{
		Code:  "fetcher_sync_contribution_few_prepares",
		Short: "couldn't fetch sync contribution due to insufficient partial sync contribution selections",
		Long:  "Reason `fetcher_sync_contribution_few_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to insufficient partial sync contribution selections submitted by the cluster validator clients.",
	}

	reasonFetcherSyncContributionZeroPrepares = reason{
		Code:  "fetcher_sync_contribution_zero_prepares",
		Short: "couldn't fetch sync contribution due to zero partial sync contribution selections",
		Long:  "Reason `fetcher_sync_contribution_zero_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections submitted by the cluster validator clients.",
	}

	reasonFetcherSyncContributionFailedPrepare = reason{
		Code:  "fetcher_sync_contribution_failed_prepare",
		Short: "couldn't fetch sync contribution due to failed prepare sync contribution duty",
		Long:  "Reason `fetcher_sync_contribution_failed_prepare` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed.",
	}

	reasonFetcherSyncContributionNoExternalPrepares = reason{
		Code:  "fetcher_sync_contribution_no_external_prepares",
		Short: "couldn't fetch sync contribution due to no partial sync contribution selections received from peers",
		Long:  "Reason `fetcher_sync_contribution_no_external_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections received from peers.",
	}

	reasonFetcherError = reason{
		Code:  "fetcher_error",
		Short: "couldn't fetch due to unexpected error",
		Long:  "Reason `fetcher_error` indicates duty failed in fetcher step with some unexpected error. This indicates a problem in charon as it is unexpected.",
	}

	reasonConsensus = reason{
		Code:  "consensus",
		Short: "consensus algorithm didn't complete",
		Long:  "Reason `consensus` indicates a duty failed in consensus step. This could indicate that insufficient honest peers participated in consensus or p2p network connection problems.",
	}

	reasonDutyDB = reason{
		Code:  "duty_db",
		Short: "bug: failed to store duty data in DutyDB",
		Long:  "Reason `duty_db` indicates a bug in the DutyDB database as it is unexpected.",
	}

	reasonValidatorAPI = reason{
		Code:  "validator_api",
		Short: "signed duty not submitted by local validator client",
		Long:  "Reason `validator_api` indicates that partial signature we never submitted by the local validator client. This could indicate that the local validator client is offline, or has connection problems with charon, or has some other problem. See validator client logs for more details.",
	}

	reasonParSigDBInternal = reason{
		Code:  "par_sig_db_internal",
		Short: "partial signature database didn't trigger partial signature exchange, this is unexpected",
		Long:  "Reason `par_sig_db_internal` indicates a bug in the partial signature database as it is unexpected. Note this may happen due to expiry race.",
	}

	reasonParSigExReceive = reason{
		Code:  "par_sig_ex_receive",
		Short: "no partial signatures received from peers",
		Long:  "Reason `par_sig_ex_receive` indicates that no partial signature for the duty was received from any peer. This indicates all peers are offline or p2p network connection problems.",
	}

	reasonParSigDBInsufficient = reason{
		Code:  "par_sig_db_insufficient",
		Short: "insufficient partial signatures received, minimum required threshold not reached",
		Long:  "Reason `par_sig_db_insufficient` indicates that insufficient partial signatures for the duty was received from peers. This indicates problems with peers or p2p network connection problems.",
	}

	reasonParSigDBInconsistentSync = reason{
		Code:  "par_sig_db_inconsistent_sync",
		Short: "known limitation: inconsistent sync committee signatures received",
		Long:  "Reason `par_sig_db_inconsistent_sync` indicates that partial signed data for the sync committee duty were inconsistent. This is known limitation in this version of charon.",
	}

	reasonParSigDBInconsistent = reason{
		Code:  "par_sig_db_inconsistent",
		Short: "bug: inconsistent partial signatures received",
		Long:  "Reason `par_sig_db_inconsistent` indicates that partial signed data for the duty were inconsistent. This indicates a bug in charon as it is unexpected (for non-sync-committee-duties).",
	}

	reasonParSigDBExternal = reason{
		Code:  "par_sig_db_external",
		Short: "bug: failed to store external partial signatures in parsigdb",
		Long:  "Reason `par_sig_db_external` indicates a bug in the partial signature database as it is unexpected.",
	}

	reasonSigAgg = reason{
		Code:  "sig_agg",
		Short: "bug: threshold aggregation of partial signatures failed due to inconsistent signed data",
		Long:  "Reason `sig_agg` indicates that BLS threshold aggregation of sufficient partial signatures failed. This indicates inconsistent signed data. This indicates a bug in charon as it is unexpected.",
	}

	reasonAggSigDB = reason{
		Code:  "agg_sig_db",
		Short: "bug: failed to store aggregated signature in aggsigdb",
		Long:  "Reason `agg_sig_db` indicates a bug in the aggregated signature database as it is unexpected.",
	}

	reasonBcast = reason{
		Code:  "bcast",
		Short: "failed to broadcast duty to beacon node",
		Long:  "Reason `bcast` indicates that beacon node returned an error while submitting aggregated duty signature to beacon node.",
	}

	reasonChainIncl = reason{
		Code:  "chain_inclusion",
		Short: "duty not included on-chain",
		Long:  "Reason `chain_inclusion` indicates that even though charon broadcasted the duty successfully, it wasn't included in the beacon chain. This is expected for up to 20% of attestations. It may however indicate problematic charon broadcast delays or beacon node network problems.",
	}
)
