// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

	reasonFetchBNError = reason{
		Code:  "fetch_bn_error",
		Short: "couldn't fetch duty data from the beacon node",
		Long:  "Reason `fetch_bn_error` indicates a duty failed in the fetcher step when it failed to fetch the required data from the beacon node API. This indicates a problem with the upstream beacon node.",
	}

	reasonMissingAggregatorAttestation = reason{
		Code:  "missing_aggregator_attestation",
		Short: "couldn't aggregate attestation due to failed attester duty",
		Long:  "Reason `missing_aggregator_attestation` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite attestation data. This indicates the associated attestation duty failed to obtain a cluster agreed upon value.",
	}

	reasonInsufficientAggregatorSelections = reason{
		Code:  "insufficient_aggregator_selections",
		Short: "couldn't aggregate attestation due to insufficient partial beacon committee selections",
		Long:  "Reason `insufficient_aggregator_selections` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to insufficient partial beacon committee selections submitted by the cluster validator clients.",
	}

	reasonZeroAggregatorSelections = reason{
		Code:  "zero_aggregator_prepares",
		Short: "couldn't aggregate attestation due to zero partial beacon committee selections",
		Long:  "Reason `zero_aggregator_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections submitted by the cluster validator clients.",
	}

	reasonFailedAggregatorSelection = reason{
		Code:  "failed_aggregator_selection",
		Short: "couldn't aggregate attestation due to failed prepare aggregator duty",
		Long:  "Reason `failed_aggregator_selection` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed.",
	}

	reasonNoAggregatorSelections = reason{
		Code:  "no_aggregator_selections",
		Short: "couldn't aggregate attestation due to no partial beacon committee selections received from peers",
		Long:  "Reason `no_aggregator_selections` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections received from peers.",
	}

	reasonProposerInsufficientRandaos = reason{
		Code:  "proposer_insufficient_randaos",
		Short: "couldn't propose block due to insufficient partial randao signatures",
		Long:  "Reason `proposer_insufficient_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to insufficient partial randao signatures submitted by the cluster validator clients.",
	}

	reasonProposerZeroRandaos = reason{
		Code:  "proposer_zero_randaos",
		Short: "couldn't propose block due to zero partial randao signatures",
		Long:  "Reason `proposer_zero_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures submitted by the cluster validator clients.",
	}

	reasonFailedProposerRandao = reason{
		Code:  "failed_proposer_randao",
		Short: "couldn't propose block due to failed randao duty",
		Long:  "Reason `failed_proposer_randao` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed.",
	}

	reasonProposerNoExternalRandaos = reason{
		Code:  "proposer_no_external_randaos",
		Short: "couldn't propose block due to no partial randao signatures received from peers",
		Long:  "Reason `proposer_no_external_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures received from peers.",
	}

	reasonSyncContributionNoSyncMsg = reason{
		Code:  "sync_contribution_no_sync_msg",
		Short: "couldn't fetch sync contribution due to failed sync message duty",
		Long:  "Reason `sync_contribution_no_sync_msg` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite sync message. This indicates the associated sync message duty failed to obtain a cluster agreed upon value.",
	}

	reasonSyncContributionFewPrepares = reason{
		Code:  "sync_contribution_few_prepares",
		Short: "couldn't fetch sync contribution due to insufficient partial sync contribution selections",
		Long:  "Reason `sync_contribution_few_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to insufficient partial sync contribution selections submitted by the cluster validator clients.",
	}

	reasonSyncContributionZeroPrepares = reason{
		Code:  "sync_contribution_zero_prepares",
		Short: "couldn't fetch sync contribution due to zero partial sync contribution selections",
		Long:  "Reason `sync_contribution_zero_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections submitted by the cluster validator clients.",
	}

	reasonSyncContributionFailedPrepare = reason{
		Code:  "sync_contribution_failed_prepare",
		Short: "couldn't fetch sync contribution due to failed prepare sync contribution duty",
		Long:  "Reason `sync_contribution_failed_prepare` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed.",
	}

	reasonSyncContributionNoExternalPrepares = reason{
		Code:  "sync_contribution_no_external_prepares",
		Short: "couldn't fetch sync contribution due to no partial sync contribution selections received from peers",
		Long:  "Reason `sync_contribution_no_external_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections received from peers.",
	}

	reasonNoConsensus = reason{
		Code:  "no_consensus",
		Short: "consensus algorithm didn't complete",
		Long:  "Reason `no_consensus` indicates a duty failed in consensus step. This could indicate that insufficient honest peers participated in consensus or p2p network connection problems.",
	}

	reasonNoLocalVCSignature = reason{
		Code:  "no_local_vc_signature",
		Short: "signed duty not submitted by local validator client",
		Long:  "Reason `no_local_vc_signature` indicates that partial signature we never submitted by the local validator client. This could indicate that the local validator client is offline, or has connection problems with charon, or has some other problem. See validator client logs for more details.",
	}

	reasonNoPeerSignatures = reason{
		Code:  "no_peer_signatures",
		Short: "no partial signatures received from peers",
		Long:  "Reason `no_peer_signatures` indicates that no partial signature for the duty was received from any peer. This indicates all peers are offline or p2p network connection problems.",
	}

	reasonInsufficientPeerSignatures = reason{
		Code:  "insufficient_peer_signatures",
		Short: "insufficient partial signatures received, minimum required threshold not reached",
		Long:  "Reason `insufficient_peer_signatures` indicates that insufficient partial signatures for the duty was received from peers. This indicates problems with peers or p2p network connection problems.",
	}

	reasonParSigDBInconsistentSync = reason{
		Code:  "par_sig_db_inconsistent_sync",
		Short: "known limitation: inconsistent sync committee signatures received",
		Long:  "Reason `par_sig_db_inconsistent_sync` indicates that partial signed data for the sync committee duty were inconsistent. This is known limitation in this version of charon.",
	}

	reasonBroadcastBNError = reason{
		Code:  "broadcast_bn_error",
		Short: "failed to broadcast duty to beacon node",
		Long:  "Reason `broadcast_bn_error` indicates that beacon node returned an error while submitting aggregated duty signature to beacon node.",
	}

	reasonNotIncludedOnChain = reason{
		Code:  "not_included_onchain",
		Short: "duty not included on-chain",
		Long:  "Reason `not_included_onchain` indicates that even though charon broadcasted the duty successfully, it wasn't included in the beacon chain. This is expected for up to 20% of attestations. It may however indicate problematic charon broadcast delays or beacon node network problems.",
	}

	reasonBugFetchError = reason{
		Code:  "bug_fetch_error",
		Short: "bug: couldn't fetch due to unexpected error",
		Long:  "Reason `bug_fetch_error` indicates duty failed in fetcher step with some unexpected error. This indicates a problem in charon as it is unexpected.",
	}

	reasonBugParSigDBInconsistent = reason{
		Code:  "bug_par_sig_db_inconsistent",
		Short: "bug: inconsistent partial signatures received",
		Long:  "Reason `bug_par_sig_db_inconsistent` indicates that partial signed data for the duty were inconsistent. This indicates a bug in charon as it is unexpected (for non-sync-committee-duties).",
	}

	reasonBugParSigDBExternal = reason{
		Code:  "bug_par_sig_db_external",
		Short: "bug: failed to store external partial signatures in parsigdb",
		Long:  "Reason `bug_par_sig_db_external` indicates a bug in the partial signature database as it is unexpected.",
	}

	reasonBugSigAgg = reason{
		Code:  "bug_sig_agg",
		Short: "bug: threshold aggregation of partial signatures failed due to inconsistent signed data",
		Long:  "Reason `bug_sig_agg` indicates that BLS threshold aggregation of sufficient partial signatures failed. This indicates inconsistent signed data. This indicates a bug in charon as it is unexpected.",
	}

	reasonBugAggregationError = reason{
		Code:  "bug_aggregation_error",
		Short: "bug: failed to store aggregated signature in aggsigdb",
		Long:  "Reason `bug_aggregation_error` indicates a bug in the aggregated signature database as it is unexpected.",
	}

	reasonBugDutyDBError = reason{
		Code:  "bug_duty_db_error",
		Short: "bug: failed to store duty data in DutyDB",
		Long:  "Reason `bug_duty_db_error` indicates a bug in the DutyDB database as it is unexpected.",
	}

	reasonBugParSigDBInternal = reason{
		Code:  "bug_par_sig_db_internal",
		Short: "bug: partial signature database didn't trigger partial signature exchange, this is unexpected",
		Long:  "Reason `bug_par_sig_db_internal` indicates a bug in the partial signature database as it is unexpected. Note this may happen due to expiry race.",
	}
)
