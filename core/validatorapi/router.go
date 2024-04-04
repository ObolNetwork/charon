// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package validatorapi defines validator facing API that serves the subset of
// endpoints related to distributed validation and reverse-proxies the rest to the
// upstream beacon client.
package validatorapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type contentType string

const (
	contentTypeJSON               contentType = "application/json"
	contentTypeSSZ                contentType = "application/octet-stream"
	versionHeader                             = "Eth-Consensus-Version"
	executionPayloadBlindedHeader             = "Eth-Execution-Payload-Blinded"
	executionPayloadValueHeader               = "Eth-Execution-Payload-Value"
	consensusBlockValueHeader                 = "Eth-Consensus-Block-Value"
)

// Handler defines the request handler providing the business logic
// for the validator API router.
type Handler interface {
	eth2client.AggregateAttestationProvider
	eth2client.AggregateAttestationsSubmitter
	eth2client.AttestationDataProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.ProposalProvider
	eth2client.ProposalSubmitter
	eth2exp.BeaconCommitteeSelectionAggregator
	eth2client.BlindedProposalSubmitter
	eth2client.NodeVersionProvider
	eth2client.ProposerDutiesProvider
	eth2client.SyncCommitteeContributionProvider
	eth2client.SyncCommitteeContributionsSubmitter
	eth2client.SyncCommitteeDutiesProvider
	eth2client.SyncCommitteeMessagesSubmitter
	eth2exp.SyncCommitteeSelectionAggregator
	eth2client.ValidatorsProvider
	eth2client.ValidatorRegistrationsSubmitter
	eth2client.VoluntaryExitSubmitter
	eth2exp.ProposerConfigProvider
	// Above sorted alphabetically.
}

// NewRouter returns a new validator http server router. The http router
// translates http requests related to the distributed validator to the Handler.
// All other requests are reverse-proxied to the beacon-node address.
func NewRouter(ctx context.Context, h Handler, eth2Cl eth2wrap.Client, isBuilderEnabled core.BuilderEnabled) (*mux.Router, error) {
	// Register subset of distributed validator related endpoints.
	endpoints := []struct {
		Name    string
		Path    string
		Handler handlerFunc
		Methods []string
	}{
		{
			Name:    "attester_duties",
			Path:    "/eth/v1/validator/duties/attester/{epoch}",
			Handler: attesterDuties(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "proposer_duties",
			Path:    "/eth/v1/validator/duties/proposer/{epoch}",
			Handler: proposerDuties(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "sync_committee_duties",
			Path:    "/eth/v1/validator/duties/sync/{epoch}",
			Handler: syncCommitteeDuties(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "attestation_data",
			Path:    "/eth/v1/validator/attestation_data",
			Handler: attestationData(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "submit_attestations",
			Path:    "/eth/v1/beacon/pool/attestations",
			Handler: submitAttestations(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "get_validators",
			Path:    "/eth/v1/beacon/states/{state_id}/validators",
			Handler: getValidators(h),
			Methods: []string{http.MethodPost, http.MethodGet},
		},
		{
			Name:    "get_validator",
			Path:    "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
			Handler: getValidator(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "propose_block_v3",
			Path:    "/eth/v3/validator/blocks/{slot}",
			Handler: proposeBlockV3(h, isBuilderEnabled),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "submit_proposal_v1",
			Path:    "/eth/v1/beacon/blocks",
			Handler: submitProposal(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_proposal_v2",
			Path:    "/eth/v2/beacon/blocks",
			Handler: submitProposal(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_blinded_block_v1",
			Path:    "/eth/v1/beacon/blinded_blocks",
			Handler: submitBlindedBlock(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_blinded_block_v2",
			Path:    "/eth/v2/beacon/blinded_blocks",
			Handler: submitBlindedBlock(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_validator_registration",
			Path:    "/eth/v1/validator/register_validator",
			Handler: submitValidatorRegistrations(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_voluntary_exit",
			Path:    "/eth/v1/beacon/pool/voluntary_exits",
			Handler: submitExit(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "teku_proposer_config",
			Path:    "/teku_proposer_config",
			Handler: proposerConfig(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "proposer_config",
			Path:    "/proposer_config",
			Handler: proposerConfig(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "aggregate_beacon_committee_selections",
			Path:    "/eth/v1/validator/beacon_committee_selections",
			Handler: aggregateBeaconCommitteeSelections(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "aggregate_attestation",
			Path:    "/eth/v1/validator/aggregate_attestation",
			Handler: aggregateAttestation(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "submit_aggregate_and_proofs",
			Path:    "/eth/v1/validator/aggregate_and_proofs",
			Handler: submitAggregateAttestations(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_sync_committee_messages",
			Path:    "/eth/v1/beacon/pool/sync_committees",
			Handler: submitSyncCommitteeMessages(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "sync_committee_contribution",
			Path:    "/eth/v1/validator/sync_committee_contribution",
			Handler: syncCommitteeContribution(h),
			Methods: []string{http.MethodGet},
		},
		{
			Name:    "submit_contribution_and_proofs",
			Path:    "/eth/v1/validator/contribution_and_proofs",
			Handler: submitContributionAndProofs(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "submit_proposal_preparations",
			Path:    "/eth/v1/validator/prepare_beacon_proposer",
			Handler: submitProposalPreparations(),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "aggregate_sync_committee_selections",
			Path:    "/eth/v1/validator/sync_committee_selections",
			Handler: aggregateSyncCommitteeSelections(h),
			Methods: []string{http.MethodPost},
		},
		{
			Name:    "node_version",
			Path:    "/eth/v1/node/version",
			Handler: nodeVersion(h),
			Methods: []string{http.MethodGet},
		},
	}

	r := mux.NewRouter()
	for _, e := range endpoints {
		handler := r.Handle(e.Path, wrap(e.Name, e.Handler))
		if len(e.Methods) != 0 {
			handler.Methods(e.Methods...)
		}
	}

	// Everything else is proxied
	r.PathPrefix("/").Handler(proxyHandler(ctx, eth2Cl))

	return r, nil
}

// apiErr defines a validator api error that is converted to an eth2 errorResponse.
type apiError struct {
	// StatusCode is the http status code to return, defaults to 500.
	StatusCode int
	// Message is a safe human-readable message, defaults to "Internal server error".
	Message string
	// Err is the original error, returned in debug mode.
	Err error
}

func (a apiError) Error() string {
	return fmt.Sprintf("api error[status=%d,msg=%s]: %v", a.StatusCode, a.Message, a.Err)
}

// handlerFunc is a convenient handler function providing a context, parsed path parameters,
// the request body, and returning the response struct or an error.
type handlerFunc func(ctx context.Context, params map[string]string, query url.Values, typ contentType, body []byte) (res any, headers http.Header, err error)

// wrap adapts the handler function returning a standard http handler.
// It does tracing, metrics and response and error writing.
func wrap(endpoint string, handler handlerFunc) http.Handler {
	wrap := func(w http.ResponseWriter, r *http.Request) {
		defer observeAPILatency(endpoint)()

		ctx := r.Context()
		ctx = log.WithTopic(ctx, "vapi")
		ctx = log.WithCtx(ctx, z.Str("vapi_endpoint", endpoint))
		ctx = withCtxDuration(ctx)

		var typ contentType
		contentHeader := r.Header.Get("Content-Type")
		if contentHeader == "" || strings.Contains(contentHeader, string(contentTypeJSON)) {
			typ = contentTypeJSON
		} else if strings.Contains(contentHeader, string(contentTypeSSZ)) {
			typ = contentTypeSSZ
		} else {
			writeError(ctx, w, endpoint, apiError{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    fmt.Sprintf("unsupported media type %s", contentHeader),
			})

			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(ctx, w, endpoint, err)
			return
		}

		res, headers, err := handler(ctx, mux.Vars(r), r.URL.Query(), typ, body)
		if err != nil {
			writeError(ctx, w, endpoint, err)
			return
		}

		writeResponse(ctx, w, endpoint, res, headers)
	}

	return wrapTrace(endpoint, wrap)
}

// writeResponse writes the 200 OK response and json response body.
func writeResponse(ctx context.Context, w http.ResponseWriter, endpoint string, response any, headers http.Header) {
	if response == nil {
		return
	}

	b, err := json.Marshal(response)
	if err != nil {
		writeError(ctx, w, endpoint, errors.Wrap(err, "marshal response body"))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	for name, values := range headers {
		for _, val := range values {
			w.Header().Add(name, val)
		}
	}

	if _, err = w.Write(b); err != nil {
		// Too late to also try to writeError at this point, so just log.
		log.Error(ctx, "Failed writing api response", err)
	}
}

// wrapTrace wraps the passed handler in a OpenTelemetry tracing span.
func wrapTrace(endpoint string, handler http.HandlerFunc) http.Handler {
	return otelhttp.NewHandler(handler, "core/validatorapi."+endpoint)
}

// getValidators returns a handler function for the get validators by pubkey or index endpoint.
func getValidators(p eth2client.ValidatorsProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, _ contentType, body []byte) (any, http.Header, error) {
		stateID := params["state_id"]

		// TODO: support 'status' param when go-eth2-client supports it
		// https://github.com/ObolNetwork/charon/issues/2846
		ids := getValidatorIDs(query)
		if len(ids) == 0 && len(body) > 0 {
			postIDs, err := getValidatorIDsFromJSON(body)
			if err != nil {
				return nil, nil, errors.Wrap(err, "getting validator ids from request body")
			}

			ids = postIDs
		}

		resp, err := getValidatorsByID(ctx, p, stateID, ids...)
		if err != nil {
			return nil, nil, err
		} else if len(resp) == 0 {
			resp = []v1Validator{} // Return empty json array instead of null.
		}

		return validatorsResponse{Data: resp}, nil, nil
	}
}

// getValidator returns a handler function for the get validators by pubkey or index endpoint.
func getValidator(p eth2client.ValidatorsProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		stateID := params["state_id"]
		id := params["validator_id"]

		vals, err := getValidatorsByID(ctx, p, stateID, id)
		if err != nil {
			return nil, nil, err
		} else if len(vals) == 0 {
			return nil, nil, apiError{
				StatusCode: http.StatusNotFound,
				Message:    "NotFound",
			}
		} else if len(vals) != 1 {
			return nil, nil, errors.New("unexpected number of validators")
		}

		return validatorResponse{Data: vals[0]}, nil, nil
	}
}

// attestationData returns a handler function for the attestation data endpoint.
func attestationData(p eth2client.AttestationDataProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		slot, err := uintQuery(query, "slot")
		if err != nil {
			return nil, nil, err
		}

		commIdx, err := uintQuery(query, "committee_index")
		if err != nil {
			return nil, nil, err
		}

		opts := &eth2api.AttestationDataOpts{
			Slot:           eth2p0.Slot(slot),
			CommitteeIndex: eth2p0.CommitteeIndex(commIdx),
		}
		eth2Resp, err := p.AttestationData(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		data := eth2Resp.Data

		return struct {
			Data *eth2p0.AttestationData `json:"data"`
		}{
			Data: data,
		}, nil, nil
	}
}

// submitAttestations returns a handler function for the attestation submitter endpoint.
func submitAttestations(p eth2client.AttestationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var atts []*eth2p0.Attestation
		err := unmarshal(typ, body, &atts)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal attestations")
		}

		return nil, nil, p.SubmitAttestations(ctx, atts)
	}
}

// proposerDuties returns a handler function for the proposer duty endpoint.
func proposerDuties(p eth2client.ProposerDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, nil, err
		}

		// Note the ProposerDutiesProvider interface adds some sugar to the official eth2spec.
		// ValidatorIndices aren't provided over the wire.
		opts := &eth2api.ProposerDutiesOpts{
			Epoch:   eth2p0.Epoch(epoch),
			Indices: nil,
		}
		eth2Resp, err := p.ProposerDuties(ctx, opts)
		if err != nil {
			return nil, nil, err
		}

		data := eth2Resp.Data
		if len(data) == 0 { // Return empty json array instead of null
			data = []*eth2v1.ProposerDuty{}
		}

		executionOptimistic, err := getExecutionOptimisticFromMetadata(eth2Resp.Metadata)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to decode ProposerDuties response metadata")
		}

		dependentRoot, err := getDependentRootFromMetadata(eth2Resp.Metadata)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to decode ProposerDuties response metadata")
		}

		return proposerDutiesResponse{
			ExecutionOptimistic: executionOptimistic,
			DependentRoot:       dependentRoot,
			Data:                data,
		}, nil, nil
	}
}

// attesterDuties returns a handler function for the attester duty endpoint.
func attesterDuties(p eth2client.AttesterDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, nil, err
		}

		var req valIndexesJSON
		if err := unmarshal(typ, body, &req); err != nil {
			return nil, nil, err
		}

		opts := &eth2api.AttesterDutiesOpts{
			Epoch:   eth2p0.Epoch(epoch),
			Indices: req,
		}
		eth2Resp, err := p.AttesterDuties(ctx, opts)
		if err != nil {
			return nil, nil, err
		}

		data := eth2Resp.Data
		if len(data) == 0 { // Return empty json array instead of null
			data = []*eth2v1.AttesterDuty{}
		}

		executionOptimistic, err := getExecutionOptimisticFromMetadata(eth2Resp.Metadata)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to decode AttesterDuties response metadata")
		}

		dependentRoot, err := getDependentRootFromMetadata(eth2Resp.Metadata)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to decode AttesterDuties response metadata")
		}

		return attesterDutiesResponse{
			ExecutionOptimistic: executionOptimistic,
			DependentRoot:       dependentRoot,
			Data:                data,
		}, nil, nil
	}
}

// syncCommitteeDuties returns a handler function for the sync committee duty endpoint.
func syncCommitteeDuties(p eth2client.SyncCommitteeDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, nil, err
		}

		var req valIndexesJSON
		if err := unmarshal(typ, body, &req); err != nil {
			return nil, nil, err
		}

		opts := &eth2api.SyncCommitteeDutiesOpts{
			Epoch:   eth2p0.Epoch(epoch),
			Indices: req,
		}
		eth2Resp, err := p.SyncCommitteeDuties(ctx, opts)
		if err != nil {
			return nil, nil, err
		}

		data := eth2Resp.Data
		if len(data) == 0 { // Return empty json array instead of null
			data = []*eth2v1.SyncCommitteeDuty{}
		}

		return syncCommitteeDutiesResponse{Data: data}, nil, nil
	}
}

// syncCommitteeContribution returns a handler function for get sync committee contribution endpoint.
func syncCommitteeContribution(s eth2client.SyncCommitteeContributionProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		slot, err := uintQuery(query, "slot")
		if err != nil {
			return nil, nil, err
		}

		subcommIdx, err := uintQuery(query, "subcommittee_index")
		if err != nil {
			return nil, nil, err
		}

		var beaconBlockRoot eth2p0.Root
		err = hexQueryFixed(query, "beacon_block_root", beaconBlockRoot[:])
		if err != nil {
			return nil, nil, err
		}

		opts := &eth2api.SyncCommitteeContributionOpts{
			Slot:              eth2p0.Slot(slot),
			SubcommitteeIndex: subcommIdx,
			BeaconBlockRoot:   beaconBlockRoot,
		}
		eth2Resp, err := s.SyncCommitteeContribution(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		contribution := eth2Resp.Data

		return syncCommitteeContributionResponse{Data: contribution}, nil, nil
	}
}

// submitContributionAndProofs returns a handler function for sync committee contributions submitter endpoint.
func submitContributionAndProofs(s eth2client.SyncCommitteeContributionsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var contributionAndProofs []*altair.SignedContributionAndProof
		err := unmarshal(typ, body, &contributionAndProofs)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed contribution and proofs")
		}

		return nil, nil, s.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
	}
}

// proposeBlockV3 returns a handler function returning an unsigned BeaconBlock or BlindedBeaconBlock.
func proposeBlockV3(p eth2client.ProposalProvider, builderEnabled core.BuilderEnabled) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		slot, randao, graffiti, err := getProposeBlockParams(params, query)
		if err != nil {
			return nil, nil, err
		}

		var bbf uint64
		if builderEnabled(slot) {
			// This gives maximum priority to builder blocks:
			// https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV3
			bbf = math.MaxUint64
		}

		opts := &eth2api.ProposalOpts{
			Slot:               eth2p0.Slot(slot),
			RandaoReveal:       randao,
			Graffiti:           graffiti,
			BuilderBoostFactor: &bbf,
		}

		eth2Resp, err := p.Proposal(ctx, opts)
		if err != nil {
			return nil, nil, err
		}

		proposal := eth2Resp.Data

		proposedBlock, err := createProposeBlockResponse(proposal)
		if err != nil {
			return nil, nil, err
		}

		resHeaders := make(http.Header)
		resHeaders.Add(versionHeader, proposal.Version.String())
		resHeaders.Add(executionPayloadBlindedHeader, strconv.FormatBool(proposal.Blinded))
		resHeaders.Add(executionPayloadValueHeader, proposal.ExecutionValue.String())
		resHeaders.Add(consensusBlockValueHeader, proposal.ConsensusValue.String())

		return proposedBlock, resHeaders, nil
	}
}

// getProposeBlockParams returns slot, randao and graffiti from propose block request params.
func getProposeBlockParams(params map[string]string, query url.Values) (uint64, eth2p0.BLSSignature, [32]byte, error) {
	slot, err := uintParam(params, "slot")
	if err != nil {
		return 0, eth2p0.BLSSignature{}, [32]byte{}, err
	}

	var randao eth2p0.BLSSignature
	if err := hexQueryFixed(query, "randao_reveal", randao[:]); err != nil {
		return 0, eth2p0.BLSSignature{}, [32]byte{}, err
	}

	graffitiBytes, _, err := hexQuery(query, "graffiti") // Graffiti is optional.
	if err != nil {
		return 0, eth2p0.BLSSignature{}, [32]byte{}, err
	}

	var graffiti [32]byte
	copy(graffiti[:], graffitiBytes)

	return slot, randao, graffiti, err
}

// createProposeBlockResponse constructs proposeBlockV3Response object for given block.
func createProposeBlockResponse(proposal *eth2api.VersionedProposal) (*proposeBlockV3Response, error) {
	var (
		version   string
		blockData any
	)

	switch proposal.Version {
	case eth2spec.DataVersionPhase0:
		if proposal.Blinded {
			return nil, errors.New("invalid blinded block")
		}
		if proposal.Phase0 == nil {
			return nil, errors.New("no phase0 block")
		}

		version = eth2spec.DataVersionPhase0.String()
		blockData = proposal.Phase0
	case eth2spec.DataVersionAltair:
		if proposal.Blinded {
			return nil, errors.New("invalid blinded block")
		}
		if proposal.Altair == nil {
			return nil, errors.New("no altair block")
		}

		version = eth2spec.DataVersionAltair.String()
		blockData = proposal.Altair
	case eth2spec.DataVersionBellatrix:
		version = eth2spec.DataVersionBellatrix.String()
		if proposal.Blinded {
			if proposal.BellatrixBlinded == nil {
				return nil, errors.New("no bellatrix blinded block")
			}
			blockData = proposal.BellatrixBlinded
		} else {
			if proposal.Bellatrix == nil {
				return nil, errors.New("no bellatrix block")
			}
			blockData = proposal.Bellatrix
		}
	case eth2spec.DataVersionCapella:
		version = eth2spec.DataVersionCapella.String()
		if proposal.Blinded {
			if proposal.CapellaBlinded == nil {
				return nil, errors.New("no capella blinded block")
			}
			blockData = proposal.CapellaBlinded
		} else {
			if proposal.Capella == nil {
				return nil, errors.New("no capella block")
			}
			blockData = proposal.Capella
		}
	case eth2spec.DataVersionDeneb:
		version = eth2spec.DataVersionDeneb.String()
		if proposal.Blinded {
			if proposal.DenebBlinded == nil {
				return nil, errors.New("no deneb blinded block")
			}
			blockData = proposal.DenebBlinded
		} else {
			if proposal.Deneb == nil {
				return nil, errors.New("no deneb block")
			}
			blockData = proposal.Deneb
		}
	default:
		if proposal.Blinded {
			return nil, errors.New("invalid blinded block")
		}

		return nil, errors.New("invalid block")
	}

	return &proposeBlockV3Response{
		Version:                 version,
		Data:                    blockData,
		ExecutionPayloadBlinded: proposal.Blinded,
		ExecutionPayloadValue:   proposal.ExecutionValue.String(),
		ConsensusBlockValue:     proposal.ConsensusValue.String(),
	}, nil
}

func submitProposal(p eth2client.ProposalSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		denebBlock := new(deneb.SignedBlockContents)
		err := unmarshal(typ, body, denebBlock)
		if err == nil {
			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   denebBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})
		}

		capellaBlock := new(capella.SignedBeaconBlock)
		err = unmarshal(typ, body, capellaBlock)
		if err == nil {
			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: capellaBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})
		}

		bellatrixBlock := new(bellatrix.SignedBeaconBlock)
		err = unmarshal(typ, body, bellatrixBlock)
		if err == nil {
			block := &eth2api.VersionedSignedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Bellatrix: bellatrixBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})
		}

		altairBlock := new(altair.SignedBeaconBlock)
		err = unmarshal(typ, body, altairBlock)
		if err == nil {
			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair:  altairBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})
		}

		phase0Block := new(eth2p0.SignedBeaconBlock)
		err = unmarshal(typ, body, phase0Block)
		if err == nil {
			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0:  phase0Block,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})
		}

		return nil, nil, errors.New("invalid submitted block", z.Hex("body", body))
	}
}

func submitBlindedBlock(p eth2client.BlindedProposalSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		// The blinded block maybe either bellatrix, capella or deneb.
		denebBlock := new(deneb.SignedBlindedBeaconBlock)
		err := unmarshal(typ, body, denebBlock)
		if err == nil {
			block := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   denebBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})
		}

		capellaBlock := new(eth2capella.SignedBlindedBeaconBlock)
		err = unmarshal(typ, body, capellaBlock)
		if err == nil {
			block := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: capellaBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})
		}

		bellatrixBlock := new(eth2bellatrix.SignedBlindedBeaconBlock)
		err = unmarshal(typ, body, bellatrixBlock)
		if err == nil {
			block := &eth2api.VersionedSignedBlindedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Bellatrix: bellatrixBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})
		}

		return nil, nil, errors.New("invalid block")
	}
}

// submitValidatorRegistrations returns a handler function for the validator (builder) registration submitter endpoint.
func submitValidatorRegistrations(r eth2client.ValidatorRegistrationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var unversioned []*eth2v1.SignedValidatorRegistration
		if err := unmarshal(typ, body, &unversioned); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed builder registration")
		}

		var versioned []*eth2api.VersionedSignedValidatorRegistration
		for _, registration := range unversioned {
			versioned = append(versioned, &eth2api.VersionedSignedValidatorRegistration{
				Version: eth2spec.BuilderVersionV1,
				V1:      registration,
			})
		}

		return nil, nil, r.SubmitValidatorRegistrations(ctx, versioned)
	}
}

// aggregateBeaconCommitteeSelections receives partial beacon committee selections and returns aggregated selections.
func aggregateBeaconCommitteeSelections(a eth2exp.BeaconCommitteeSelectionAggregator) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (res any, headers http.Header, err error) {
		var selections []*eth2exp.BeaconCommitteeSelection
		if err := unmarshal(typ, body, &selections); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal beacon committee selections")
		}

		resp, err := a.AggregateBeaconCommitteeSelections(ctx, selections)
		if err != nil {
			return nil, nil, err
		}

		return aggregateBeaconCommitteeSelectionsJSON{Data: resp}, nil, nil
	}
}

// aggregateSyncCommitteeSelections receives partial sync committee selections and returns aggregated selections.
func aggregateSyncCommitteeSelections(a eth2exp.SyncCommitteeSelectionAggregator) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (res any, headers http.Header, err error) {
		var selections []*eth2exp.SyncCommitteeSelection
		if err := unmarshal(typ, body, &selections); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal sync committee selections")
		}

		resp, err := a.AggregateSyncCommitteeSelections(ctx, selections)
		if err != nil {
			return nil, nil, err
		}

		return aggregateSyncCommitteeSelectionsJSON{Data: resp}, nil, nil
	}
}

// submitExit returns a handler function for the exit submitter endpoint.
func submitExit(p eth2client.VoluntaryExitSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		exit := new(eth2p0.SignedVoluntaryExit)
		if err := unmarshal(typ, body, exit); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed voluntary exit")
		}

		return nil, nil, p.SubmitVoluntaryExit(ctx, exit)
	}
}

func proposerConfig(p eth2exp.ProposerConfigProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		resp, err := p.ProposerConfig(ctx)
		if err != nil {
			return nil, nil, errors.Wrap(err, "proposer config")
		}

		return resp, nil, nil
	}
}

func aggregateAttestation(p eth2client.AggregateAttestationProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		slot, err := uintQuery(query, "slot")
		if err != nil {
			return nil, nil, err
		}

		var attDataRoot eth2p0.Root
		if err := hexQueryFixed(query, "attestation_data_root", attDataRoot[:]); err != nil {
			return nil, nil, err
		}

		opts := &eth2api.AggregateAttestationOpts{
			Slot:                eth2p0.Slot(slot),
			AttestationDataRoot: attDataRoot,
		}
		eth2Resp, err := p.AggregateAttestation(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		data := eth2Resp.Data

		return struct {
			Data *eth2p0.Attestation `json:"data"`
		}{
			Data: data,
		}, nil, nil
	}
}

func submitAggregateAttestations(s eth2client.AggregateAttestationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var aggs []*eth2p0.SignedAggregateAndProof
		err := unmarshal(typ, body, &aggs)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed aggregate and proofs")
		}

		err = s.SubmitAggregateAttestations(ctx, aggs)
		if err != nil {
			return nil, nil, err
		}

		return nil, nil, nil
	}
}

func submitSyncCommitteeMessages(s eth2client.SyncCommitteeMessagesSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var msgs []*altair.SyncCommitteeMessage
		err := unmarshal(typ, body, &msgs)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal sync committee messages")
		}

		err = s.SubmitSyncCommitteeMessages(ctx, msgs)
		if err != nil {
			return nil, nil, err
		}

		return nil, nil, nil
	}
}

// submitProposalPreparations swallows fee-recipient-address from validator client as it should be
// configured by charon from cluster-lock.json and VC need not be configured with correct fee-recipient-address.
func submitProposalPreparations() handlerFunc {
	return func(context.Context, map[string]string, url.Values, contentType, []byte) (any, http.Header, error) {
		return nil, nil, nil
	}
}

// nodeVersion returns the version of the node.
func nodeVersion(p eth2client.NodeVersionProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		eth2Resp, err := p.NodeVersion(ctx, &eth2api.NodeVersionOpts{})
		if err != nil {
			return nil, nil, err
		}
		version := eth2Resp.Data

		return nodeVersionResponse{
			Data: struct {
				Version string `json:"version"`
			}(struct{ Version string }{Version: version}),
		}, nil, nil
	}
}

// addressProvider provides the address of the active beacon node.
type addressProvider interface {
	Address() string
}

// proxyHandler returns a reverse proxy handler.
// Proxied requests use the provided context, so are cancelled when the context is cancelled.
func proxyHandler(ctx context.Context, addrProvider addressProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get active beacon node address.
		targetURL, err := getBeaconNodeAddress(addrProvider)
		if err != nil {
			ctx := log.WithTopic(r.Context(), "vapi")
			log.Error(ctx, "Proxy target beacon node address", err)
			writeError(ctx, w, "proxy", err)

			return
		}
		// Get address for active beacon node
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		// Extend default proxy director with basic auth and host header.
		defaultDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			if targetURL.User != nil {
				password, _ := targetURL.User.Password()
				req.SetBasicAuth(targetURL.User.Username(), password)
			}
			req.Host = targetURL.Host
			defaultDirector(req)
		}
		proxy.ErrorLog = stdlog.New(io.Discard, "", 0)

		// Use provided context for proxied requests, so long running
		// requests are cancelled when this context is cancelled (soft shutdown).
		clonedReq := r.Clone(ctx)

		defer observeAPILatency("proxy")()
		proxy.ServeHTTP(proxyResponseWriter{w.(writeFlusher)}, clonedReq)
	}
}

// getBeaconNodeAddress returns an active beacon node proxy target address.
func getBeaconNodeAddress(addrProvider addressProvider) (*url.URL, error) {
	addr := addrProvider.Address()
	targetURL, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, errors.Wrap(err, "invalid beacon node address", z.Str("address", addr))
	}

	return targetURL, nil
}

// writeError writes a http json error response object.
func writeError(ctx context.Context, w http.ResponseWriter, endpoint string, err error) {
	if ctx.Err() != nil {
		// Client cancelled the request
		err = apiError{
			StatusCode: http.StatusRequestTimeout,
			Message:    "client cancelled request",
			Err:        ctx.Err(),
		}
	}

	var aerr apiError
	if !errors.As(err, &aerr) {
		aerr = apiError{
			StatusCode: http.StatusInternalServerError,
			Message:    "Internal server error",
			Err:        err,
		}
	}

	if aerr.StatusCode/100 == 4 {
		// 4xx status codes are client errors (not server), so log as debug only.
		log.Debug(ctx, "Validator api 4xx response",
			z.Int("status_code", aerr.StatusCode),
			z.Str("message", aerr.Message),
			z.Err(err),
			getCtxDuration(ctx))
	} else {
		// 5xx status codes (or other weird ranges) are server errors, so log as error.
		log.Error(ctx, "Validator api 5xx response", err,
			z.Int("status_code", aerr.StatusCode),
			z.Str("message", aerr.Message),
			getCtxDuration(ctx))
	}

	incAPIErrors(endpoint, aerr.StatusCode)

	res := errorResponse{
		Code:    aerr.StatusCode,
		Message: aerr.Message,
		// TODO(corver): Add support for debug mode error and stacktraces.
	}

	b, err2 := json.Marshal(res)
	if err2 != nil {
		// Log and continue to write nil b.
		log.Error(ctx, "Failed marshalling error response", err2)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(aerr.StatusCode)

	if _, err2 = w.Write(b); err2 != nil {
		log.Error(ctx, "Failed writing api error", err2)
	}
}

// unmarshal parses body with the appropriate unmarshaler based on the contentType and stores the result
// in the value pointed to by v.
func unmarshal(typ contentType, body []byte, v any) error {
	if len(body) == 0 {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    "empty request body",
			Err:        errors.New("empty request body"),
		}
	}

	if typ == contentTypeJSON {
		err := json.Unmarshal(body, v)
		if err != nil {
			return apiError{
				StatusCode: http.StatusBadRequest,
				Message:    "failed parsing json request body",
				Err:        err,
			}
		}

		return nil
	} else if typ == contentTypeSSZ {
		unmarshaller, ok := v.(ssz.Unmarshaler)
		if !ok {
			return apiError{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal type doesn't support ssz unmarshalling",
				Err:        errors.New("internal type doesn't support ssz unmarshalling"),
			}
		}

		err := unmarshaller.UnmarshalSSZ(body)
		if err != nil {
			return apiError{
				StatusCode: http.StatusBadRequest,
				Message:    "failed parsing ssz request body",
				Err:        err,
			}
		}

		return nil
	}

	return errors.New("bug: invalid content type")
}

// uintParam returns a uint path parameter.
func uintParam(params map[string]string, name string) (uint64, error) {
	param, ok := params[name]
	if !ok {
		return 0, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("missing path parameter %s", name),
		}
	}

	res, err := strconv.ParseUint(param, 10, 64)
	if err != nil {
		return 0, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid uint path parameter %s [%s]", name, param),
			Err:        err,
		}
	}

	return res, nil
}

// uintQuery returns a uint query parameter.
func uintQuery(query url.Values, name string) (uint64, error) {
	if !query.Has(name) {
		return 0, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("missing query parameter %s", name),
		}
	}

	param := query.Get(name)

	res, err := strconv.ParseUint(param, 10, 64)
	if err != nil {
		return 0, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid uint path parameter %s [%s]", name, param),
			Err:        err,
		}
	}

	return res, nil
}

// hexQueryFixed parses a fixed length 0x-hex query parameter into target.
func hexQueryFixed(query url.Values, name string, target []byte) error {
	resp, ok, err := hexQuery(query, name)
	if err != nil {
		return err
	} else if !ok {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("missing 0x-hex query parameter %s", name),
		}
	} else if len(resp) != len(target) {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid length for 0x-hex query parameter %s, expect %d bytes", name, len(target)),
		}
	}
	copy(target, resp)

	return nil
}

// hexQuery returns a 0x-prefixed hex query parameter with name or false if not present.
func hexQuery(query url.Values, name string) ([]byte, bool, error) {
	valueA, ok := query[name]
	if !ok || len(valueA) != 1 {
		return nil, false, nil
	}
	value := valueA[0]

	resp, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		return nil, false, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid 0x-hex query parameter %s [%s]", name, value),
			Err:        err,
		}
	}

	return resp, true, nil
}

// writeFlusher is copied from /net/http/httputil/reverseproxy.go.
// It is required to flush streaming responses.
type writeFlusher interface {
	http.ResponseWriter
	http.Flusher
}

// proxyResponseWriter wraps the writeFlusher interface and instruments errors.
type proxyResponseWriter struct {
	writeFlusher
}

func (w proxyResponseWriter) WriteHeader(statusCode int) {
	if statusCode/100 == 2 {
		// 2XX isn't an error
		return
	}

	incAPIErrors("proxy", statusCode)
	w.writeFlusher.WriteHeader(statusCode)
}

// getValidatorIDs returns validator IDs as "id" array query parameters.
func getValidatorIDs(query url.Values) []string {
	return getQueryArrayParameter(query, "id")
}

// getQueryArrayParameter returns all array values passed as query parameter (supporting csv values).
func getQueryArrayParameter(query url.Values, param string) []string {
	var resp []string
	for _, csv := range query[param] {
		for _, id := range strings.Split(csv, ",") {
			resp = append(resp, strings.TrimSpace(id))
		}
	}

	return resp
}

// getValidatorIDsFromJSON returns validator IDs as "id" field of json payload.
func getValidatorIDsFromJSON(b []byte) ([]string, error) {
	requestBody := struct {
		IDs []string `json:"ids"`
	}{}

	if err := json.Unmarshal(b, &requestBody); err != nil {
		return nil, errors.Wrap(err, "failed to parse request body")
	}

	return requestBody.IDs, nil
}

// getValidatorsByID returns the validators with ids being either pubkeys or validator indexes.
func getValidatorsByID(ctx context.Context, p eth2client.ValidatorsProvider, stateID string, ids ...string) ([]v1Validator, error) {
	flatten := func(kvs map[eth2p0.ValidatorIndex]*eth2v1.Validator) []v1Validator {
		var vals []v1Validator
		for _, v := range kvs {
			vals = append(vals, v1Validator(*v))
		}

		return vals
	}

	if len(ids) > 0 && strings.HasPrefix(ids[0], "0x") {
		var pubkeys []eth2p0.BLSPubKey
		for _, id := range ids {
			coreBytes, err := core.PubKey(id).Bytes()
			if err != nil {
				return nil, errors.Wrap(err, "fetch public key bytes")
			}
			pubkey, err := tblsconv.PubkeyFromBytes(coreBytes)
			if err != nil {
				return nil, errors.Wrap(err, "decode public key hex")
			}
			eth2Pubkey := eth2p0.BLSPubKey(pubkey)

			pubkeys = append(pubkeys, eth2Pubkey)
		}

		opts := &eth2api.ValidatorsOpts{
			State:   stateID,
			PubKeys: pubkeys,
		}
		eth2Resp, err := p.Validators(ctx, opts)
		if err != nil {
			return nil, err
		}
		vals := eth2Resp.Data

		return flatten(vals), nil
	}

	var vIdxs []eth2p0.ValidatorIndex
	for _, id := range ids {
		vIdx, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			return nil, errors.Wrap(err, "parse validator index")
		}
		vIdxs = append(vIdxs, eth2p0.ValidatorIndex(vIdx))
	}

	opts := &eth2api.ValidatorsOpts{
		State:   stateID,
		Indices: vIdxs,
	}
	eth2Resp, err := p.Validators(ctx, opts)
	if err != nil {
		return nil, err
	}
	vals := eth2Resp.Data

	return flatten(vals), nil
}

type durationKey struct{}

// withCtxDuration returns a copy of parent in which the current time is associated with the duration key.
func withCtxDuration(ctx context.Context) context.Context {
	return context.WithValue(ctx, durationKey{}, time.Now())
}

// getCtxDuration returns a zap field with the duration withCtxDuration was called on the context.
// Else it returns a noop zap field.
func getCtxDuration(ctx context.Context) z.Field {
	v := ctx.Value(durationKey{})
	if v == nil {
		return z.Skip
	}
	t0, ok := v.(time.Time)
	if !ok {
		return z.Skip
	}

	return z.Str("duration", time.Since(t0).String())
}

// getExecutionOptimisticFromMetadata returns execution_optimistic value from metadata,
// or error if it is missing or has a wrong type.
// Default value `false` is returned in case metadata is nil.
func getExecutionOptimisticFromMetadata(metadata map[string]any) (bool, error) {
	if metadata == nil {
		return false, nil
	}

	if v, has := metadata["execution_optimistic"]; has {
		if b, ok := v.(bool); ok {
			return b, nil
		}

		return false, errors.New("metadata has malformed execution_optimistic value", z.Any("execution_optimistic", v))
	}

	return false, errors.New("metadata has missing execution_optimistic value")
}

// getDependentRootFromMetadata returns dependent_root value from metadata,
// or error if it is missing, has a wrong type or a malformed value.
// Default value `0x00..` is returned in case metadata is nil.
func getDependentRootFromMetadata(metadata map[string]any) (root, error) {
	if metadata == nil {
		return root{}, nil
	}

	if v, has := metadata["dependent_root"]; has {
		if r, ok := v.(eth2p0.Root); ok {
			return root(r), nil
		}

		return root{}, errors.New("metadata has wrong dependent_root type", z.Any("dependent_root", v))
	}

	return root{}, errors.New("metadata has missing dependent_root value")
}
