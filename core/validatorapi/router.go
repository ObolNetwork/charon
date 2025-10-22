// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2fulu "github.com/attestantio/go-eth2-client/api/v1/fulu"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/gorilla/mux"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

//go:generate mockery --name Handler --output=mocks --outpkg=mocks --case=underscore

type contentType string

const (
	contentTypeJSON               contentType = "application/json"
	contentTypeSSZ                contentType = "application/octet-stream"
	versionHeader                             = "Eth-Consensus-Version"
	executionPayloadBlindedHeader             = "Eth-Execution-Payload-Blinded"
	executionPayloadValueHeader               = "Eth-Execution-Payload-Value"
	consensusBlockValueHeader                 = "Eth-Consensus-Block-Value"
	defaultRequestTimeout                     = 10 * time.Second
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
	eth2client.BeaconCommitteeSelectionsProvider
	eth2client.BlindedProposalSubmitter
	eth2client.NodeVersionProvider
	eth2client.ProposerDutiesProvider
	eth2client.SyncCommitteeContributionProvider
	eth2client.SyncCommitteeContributionsSubmitter
	eth2client.SyncCommitteeDutiesProvider
	eth2client.SyncCommitteeMessagesSubmitter
	eth2client.SyncCommitteeSelectionsProvider
	eth2client.ValidatorsProvider
	eth2client.ValidatorRegistrationsSubmitter
	eth2client.VoluntaryExitSubmitter
	// Above sorted alphabetically.
}

// NewRouter returns a new validator http server router. The http router
// translates http requests related to the distributed validator to the Handler.
// All other requests are reverse-proxied to the beacon-node address.
func NewRouter(ctx context.Context, h Handler, eth2Cl eth2wrap.Client, builderEnabled bool) (*mux.Router, error) {
	// Register subset of distributed validator related endpoints.
	endpoints := []struct {
		Name      string
		Path      string
		Handler   handlerFunc
		Methods   []string
		Encodings []contentType
	}{
		{
			Name:      "attester_duties",
			Path:      "/eth/v1/validator/duties/attester/{epoch}",
			Handler:   attesterDuties(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "proposer_duties",
			Path:      "/eth/v1/validator/duties/proposer/{epoch}",
			Handler:   proposerDuties(h),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "sync_committee_duties",
			Path:      "/eth/v1/validator/duties/sync/{epoch}",
			Handler:   syncCommitteeDuties(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "attestation_data",
			Path:      "/eth/v1/validator/attestation_data",
			Handler:   attestationData(h),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_attestations",
			Path:      "/eth/v1/beacon/pool/attestations",
			Handler:   respond404("/eth/v1/beacon/pool/attestations"),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_attestations_v2",
			Path:      "/eth/v2/beacon/pool/attestations",
			Handler:   submitAttestations(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "get_validators",
			Path:      "/eth/v1/beacon/states/{state_id}/validators",
			Handler:   getValidators(h),
			Methods:   []string{http.MethodPost, http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "get_validator",
			Path:      "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
			Handler:   getValidator(h),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "propose_block",
			Path:      "/eth/v2/validator/blocks/{slot}",
			Handler:   respond404("/eth/v2/validator/blocks/{slot}"),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "propose_blinded_block",
			Path:      "/eth/v1/validator/blinded_blocks/{slot}",
			Handler:   respond404("/eth/v1/validator/blinded_blocks/{slot}"),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "propose_block_v3",
			Path:      "/eth/v3/validator/blocks/{slot}",
			Handler:   proposeBlockV3(h, builderEnabled),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "submit_proposal_v1",
			Path:      "/eth/v1/beacon/blocks",
			Handler:   submitProposal(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "submit_proposal_v2",
			Path:      "/eth/v2/beacon/blocks",
			Handler:   submitProposal(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "submit_blinded_block_v1",
			Path:      "/eth/v1/beacon/blinded_blocks",
			Handler:   submitBlindedBlock(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "submit_blinded_block_v2",
			Path:      "/eth/v2/beacon/blinded_blocks",
			Handler:   submitBlindedBlock(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "submit_validator_registration",
			Path:      "/eth/v1/validator/register_validator",
			Handler:   submitValidatorRegistrations(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON, contentTypeSSZ},
		},
		{
			Name:      "submit_voluntary_exit",
			Path:      "/eth/v1/beacon/pool/voluntary_exits",
			Handler:   submitExit(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "teku_proposer_config",
			Path:      "/teku_proposer_config",
			Handler:   respond404("/teku_proposer_config"),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "proposer_config",
			Path:      "/proposer_config",
			Handler:   respond404("/proposer_config"),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "aggregate_beacon_committee_selections",
			Path:      "/eth/v1/validator/beacon_committee_selections",
			Handler:   beaconCommitteeSelections(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "aggregate_attestation",
			Path:      "/eth/v1/validator/aggregate_attestation",
			Handler:   respond404("/eth/v1/validator/aggregate_attestation"),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "aggregate_attestation_v2",
			Path:      "/eth/v2/validator/aggregate_attestation",
			Handler:   aggregateAttestation(h),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_aggregate_and_proofs",
			Path:      "/eth/v1/validator/aggregate_and_proofs",
			Handler:   respond404("/eth/v1/validator/aggregate_and_proofs"),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_aggregate_and_proofs_v2",
			Path:      "/eth/v2/validator/aggregate_and_proofs",
			Handler:   submitAggregateAttestations(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_sync_committee_messages",
			Path:      "/eth/v1/beacon/pool/sync_committees",
			Handler:   submitSyncCommitteeMessages(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "sync_committee_contribution",
			Path:      "/eth/v1/validator/sync_committee_contribution",
			Handler:   syncCommitteeContribution(h),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_contribution_and_proofs",
			Path:      "/eth/v1/validator/contribution_and_proofs",
			Handler:   submitContributionAndProofs(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "submit_proposal_preparations",
			Path:      "/eth/v1/validator/prepare_beacon_proposer",
			Handler:   submitProposalPreparations(),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "aggregate_sync_committee_selections",
			Path:      "/eth/v1/validator/sync_committee_selections",
			Handler:   syncCommitteeSelections(h),
			Methods:   []string{http.MethodPost},
			Encodings: []contentType{contentTypeJSON},
		},
		{
			Name:      "node_version",
			Path:      "/eth/v1/node/version",
			Handler:   nodeVersion(h),
			Methods:   []string{http.MethodGet},
			Encodings: []contentType{contentTypeJSON},
		},
	}

	r := mux.NewRouter()
	for _, e := range endpoints {
		handler := r.Handle(e.Path, wrap(e.Name, e.Handler, e.Encodings))
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
type handlerFunc func(ctx context.Context, params map[string]string, header http.Header, query url.Values, typ contentType, body []byte) (res any, headers http.Header, err error)

// wrap adapts the handler function returning a standard http handler.
// It does tracing, metrics and response and error writing.
func wrap(endpoint string, handler handlerFunc, encodings []contentType) http.Handler {
	wrap := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = log.WithTopic(ctx, "vapi")
		ctx = log.WithCtx(ctx, z.Str("vapi_endpoint", endpoint))
		ctx = withCtxDuration(ctx)
		ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)

		defer func() {
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				observeAPILatency(endpoint)()
			}

			cancel()
		}()

		var typ contentType

		contentHeader := r.Header.Get("Content-Type")
		if contentHeader == "" || strings.Contains(contentHeader, string(contentTypeJSON)) {
			typ = contentTypeJSON
		} else if strings.Contains(contentHeader, string(contentTypeSSZ)) {
			typ = contentTypeSSZ
		} else {
			writeError(ctx, w, endpoint, apiError{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    "unsupported media type " + contentHeader,
			})

			return
		}

		vcContentType.WithLabelValues(endpoint, string(typ)).Inc()

		if !slices.Contains(encodings, typ) {
			writeError(ctx, w, endpoint, apiError{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    "Cannot read the supplied content type.",
			})

			return
		}

		userAgent := r.Header.Get("User-Agent")
		if userAgent != "" {
			vcUserAgentGauge.WithLabelValues(userAgent).Set(1)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(ctx, w, endpoint, err)
			return
		}

		res, headers, err := handler(ctx, mux.Vars(r), r.Header, r.URL.Query(), typ, body)
		if err != nil {
			writeError(ctx, w, endpoint, err)
			return
		}

		writeResponse(ctx, w, endpoint, res, headers)
	}

	return http.HandlerFunc(wrap)
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
		log.Error(ctx, "Failed to write API response to client. Connection may have been closed", err)
	}
}

// getValidators returns a handler function for the get validators by pubkey or index endpoint.
func getValidators(p eth2client.ValidatorsProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ http.Header, query url.Values, _ contentType, body []byte) (any, http.Header, error) {
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
	return func(ctx context.Context, params map[string]string, _ http.Header, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
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
	return func(ctx context.Context, _ map[string]string, _ http.Header, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
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

// submitAttestations returns a handler function for the attestation submitter v2 endpoint.
func submitAttestations(p eth2client.AttestationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, header http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		versionedAtts := []*eth2spec.VersionedAttestation{}

		var version eth2spec.DataVersion

		err := version.UnmarshalJSON([]byte("\"" + header.Get(versionHeader) + "\""))
		if err != nil {
			return nil, nil, errors.New("missing consensus version header", z.Hex("body", body))
		}

		switch version {
		case eth2spec.DataVersionPhase0:
			p0Atts := new([]eth2p0.Attestation)

			err = unmarshal(typ, body, p0Atts)
			if err != nil {
				return nil, nil, errors.New("invalid phase0 attestations", z.Hex("body", body))
			}

			for _, p0Att := range *p0Atts {
				versionedAtt := eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionPhase0,
					Phase0:  &p0Att,
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		case eth2spec.DataVersionAltair:
			p0Atts := new([]eth2p0.Attestation)

			err = unmarshal(typ, body, p0Atts)
			if err != nil {
				return nil, nil, errors.New("invalid altair attestations", z.Hex("body", body))
			}

			for _, p0Att := range *p0Atts {
				versionedAtt := eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionAltair,
					Altair:  &p0Att,
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		case eth2spec.DataVersionBellatrix:
			p0Atts := new([]eth2p0.Attestation)

			err = unmarshal(typ, body, p0Atts)
			if err != nil {
				return nil, nil, errors.New("invalid bellatrix attestations", z.Hex("body", body))
			}

			for _, p0Att := range *p0Atts {
				versionedAtt := eth2spec.VersionedAttestation{
					Version:   eth2spec.DataVersionBellatrix,
					Bellatrix: &p0Att,
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		case eth2spec.DataVersionCapella:
			p0Atts := new([]eth2p0.Attestation)

			err = unmarshal(typ, body, p0Atts)
			if err != nil {
				return nil, nil, errors.New("invalid capella attestations", z.Hex("body", body))
			}

			for _, p0Att := range *p0Atts {
				versionedAtt := eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionCapella,
					Capella: &p0Att,
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		case eth2spec.DataVersionDeneb:
			p0Atts := new([]eth2p0.Attestation)

			err = unmarshal(typ, body, p0Atts)
			if err != nil {
				return nil, nil, errors.New("invalid deneb attestations", z.Hex("body", body))
			}

			for _, p0Att := range *p0Atts {
				versionedAtt := eth2spec.VersionedAttestation{
					Version: eth2spec.DataVersionDeneb,
					Deneb:   &p0Att,
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		case eth2spec.DataVersionElectra:
			electraAtts := new([]electra.SingleAttestation)

			err = unmarshal(typ, body, electraAtts)
			if err != nil {
				return nil, nil, errors.New("invalid electra attestations", z.Hex("body", body))
			}

			for _, electraAtt := range *electraAtts {
				commBits := bitfield.NewBitvector64()
				commBits.SetBitAt(uint64(electraAtt.CommitteeIndex), true)
				versionedAtt := eth2spec.VersionedAttestation{
					Version:        eth2spec.DataVersionElectra,
					ValidatorIndex: &electraAtt.AttesterIndex,
					Electra: &electra.Attestation{
						// the VersionedAttestation object will be converted back to SingleAttestation object inside go-eth2-client's SubmitAttestations,
						// SingleAttestation object disregards AggregationBits, so this empty Bitlist is safe
						AggregationBits: bitfield.NewBitlist(0),
						Data:            electraAtt.Data,
						Signature:       electraAtt.Signature,
						CommitteeBits:   commBits,
					},
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		case eth2spec.DataVersionFulu:
			electraAtts := new([]electra.SingleAttestation)

			err = unmarshal(typ, body, electraAtts)
			if err != nil {
				return nil, nil, errors.New("invalid fulu attestations", z.Hex("body", body))
			}

			for _, electraAtt := range *electraAtts {
				commBits := bitfield.NewBitvector64()
				commBits.SetBitAt(uint64(electraAtt.CommitteeIndex), true)
				versionedAtt := eth2spec.VersionedAttestation{
					Version:        eth2spec.DataVersionFulu,
					ValidatorIndex: &electraAtt.AttesterIndex,
					Fulu: &electra.Attestation{
						// the VersionedAttestation object will be converted back to SingleAttestation object inside go-eth2-client's SubmitAttestations,
						// SingleAttestation object disregards AggregationBits, so this empty Bitlist is safe
						AggregationBits: bitfield.NewBitlist(0),
						Data:            electraAtt.Data,
						Signature:       electraAtt.Signature,
						CommitteeBits:   commBits,
					},
				}
				versionedAtts = append(versionedAtts, &versionedAtt)
			}
		default:
			return nil, nil, errors.New("invalid attestations version", z.Hex("body", body), z.Str("version", version.String()))
		}

		return nil, nil, p.SubmitAttestations(ctx, &eth2api.SubmitAttestationsOpts{Attestations: versionedAtts})
	}
}

// proposerDuties returns a handler function for the proposer duty endpoint.
func proposerDuties(p eth2client.ProposerDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ http.Header, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
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
	return func(ctx context.Context, params map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
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
	return func(ctx context.Context, params map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
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
	return func(ctx context.Context, _ map[string]string, _ http.Header, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
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
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var contributionAndProofs []*altair.SignedContributionAndProof

		err := unmarshal(typ, body, &contributionAndProofs)
		if err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed contribution and proofs")
		}

		return nil, nil, s.SubmitSyncCommitteeContributions(ctx, contributionAndProofs)
	}
}

// respond404 returns a handler function always returning http.StatusNotFound
func respond404(endpoint string) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		log.Warn(ctx, "This endpoint shall not be hit", nil, z.Str("endpoint", endpoint))

		return nil, nil, apiError{
			StatusCode: http.StatusNotFound,
			Message:    "NotFound",
		}
	}
}

// proposeBlockV3 returns a handler function returning an unsigned BeaconBlock or BlindedBeaconBlock.
func proposeBlockV3(p eth2client.ProposalProvider, builderEnabled bool) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ http.Header, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		slot, randao, graffiti, err := getProposeBlockParams(params, query)
		if err != nil {
			return nil, nil, err
		}

		var bbf uint64
		if builderEnabled {
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
	case eth2spec.DataVersionElectra:
		version = eth2spec.DataVersionElectra.String()

		if proposal.Blinded {
			if proposal.ElectraBlinded == nil {
				return nil, errors.New("no electra blinded block")
			}

			blockData = proposal.ElectraBlinded
		} else {
			if proposal.Electra == nil {
				return nil, errors.New("no electra block")
			}

			blockData = proposal.Electra
		}
	case eth2spec.DataVersionFulu:
		version = eth2spec.DataVersionFulu.String()

		if proposal.Blinded {
			if proposal.FuluBlinded == nil {
				return nil, errors.New("no fulu blinded block")
			}

			blockData = proposal.FuluBlinded
		} else {
			if proposal.Fulu == nil {
				return nil, errors.New("no fulu block")
			}

			blockData = proposal.Fulu
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
	return func(ctx context.Context, _ map[string]string, header http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var version eth2spec.DataVersion

		err := version.UnmarshalJSON([]byte("\"" + header.Get(versionHeader) + "\""))
		if err != nil {
			return nil, nil, errors.New("missing consensus version header", z.Hex("body", body))
		}

		switch version {
		case eth2spec.DataVersionPhase0:
			phase0Block := new(eth2p0.SignedBeaconBlock)

			err = unmarshal(typ, body, phase0Block)
			if err != nil {
				return nil, nil, errors.New("invalid submitted phase0 block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionPhase0,
				Phase0:  phase0Block,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionAltair:
			altairBlock := new(altair.SignedBeaconBlock)

			err = unmarshal(typ, body, altairBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted altair block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionAltair,
				Altair:  altairBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionBellatrix:
			bellatrixBlock := new(bellatrix.SignedBeaconBlock)

			err = unmarshal(typ, body, bellatrixBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted bellatrix block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Bellatrix: bellatrixBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionCapella:
			capellaBlock := new(capella.SignedBeaconBlock)

			err = unmarshal(typ, body, capellaBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted capella block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: capellaBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionDeneb:
			denebBlock := new(eth2deneb.SignedBlockContents)

			err = unmarshal(typ, body, denebBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted deneb block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   denebBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionElectra:
			electraBlock := new(eth2electra.SignedBlockContents)

			err = unmarshal(typ, body, electraBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted electra block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionElectra,
				Electra: electraBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionFulu:
			fuluBlock := new(eth2fulu.SignedBlockContents)

			err = unmarshal(typ, body, fuluBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted fulu block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedProposal{
				Version: eth2spec.DataVersionFulu,
				Fulu:    fuluBlock,
			}

			return nil, nil, p.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{
				Proposal: block,
			})

		default:
			return nil, nil, errors.New("invalid submitted block", z.Hex("body", body))
		}
	}
}

func submitBlindedBlock(p eth2client.BlindedProposalSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, header http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var version eth2spec.DataVersion

		err := version.UnmarshalJSON([]byte("\"" + header.Get(versionHeader) + "\""))
		if err != nil {
			return nil, nil, errors.New("missing consensus version header", z.Hex("body", body))
		}

		switch version {
		case eth2spec.DataVersionBellatrix:
			bellatrixBlock := new(eth2bellatrix.SignedBlindedBeaconBlock)

			err = unmarshal(typ, body, bellatrixBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted bellatrix blinded block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedBlindedProposal{
				Version:   eth2spec.DataVersionBellatrix,
				Bellatrix: bellatrixBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionCapella:
			capellaBlock := new(eth2capella.SignedBlindedBeaconBlock)

			err = unmarshal(typ, body, capellaBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted capella blinded block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: capellaBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionDeneb:
			denebBlock := new(eth2deneb.SignedBlindedBeaconBlock)

			err = unmarshal(typ, body, denebBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted deneb blinded block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionDeneb,
				Deneb:   denebBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionElectra:
			electraBlock := new(eth2electra.SignedBlindedBeaconBlock)

			err := unmarshal(typ, body, electraBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted electra blinded block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionElectra,
				Electra: electraBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})

		case eth2spec.DataVersionFulu:
			fuluBlock := new(eth2electra.SignedBlindedBeaconBlock) // Fulu blinded blocks have the same structure as electra blinded blocks.

			err := unmarshal(typ, body, fuluBlock)
			if err != nil {
				return nil, nil, errors.New("invalid submitted fulu blinded block", z.Hex("body", body))
			}

			block := &eth2api.VersionedSignedBlindedProposal{
				Version: eth2spec.DataVersionFulu,
				Fulu:    fuluBlock,
			}

			return nil, nil, p.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
				Proposal: block,
			})

		default:
			return nil, nil, errors.New("invalid block")
		}
	}
}

// submitValidatorRegistrations returns a handler function for the validator (builder) registration submitter endpoint.
func submitValidatorRegistrations(r eth2client.ValidatorRegistrationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		var unversioned signedValidatorRegistrations
		if err := unmarshal(typ, body, &unversioned); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed builder registration")
		}

		var versioned []*eth2api.VersionedSignedValidatorRegistration
		for _, registration := range unversioned.Registrations {
			versioned = append(versioned, &eth2api.VersionedSignedValidatorRegistration{
				Version: eth2spec.BuilderVersionV1,
				V1:      registration,
			})
		}

		return nil, nil, r.SubmitValidatorRegistrations(ctx, versioned)
	}
}

// beaconCommitteeSelections receives partial beacon committee selections and returns aggregated selections.
func beaconCommitteeSelections(a eth2client.BeaconCommitteeSelectionsProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (res any, headers http.Header, err error) {
		var selections []*eth2v1.BeaconCommitteeSelection
		if err := unmarshal(typ, body, &selections); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal beacon committee selections")
		}

		eth2Resp, err := a.BeaconCommitteeSelections(ctx, &eth2api.BeaconCommitteeSelectionsOpts{Selections: selections})
		if err != nil {
			return nil, nil, errors.Wrap(err, "beacon committee selections")
		}

		return beaconCommitteeSelectionsJSON{Data: eth2Resp.Data}, nil, nil
	}
}

// syncCommitteeSelections receives partial sync committee selections and returns aggregated selections.
func syncCommitteeSelections(a eth2client.SyncCommitteeSelectionsProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (res any, headers http.Header, err error) {
		var selections []*eth2v1.SyncCommitteeSelection
		if err := unmarshal(typ, body, &selections); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal sync committee selections")
		}

		eth2Resp, err := a.SyncCommitteeSelections(ctx, &eth2api.SyncCommitteeSelectionsOpts{Selections: selections})
		if err != nil {
			return nil, nil, errors.Wrap(err, "sync committee selections")
		}

		return syncCommitteeSelectionsJSON{Data: eth2Resp.Data}, nil, nil
	}
}

// submitExit returns a handler function for the exit submitter endpoint.
func submitExit(p eth2client.VoluntaryExitSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		exit := new(eth2p0.SignedVoluntaryExit)
		if err := unmarshal(typ, body, exit); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal signed voluntary exit")
		}

		return nil, nil, p.SubmitVoluntaryExit(ctx, exit)
	}
}

func aggregateAttestation(p eth2client.AggregateAttestationProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, query url.Values, _ contentType, _ []byte) (any, http.Header, error) {
		slot, err := uintQuery(query, "slot")
		if err != nil {
			return nil, nil, err
		}

		var attDataRoot eth2p0.Root
		if err := hexQueryFixed(query, "attestation_data_root", attDataRoot[:]); err != nil {
			return nil, nil, err
		}

		committeeIndex, err := uintQuery(query, "committee_index")
		if err != nil {
			return nil, nil, err
		}

		opts := &eth2api.AggregateAttestationOpts{
			Slot:                eth2p0.Slot(slot),
			AttestationDataRoot: attDataRoot,
			CommitteeIndex:      eth2p0.CommitteeIndex(committeeIndex),
		}

		eth2Resp, err := p.AggregateAttestation(ctx, opts)
		if err != nil {
			return nil, nil, err
		}

		data := eth2Resp.Data

		resHeaders := make(http.Header)
		resHeaders.Add(versionHeader, data.Version.String())

		res, err := createAggregateAttestation(data)
		if err != nil {
			return nil, nil, err
		}

		return res, resHeaders, nil
	}
}

// createAggregateAttestation constructs aggregateAttestationV2Response object for given block.
func createAggregateAttestation(aggAtt *eth2spec.VersionedAttestation) (*aggregateAttestationV2Response, error) {
	res := aggregateAttestationV2Response{Version: aggAtt.Version.String()}

	switch aggAtt.Version {
	case eth2spec.DataVersionPhase0:
		if aggAtt.Phase0 == nil {
			return nil, errors.New("no phase0 attestation")
		}

		res.Data = aggAtt.Phase0
	case eth2spec.DataVersionAltair:
		if aggAtt.Altair == nil {
			return nil, errors.New("no altair attestation")
		}

		res.Data = aggAtt.Altair
	case eth2spec.DataVersionBellatrix:
		if aggAtt.Bellatrix == nil {
			return nil, errors.New("no bellatrix attestation")
		}

		res.Data = aggAtt.Bellatrix
	case eth2spec.DataVersionCapella:
		if aggAtt.Capella == nil {
			return nil, errors.New("no capella attestation")
		}

		res.Data = aggAtt.Capella
	case eth2spec.DataVersionDeneb:
		if aggAtt.Deneb == nil {
			return nil, errors.New("no deneb attestation")
		}

		res.Data = aggAtt.Deneb
	case eth2spec.DataVersionElectra:
		if aggAtt.Electra == nil {
			return nil, errors.New("no electra attestation")
		}

		res.Data = aggAtt.Electra
	case eth2spec.DataVersionFulu:
		if aggAtt.Fulu == nil {
			return nil, errors.New("no fulu attestation")
		}

		res.Data = aggAtt.Fulu
	default:
		return nil, errors.New("invalid attestation")
	}

	return &res, nil
}

func submitAggregateAttestations(s eth2client.AggregateAttestationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, header http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
		aggs := []*eth2spec.VersionedSignedAggregateAndProof{}

		var version eth2spec.DataVersion

		err := version.UnmarshalJSON([]byte("\"" + header.Get(versionHeader) + "\""))
		if err != nil {
			return nil, nil, errors.New("missing consensus version header", z.Hex("body", body))
		}

		switch version {
		case eth2spec.DataVersionPhase0:
			var p0Aggs []*eth2p0.SignedAggregateAndProof

			err := unmarshal(typ, body, &p0Aggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal phase0 signed aggregate and proofs", z.Hex("body", body))
			}

			for _, p0Agg := range p0Aggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionPhase0,
					Phase0:  p0Agg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		case eth2spec.DataVersionAltair:
			var p0Aggs []*eth2p0.SignedAggregateAndProof

			err := unmarshal(typ, body, &p0Aggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal altair signed aggregate and proofs", z.Hex("body", body))
			}

			for _, p0Agg := range p0Aggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionAltair,
					Altair:  p0Agg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		case eth2spec.DataVersionBellatrix:
			var p0Aggs []*eth2p0.SignedAggregateAndProof

			err := unmarshal(typ, body, &p0Aggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal bellatrix signed aggregate and proofs", z.Hex("body", body))
			}

			for _, p0Agg := range p0Aggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version:   eth2spec.DataVersionBellatrix,
					Bellatrix: p0Agg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		case eth2spec.DataVersionCapella:
			var p0Aggs []*eth2p0.SignedAggregateAndProof

			err := unmarshal(typ, body, &p0Aggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal capella signed aggregate and proofs", z.Hex("body", body))
			}

			for _, p0Agg := range p0Aggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionCapella,
					Capella: p0Agg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		case eth2spec.DataVersionDeneb:
			var p0Aggs []*eth2p0.SignedAggregateAndProof

			err := unmarshal(typ, body, &p0Aggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal deneb signed aggregate and proofs", z.Hex("body", body))
			}

			for _, p0Agg := range p0Aggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionDeneb,
					Deneb:   p0Agg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		case eth2spec.DataVersionElectra:
			var electraAggs []*electra.SignedAggregateAndProof

			err := unmarshal(typ, body, &electraAggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal electra signed aggregate and proofs", z.Hex("body", body))
			}

			for _, electraAgg := range electraAggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionElectra,
					Electra: electraAgg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		case eth2spec.DataVersionFulu:
			var electraAggs []*electra.SignedAggregateAndProof

			err := unmarshal(typ, body, &electraAggs)
			if err != nil {
				return nil, nil, errors.Wrap(err, "unmarshal fulu signed aggregate and proofs", z.Hex("body", body))
			}

			for _, electraAgg := range electraAggs {
				versionedAgg := eth2spec.VersionedSignedAggregateAndProof{
					Version: eth2spec.DataVersionFulu,
					Fulu:    electraAgg,
				}
				aggs = append(aggs, &versionedAgg)
			}
		default:
			return nil, nil, errors.Wrap(err, "unknown signed aggregate and proofs version", z.Hex("body", body), z.Str("version", version.String()))
		}

		return nil, nil, s.SubmitAggregateAttestations(ctx, &eth2api.SubmitAggregateAttestationsOpts{
			SignedAggregateAndProofs: aggs,
		})
	}
}

func submitSyncCommitteeMessages(s eth2client.SyncCommitteeMessagesSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, typ contentType, body []byte) (any, http.Header, error) {
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
	return func(context.Context, map[string]string, http.Header, url.Values, contentType, []byte) (any, http.Header, error) {
		return nil, nil, nil
	}
}

// nodeVersion returns the version of the node.
func nodeVersion(p eth2client.NodeVersionProvider) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ http.Header, _ url.Values, _ contentType, _ []byte) (any, http.Header, error) {
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

// mergeContext returns a new context that is derived from mainCtx, but will be cancelled
// as soon as either mainCtx or reqCtx is cancelled.
func mergeContext(mainCtx, reqCtx context.Context) context.Context {
	mergedCtx, cancel := context.WithCancel(mainCtx)
	go func() {
		select {
		case <-mainCtx.Done():
			cancel()
		case <-reqCtx.Done():
			cancel()
		}
		cancel()
	}()

	return mergedCtx
}

func proxyHandler(ctx context.Context, eth2Cl eth2wrap.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(mergeContext(ctx, r.Context()))
		ctx = log.WithTopic(ctx, "vapi")
		ctx = log.WithCtx(ctx, z.Str("vapi_proxy_method", r.Method), z.Str("vapi_proxy_path", r.URL.Path))
		ctx = withCtxDuration(ctx)
		ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)

		defer func() {
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				observeProxyAPILatency(r.URL.Path)()
				observeAPILatency("proxy")()
			}

			cancel()
		}()

		// Send request to eth2wrap logic
		// If using multi, will clone the response and proxy to each available BN
		res, err := eth2Cl.ProxyRequest(ctx, r)
		if err != nil {
			writeError(ctx, w, r.URL.Path, err)
			return
		}

		// Copy headers from upstream (already filtered by ProxyRequest in httpwrap)
		maps.Copy(w.Header(), res.Header)

		// If trailers expected, declare them before writing headers.
		if len(res.Trailer) > 0 {
			for k := range res.Trailer {
				w.Header().Add("Trailer", k)
			}
		}

		if res.StatusCode/100 != 2 {
			incAPIErrors("proxy", res.StatusCode)
		}

		w.WriteHeader(res.StatusCode)

		// For HEAD, do not write a body.
		if r.Method == http.MethodHead {
			if res.Body != nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}
			return
		}

		if res.Body != nil {
			_, err = io.Copy(w, res.Body)
			if err != nil {
				log.Error(ctx, "Failed writing api response", err)
			}
			_ = res.Body.Close()
		}

		// Set trailer values after the body if present.
		if len(res.Trailer) > 0 {
			for k, vv := range res.Trailer {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
		}
	}
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

	switch typ {
	case contentTypeJSON:
		err := json.Unmarshal(body, v)
		if err != nil {
			return apiError{
				StatusCode: http.StatusBadRequest,
				Message:    "failed parsing json request body",
				Err:        err,
			}
		}

		return nil
	case contentTypeSSZ:
		unmarshaller, ok := v.(ssz.Unmarshaler)
		if !ok {
			return apiError{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    "internal type doesn't support ssz unmarshalling",
				Err:        errors.New("internal type doesn't support ssz unmarshalling"),
			}
		}

		err := unmarshaller.UnmarshalSSZ(body)
		if err != nil {
			return apiError{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    "failed parsing ssz request body",
				Err:        err,
			}
		}

		return nil
	default:
		return errors.New("bug: invalid content type")
	}
}

// uintParam returns a uint path parameter.
func uintParam(params map[string]string, name string) (uint64, error) {
	param, ok := params[name]
	if !ok {
		return 0, apiError{
			StatusCode: http.StatusBadRequest,
			Message:    "missing path parameter " + name,
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
			Message:    "missing query parameter " + name,
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
			Message:    "missing 0x-hex query parameter " + name,
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
