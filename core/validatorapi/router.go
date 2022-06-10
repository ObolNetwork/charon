// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

// Package validatorapi defines validator facing API that serves the subset of
// endpoints related to distributed validation and reverse-proxies the rest to the
// upstream beacon client.
package validatorapi

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Handler defines the request handler providing the business logic
// for the validator API router.
type Handler interface {
	eth2client.AttestationDataProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.BeaconBlockProposalProvider
	eth2client.BeaconBlockSubmitter
	eth2client.ProposerDutiesProvider
	eth2client.ValidatorsProvider
	eth2client.VoluntaryExitSubmitter
	// Above sorted alphabetically.
}

// NewRouter returns a new validator http server router. The http router
// translates http requests related to the distributed validator to the validatorapi.Handler.
// All other requests are reserve-proxied to the beacon-node address.
func NewRouter(h Handler, beaconNodeAddr string) (*mux.Router, error) {
	// Register subset of distributed validator related endpoints
	endpoints := []struct {
		Name    string
		Path    string
		Handler handlerFunc
	}{
		{
			Name:    "attester_duties",
			Path:    "/eth/v1/validator/duties/attester/{epoch}",
			Handler: attesterDuties(h),
		},
		{
			Name:    "proposer_duties",
			Path:    "/eth/v1/validator/duties/proposer/{epoch}",
			Handler: proposerDuties(h),
		},
		{
			Name:    "attestation_data",
			Path:    "/eth/v1/validator/attestation_data",
			Handler: attestationData(h),
		},
		{
			Name:    "submit_attestations",
			Path:    "/eth/v1/beacon/pool/attestations",
			Handler: submitAttestations(h),
		},
		{
			Name:    "get_validators",
			Path:    "/eth/v1/beacon/states/{state_id}/validators",
			Handler: getValidators(h),
		},
		{
			Name:    "get_validator",
			Path:    "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
			Handler: getValidator(h),
		},
		{
			Name:    "propose_block",
			Path:    "/eth/v2/validator/blocks/{slot}",
			Handler: proposeBlock(h),
		},
		{
			Name:    "submit_block",
			Path:    "/eth/v1/beacon/blocks",
			Handler: submitBlock(h),
		},
		{
			Name:    "submit_voluntary_exit",
			Path:    "/eth/v1/beacon/pool/voluntary_exits",
			Handler: submitExit(h),
		},
		// TODO(corver): Add more endpoints
	}

	r := mux.NewRouter()
	for _, e := range endpoints {
		r.Handle(e.Path, wrap(e.Name, e.Handler))
	}

	// Everything else is proxied
	proxy, err := proxyHandler(beaconNodeAddr)
	if err != nil {
		return nil, err
	}

	r.PathPrefix("/").Handler(proxy)

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
type handlerFunc func(ctx context.Context, params map[string]string, query url.Values, body []byte) (res interface{}, err error)

// wrap adapts the handler function returning a standard http handler.
// It does tracing, metrics and response and error writing.
func wrap(endpoint string, handler handlerFunc) http.Handler {
	wrap := func(w http.ResponseWriter, r *http.Request) {
		defer observeAPILatency(endpoint)()

		ctx := r.Context()
		ctx = log.WithTopic(ctx, "vapi")
		ctx = log.WithCtx(ctx, z.Str("vapi_endpoint", endpoint))
		ctx = withCtxDuration(ctx)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(ctx, w, endpoint, err)
			return
		}

		res, err := handler(ctx, mux.Vars(r), r.URL.Query(), body)
		if err != nil {
			writeError(ctx, w, endpoint, err)
			return
		}

		writeResponse(ctx, w, endpoint, res)
	}

	return wrapTrace(endpoint, wrap)
}

// wrapTrace wraps the passed handler in a OpenTelemetry tracing span.
func wrapTrace(endpoint string, handler http.HandlerFunc) http.Handler {
	return otelhttp.NewHandler(handler, "core/validatorapi."+endpoint)
}

// getValidator returns a handler function for the get validators by pubkey or index endpoint.
func getValidators(p eth2client.ValidatorsProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, body []byte) (interface{}, error) {
		stateID := params["state_id"]

		var resp []v1Validator
		for _, id := range getValidatorIDs(query) {
			val, ok, err := getValidatorByID(ctx, p, stateID, id)
			if err != nil {
				return nil, err
			} else if ok {
				resp = append(resp, v1Validator(*val))
			}
		}

		if len(resp) == 0 {
			return nil, apiError{
				StatusCode: http.StatusNotFound,
				Message:    "NotFound",
			}
		}

		return validatorsResponse{Data: resp}, nil
	}
}

// getValidator returns a handler function for the get validators by pubkey or index endpoint.
func getValidator(p eth2client.ValidatorsProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, body []byte) (interface{}, error) {
		stateID := params["state_id"]
		id := params["validator_id"]

		val, ok, err := getValidatorByID(ctx, p, stateID, id)
		if err != nil {
			return nil, err
		} else if !ok {
			return nil, apiError{
				StatusCode: http.StatusNotFound,
				Message:    "NotFound",
			}
		}

		return validatorResponse{Data: v1Validator(*val)}, nil
	}
}

// attestationData returns a handler function for the attestation data endpoint.
func attestationData(p eth2client.AttestationDataProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, body []byte) (interface{}, error) {
		slot, err := uintQuery(query, "slot")
		if err != nil {
			return nil, err
		}

		commIdx, err := uintQuery(query, "committee_index")
		if err != nil {
			return nil, err
		}

		data, err := p.AttestationData(ctx, eth2p0.Slot(slot), eth2p0.CommitteeIndex(commIdx))
		if err != nil {
			return nil, err
		}

		return struct {
			Data *eth2p0.AttestationData `json:"data"`
		}{
			Data: data,
		}, nil
	}
}

// submitAttestations returns a handler function for the attestation submitter endpoint.
func submitAttestations(p eth2client.AttestationsSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, body []byte) (interface{}, error) {
		var atts []*eth2p0.Attestation
		err := json.Unmarshal(body, &atts)
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal attestations")
		}

		err = p.SubmitAttestations(ctx, atts)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

// proposerDuties returns a handler function for the proposer duty endpoint.
func proposerDuties(p eth2client.ProposerDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ url.Values, body []byte) (interface{}, error) {
		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, err
		}

		// Note the ProposerDutiesProvider interface adds some sugar to the official spec.
		// ValidatorIndices aren't provided over the wire.
		data, err := p.ProposerDuties(ctx, eth2p0.Epoch(epoch), nil)
		if err != nil {
			return nil, err
		}

		if len(data) == 0 {
			data = []*eth2v1.ProposerDuty{}
		}

		return proposerDutiesResponse{
			DependentRoot: stubRoot(epoch), // TODO(corver): Fill this properly
			Data:          data,
		}, nil
	}
}

// attesterDuties returns a handler function for the attester duty endpoint.
func attesterDuties(p eth2client.AttesterDutiesProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, _ url.Values, body []byte) (interface{}, error) {
		epoch, err := uintParam(params, "epoch")
		if err != nil {
			return nil, err
		}

		var req attesterDutiesRequest
		if err := unmarshal(body, &req); err != nil {
			return nil, err
		}

		data, err := p.AttesterDuties(ctx, eth2p0.Epoch(epoch), req)
		if err != nil {
			return nil, err
		}

		if len(data) == 0 {
			data = []*eth2v1.AttesterDuty{}
		}

		return attesterDutiesResponse{
			DependentRoot: stubRoot(epoch), // TODO(corver): Fill this properly
			Data:          data,
		}, nil
	}
}

// proposeBlock receives the randao from the validator and returns the unsigned BeaconBlock.
func proposeBlock(p eth2client.BeaconBlockProposalProvider) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, body []byte) (interface{}, error) {
		slot, err := uintParam(params, "slot")
		if err != nil {
			return nil, err
		}

		var randao eth2p0.BLSSignature
		b, err := hexQuery(query, "randao_reveal")
		if err != nil {
			return nil, err
		}
		if len(b) != len(randao) {
			return nil, errors.New("input randao_reveal has wrong length")
		}
		copy(randao[:], b)

		var graffiti []byte
		if query.Has("graffiti") {
			graffiti, err = hexQuery(query, "graffiti")
			if err != nil {
				return nil, errors.Wrap(err, "hexadecimal encoding")
			}
			// TODO(leo): where should we put this constant?
			if len(graffiti) > 32 {
				return nil, errors.New("above graffiti length max of 32")
			}
		}

		block, err := p.BeaconBlockProposal(ctx, eth2p0.Slot(slot), randao, graffiti)
		if err != nil {
			return nil, err
		}

		switch block.Version {
		case spec.DataVersionPhase0:
			if block.Phase0 == nil {
				return 0, errors.New("no phase0 block")
			}

			return proposeBlockResponsePhase0{
				Version: "PHASE0",
				Data:    block.Phase0,
			}, nil
		case spec.DataVersionAltair:
			if block.Altair == nil {
				return 0, errors.New("no altair block")
			}

			return proposeBlockResponseAltair{
				Version: "ALTAIR",
				Data:    block.Altair,
			}, nil
		case spec.DataVersionBellatrix:
			if block.Bellatrix == nil {
				return 0, errors.New("no bellatrix block")
			}

			return proposeBlockResponseBellatrix{
				Version: "BELLATRIX",
				Data:    block.Bellatrix,
			}, nil
		default:
			return 0, errors.New("invalid block")
		}
	}
}

func submitBlock(p eth2client.BeaconBlockSubmitter) handlerFunc {
	return func(ctx context.Context, params map[string]string, query url.Values, body []byte) (interface{}, error) {
		bellatrixBlock := new(bellatrix.SignedBeaconBlock)
		err := bellatrixBlock.UnmarshalJSON(body)
		if err == nil {
			block := &spec.VersionedSignedBeaconBlock{
				Version:   spec.DataVersionBellatrix,
				Bellatrix: bellatrixBlock,
			}
			err = p.SubmitBeaconBlock(ctx, block)

			return nil, err
		}

		altairBlock := new(altair.SignedBeaconBlock)
		err = altairBlock.UnmarshalJSON(body)
		if err == nil {
			block := &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair:  altairBlock,
			}
			err = p.SubmitBeaconBlock(ctx, block)

			return nil, err
		}

		phase0Block := new(eth2p0.SignedBeaconBlock)
		err = phase0Block.UnmarshalJSON(body)
		if err == nil {
			block := &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0:  phase0Block,
			}
			err = p.SubmitBeaconBlock(ctx, block)

			return nil, err
		}

		return nil, errors.New("invalid block")
	}
}

// submitExit returns a handler function for the exit submitter endpoint.
func submitExit(p eth2client.VoluntaryExitSubmitter) handlerFunc {
	return func(ctx context.Context, _ map[string]string, _ url.Values, body []byte) (interface{}, error) {
		exit := new(eth2p0.SignedVoluntaryExit)
		if err := exit.UnmarshalJSON(body); err != nil {
			return nil, errors.Wrap(err, "unmarshal signed voluntary exit")
		}

		return nil, p.SubmitVoluntaryExit(ctx, exit)
	}
}

// proxyHandler returns a reverse proxy handler.
func proxyHandler(target string) (http.HandlerFunc, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, errors.Wrap(err, "invalid proxy target address")
	}

	// TODO(corver): Add support for multiple upstream targets via some form of load balancing.
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

	return func(w http.ResponseWriter, r *http.Request) {
		defer observeAPILatency("proxy")()
		proxy.ServeHTTP(proxyResponseWriter{w.(writeFlusher)}, r)
	}, nil
}

// writeResponse writes the 200 OK response and json response body.
func writeResponse(ctx context.Context, w http.ResponseWriter, endpoint string, response interface{}) {
	w.WriteHeader(http.StatusOK)

	if response == nil {
		return
	}

	b, err := json.Marshal(response)
	if err != nil {
		writeError(ctx, w, endpoint, errors.Wrap(err, "marshal response body"))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if _, err = w.Write(b); err != nil {
		// Too late to also try to writeError at this point, so just log.
		log.Error(ctx, "Failed writing api response", err, z.Str("vapi_endpoint", endpoint))
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

	w.WriteHeader(aerr.StatusCode)
	w.Header().Set("Content-Type", "application/json")

	if _, err2 = w.Write(b); err2 != nil {
		log.Error(ctx, "Failed writing api error", err2)
	}
}

// unmarshal parses the JSON-encoded request body and stores the result
// in the value pointed to by v.
func unmarshal(body []byte, v interface{}) error {
	if len(body) == 0 {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    "empty request body",
			Err:        errors.New("empty request body"),
		}
	}

	err := json.Unmarshal(body, v)
	if err != nil {
		return apiError{
			StatusCode: http.StatusBadRequest,
			Message:    "failed parsing request body",
			Err:        err,
		}
	}

	return nil
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

func hexQuery(query url.Values, name string) ([]byte, error) {
	valueA, ok := query[name]
	if !ok || len(valueA) != 1 {
		return nil, errors.New("key not present in query")
	}
	value := valueA[0]

	resp, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	}

	return resp, nil
}

// writeFlusher is copied from /net/http/httputil/reverseproxy.go.
// It is required to flush streaming responses.
type writeFlusher interface {
	http.ResponseWriter
	http.Flusher
}

// proxyResponseWriter wraps a http response writer and instruments errors.
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

// stubRoot return a stub dependent root for an epoch.
func stubRoot(epoch uint64) root {
	var r eth2p0.Root
	binary.PutUvarint(r[:], epoch)

	return root(r)
}

// getValidatorIDs returns validator IDs as "id" query parameters (supporting csv values).
func getValidatorIDs(query url.Values) []string {
	var resp []string
	for _, csv := range query["id"] {
		for _, id := range strings.Split(csv, ",") {
			resp = append(resp, strings.TrimSpace(id))
		}
	}

	return resp
}

// getValidatorByID returns the validator and true with id being either a pubkey or a validator index.
// It returns false if the validator is not found.
func getValidatorByID(ctx context.Context, p eth2client.ValidatorsProvider, stateID, id string) (*eth2v1.Validator, bool, error) {
	if strings.HasPrefix(id, "0x") {
		pubkey, err := tblsconv.KeyFromCore(core.PubKey(id))
		if err != nil {
			return nil, false, errors.Wrap(err, "decode public key hex")
		}
		eth2Pubkey, err := tblsconv.KeyToETH2(pubkey)
		if err != nil {
			return nil, false, err
		}

		temp, err := p.ValidatorsByPubKey(ctx, stateID, []eth2p0.BLSPubKey{eth2Pubkey})
		if err != nil {
			return nil, false, err
		}

		for _, validator := range temp {
			return validator, true, nil
		}

		return nil, false, nil
	}

	vIdx, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, false, errors.Wrap(err, "parse validator index")
	}

	temp, err := p.Validators(ctx, stateID, []eth2p0.ValidatorIndex{eth2p0.ValidatorIndex(vIdx)})
	if err != nil {
		return nil, false, err
	}

	for _, validator := range temp {
		return validator, true, nil
	}

	return nil, false, nil
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
