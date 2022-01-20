// Package validatorapi defines validator facing API that serves the subset of
// endpoints related to distributed validation and reverse-proxies the rest to the
// upstream beacon client.
package validatorapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
	zerologger "github.com/rs/zerolog/log"
)

var log = zerologger.Logger

// NewRouter returns a new validator http server router. The http router
// translates http requests related to the distributed validator to the validatorapi.Handler.
// All other requests are reserve-proxied to the beacon-node address.
func NewRouter(h Handler, beaconNodeAddr string) (*mux.Router, error) {
	proxy, err := proxyHandler(beaconNodeAddr)
	if err != nil {
		return nil, err
	}

	r := mux.NewRouter()

	// Register subset of distributed validator related endpoints
	r.Handle("/eth/v1/validator/duties/attester/{epoch}", wrapAttesterDuties(h))
	// TODO(corver): Add more endpoints

	// Everything else is proxied
	r.PathPrefix("/").Handler(proxy)

	return r, nil
}

func wrapAttesterDuties(h Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			params = struct {
				Epoch eth2p0.Epoch `json:"epoch,string"`
			}{}
			reqBody attesterDutiesRequest
		)
		if ok := parseReq(w, r, &params, &reqBody); !ok {
			return
		}

		data, err := h.AttesterDuties(r.Context(), params.Epoch, reqBody)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		res := attesterDutiesResponse{
			DependentRoot: eth2p0.Root{}, // TODO(corver): Fill this
			Data:          data,
		}

		writeResponse(w, res)
	}
}

// proxyHandler returns a reverse proxy handler.
func proxyHandler(target string) (http.Handler, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy target address: %w", err)
	}

	// TODO(corver): Add support for multiple upstream targets via some form of load balancing.
	return httputil.NewSingleHostReverseProxy(targetURL), nil
}

// parseReq parses route variables in params and the json request body into reqBody and returns true.
// On any parsing error, it writes the http error response and returns false.
func parseReq(w http.ResponseWriter, r *http.Request, params interface{}, reqBody interface{}) bool {
	b, err := json.Marshal(mux.Vars(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}

	if err := json.Unmarshal(b, params); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}

	b, err = io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}

	if err := json.Unmarshal(b, reqBody); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}

	return true
}

// writeResponse writes the 200 OK response and json response body.
func writeResponse(w http.ResponseWriter, response interface{}) {
	b, err := json.Marshal(response)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("marshal response body: %w", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	if _, err = w.Write(b); err != nil {
		log.Error().Err(err).Msg("Failed writing api response")
	}
}

// writeError writes a http json error response object.
func writeError(w http.ResponseWriter, statusCode int, err error) {
	log.Error().Err(err).Int("status", statusCode).Msg("validator api error response")

	res := errorResponse{
		Code:    statusCode,
		Message: err.Error(), // TODO(corver): This could leak sensitive info, define "exposable errors" with safe messages.
	}

	b, err2 := json.Marshal(res)
	if err2 != nil {
		log.Error().Err(err2).Msg("Failed marshalling error body")
	}

	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")

	if _, err2 = w.Write(b); err2 != nil {
		log.Error().Err(err2).Msg("Failed writing api error")
	}
}
