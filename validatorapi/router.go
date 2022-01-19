// Package validatorapi defines validator facing API that serves the subset of
// endpoints related to distributed validation and reverse-proxies the rest to the
// upstream beacon client.
package validatorapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
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
	r.Handle("/eth/v1/validator/duties/attester/{epoch}", wrapAttesterDuties(h)) // TODO(corver): Add more endpoints

	// Everything else is proxied
	r.PathPrefix("/").Handler(proxy)

	return r, nil
}

func wrapAttesterDuties(h Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			params = struct {
				Epoch eth2p0.Epoch `json:"epoch"`
			}{}

			reqBody []eth2p0.ValidatorIndex
		)

		if ok := parseReq(w, r, &params, &reqBody); !ok {
			return
		}

		data, err := h.AttesterDuties(r.Context(), params.Epoch, reqBody)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		res := struct {
			DependentRoot string                 `json:"dependent_root"`
			Data          []*eth2v1.AttesterDuty `json:"data"`
		}{
			DependentRoot: "", // TODO(corver): Fill this
			Data:          data,
		}

		writeResponse(w, res)
	}
}

func proxyHandler(target string) (http.HandlerFunc, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy target address", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}, nil
}

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

	reader, err := r.GetBody()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}

	if err := json.NewDecoder(reader).Decode(reqBody); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}

	return true
}

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

func writeError(w http.ResponseWriter, statusCode int, err error) {
	log.Error().Err(err).Int("status", statusCode).Msg("validator api error response")

	var body = struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		// TODO(corver): Maybe add stacktraces field for debugging.
	}{
		Code:    statusCode,
		Message: err.Error(),
	}

	b, err2 := json.Marshal(body)
	if err2 != nil {
		log.Error().Err(err2).Msg("Failed marshalling error body")
	}

	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")

	if _, err2 = w.Write(b); err2 != nil {
		log.Error().Err(err2).Msg("Failed writing api error")
	}
}
