// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec"
	eth2e "github.com/attestantio/go-eth2-client/spec/electra"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/statecomm"
)

// BlockAttestationsProvider is the interface for providing attestations included in blocks.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations.
type BlockAttestationsProvider interface {
	BlockAttestations(ctx context.Context, stateID string) ([]*spec.VersionedAttestation, error)
}

// BlockProvider is the interface for providing block details.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2.
type BlockProvider interface {
	Block(ctx context.Context, stateID string) (*spec.VersionedSignedBeaconBlock, error)
}

// BeaconStateCommitteesProvider is the interface for providing committees for given slot.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochCommittees.
type BeaconStateCommitteesProvider interface {
	BeaconStateCommittees(ctx context.Context, slot uint64) ([]*statecomm.StateCommittee, error)
}

// NodePeerCountProvider is the interface for providing node peer count.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Node/getPeerCount.
type NodePeerCountProvider interface {
	// NodePeerCount provides peer count of the beacon node.
	NodePeerCount(ctx context.Context) (int, error)
}

// NewHTTPAdapterForT returns a http adapter for testing non-eth2service methods as it is nil.
func NewHTTPAdapterForT(_ *testing.T, address string, headers map[string]string, timeout time.Duration) Client {
	return newHTTPAdapter(nil, address, headers, timeout)
}

// AdaptEth2HTTP returns a Client wrapping an eth2http service by adding experimental endpoints.
// Note that the returned client doesn't wrap errors, so they are unstructured without stacktraces.
func AdaptEth2HTTP(eth2Svc *eth2http.Service, headers map[string]string, timeout time.Duration) Client {
	return newHTTPAdapter(eth2Svc, eth2Svc.Address(), headers, timeout)
}

// newHTTPAdapter returns a new http adapter.
func newHTTPAdapter(ethSvc *eth2http.Service, address string, headers map[string]string, timeout time.Duration) *httpAdapter {
	return &httpAdapter{
		Service: ethSvc,
		address: address,
		headers: headers,
		timeout: timeout,
	}
}

// httpAdapter implements Client by wrapping and adding the following to eth2http.Service:
//   - interfaces not present in go-eth2-client
//   - experimental interfaces
type httpAdapter struct {
	*eth2http.Service

	address     string
	headers     map[string]string
	timeout     time.Duration
	valCacheMu  sync.RWMutex
	valCache    func(context.Context) (ActiveValidators, CompleteValidators, error)
	forkVersion [4]byte
}

func (h *httpAdapter) SetForkVersion(forkVersion [4]byte) {
	h.forkVersion = forkVersion
}

func (h *httpAdapter) SetValidatorCache(valCache func(context.Context) (ActiveValidators, CompleteValidators, error)) {
	h.valCacheMu.Lock()
	h.valCache = valCache
	h.valCacheMu.Unlock()
}

func (h *httpAdapter) ActiveValidators(ctx context.Context) (ActiveValidators, error) {
	h.valCacheMu.RLock()
	defer h.valCacheMu.RUnlock()

	if h.valCache == nil {
		return nil, errors.New("no active validator cache")
	}

	active, _, err := h.valCache(ctx)

	return active, err
}

func (h *httpAdapter) CompleteValidators(ctx context.Context) (CompleteValidators, error) {
	h.valCacheMu.RLock()
	defer h.valCacheMu.RUnlock()

	if h.valCache == nil {
		return nil, errors.New("no active validator cache")
	}

	_, complete, err := h.valCache(ctx)

	return complete, err
}

// Validators returns the validators as requested in opts.
// If the amount of validators requested is greater than 200, exponentially increase the timeout: on crowded testnets
// this HTTP call takes a long time.
func (h *httpAdapter) Validators(ctx context.Context, opts *api.ValidatorsOpts) (
	*api.Response[map[eth2p0.ValidatorIndex]*apiv1.Validator],
	error,
) {
	var cancel func()

	reqCtx := ctx

	maxValAmt := max(len(opts.PubKeys), len(opts.Indices))

	if maxValAmt > 200 {
		reqTimeout := time.Duration(50*maxValAmt) * time.Millisecond
		reqCtx, cancel = context.WithTimeout(reqCtx, reqTimeout)
	}

	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	return h.Service.Validators(reqCtx, opts)
}

// AggregateBeaconCommitteeSelections implements eth2exp.BeaconCommitteeSelectionAggregator.
func (h *httpAdapter) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	reqBody, err := json.Marshal(selections)
	if err != nil {
		return nil, errors.Wrap(err, "marshal submit beacon committee selections")
	}

	respBody, err := httpPost(ctx, h.address, "/eth/v1/validator/beacon_committee_selections", bytes.NewReader(reqBody), h.headers, h.timeout)
	if err != nil {
		return nil, errors.Wrap(err, "submit beacon committee selections")
	}

	var resp submitBeaconCommitteeSelectionsJSON
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, errors.Wrap(err, "failed to parse beacon committee selections response")
	}

	return resp.Data, nil
}

// AggregateSyncCommitteeSelections implements eth2exp.SyncCommitteeSelectionAggregator.
func (h *httpAdapter) AggregateSyncCommitteeSelections(ctx context.Context, selections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	reqBody, err := json.Marshal(selections)
	if err != nil {
		return nil, errors.Wrap(err, "marshal sync committee selections")
	}

	respBody, err := httpPost(ctx, h.address, "/eth/v1/validator/sync_committee_selections", bytes.NewReader(reqBody), h.headers, h.timeout)
	if err != nil {
		return nil, errors.Wrap(err, "submit sync committee selections")
	}

	var resp submitSyncCommitteeSelectionsJSON
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, errors.Wrap(err, "failed to parse sync committee selections response")
	}

	return resp.Data, nil
}

// BlockAttestations returns the attestations included in the requested block.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestationsV2.
func (h *httpAdapter) BlockAttestations(ctx context.Context, stateID string) ([]*spec.VersionedAttestation, error) {
	path := fmt.Sprintf("/eth/v2/beacon/blocks/%s/attestations", stateID)

	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	resp, err := httpGetRaw(ctx, h.address, path, h.headers, nil)
	if err != nil {
		return nil, errors.Wrap(err, "request block attestations")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // No block for slot, so no attestations.
	} else if resp.StatusCode != http.StatusOK {
		return nil, errors.New("request block attestations failed", z.Int("status", resp.StatusCode))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "request block attestations body")
	}

	version, err := fetchConsensusVersion(resp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get consensus version")
	}

	res := []*spec.VersionedAttestation{}
	switch version {
	case spec.DataVersionPhase0:
		var respAttestation p0AttestationsJSON
		if err := json.Unmarshal(respBody, &respAttestation); err != nil {
			return nil, errors.Wrap(err, "failed to parse block attestations response")
		}

		for _, a := range respAttestation.Data {
			res = append(res, &spec.VersionedAttestation{Version: version, Phase0: a})
		}
	case spec.DataVersionAltair:
		var respAttestation p0AttestationsJSON
		if err := json.Unmarshal(respBody, &respAttestation); err != nil {
			return nil, errors.Wrap(err, "failed to parse block attestations response")
		}

		for _, a := range respAttestation.Data {
			res = append(res, &spec.VersionedAttestation{Version: version, Altair: a})
		}
	case spec.DataVersionBellatrix:
		var respAttestation p0AttestationsJSON
		if err := json.Unmarshal(respBody, &respAttestation); err != nil {
			return nil, errors.Wrap(err, "failed to parse block attestations response")
		}

		for _, a := range respAttestation.Data {
			res = append(res, &spec.VersionedAttestation{Version: version, Bellatrix: a})
		}
	case spec.DataVersionCapella:
		var respAttestation p0AttestationsJSON
		if err := json.Unmarshal(respBody, &respAttestation); err != nil {
			return nil, errors.Wrap(err, "failed to parse block attestations response")
		}

		for _, a := range respAttestation.Data {
			res = append(res, &spec.VersionedAttestation{Version: version, Capella: a})
		}
	case spec.DataVersionDeneb:
		var respAttestation p0AttestationsJSON
		if err := json.Unmarshal(respBody, &respAttestation); err != nil {
			return nil, errors.Wrap(err, "failed to parse block attestations response")
		}

		for _, a := range respAttestation.Data {
			res = append(res, &spec.VersionedAttestation{Version: version, Deneb: a})
		}
	case spec.DataVersionElectra:
		var respAttestation electraAttestationsJSON
		if err := json.Unmarshal(respBody, &respAttestation); err != nil {
			return nil, errors.Wrap(err, "failed to parse block attestations response")
		}

		for _, a := range respAttestation.Data {
			res = append(res, &spec.VersionedAttestation{Version: version, Electra: a})
		}
	case spec.DataVersionUnknown:
		return nil, errors.New("attestations data version unknown")
	}

	return res, nil
}

// Block returns the block details.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2.
func (h *httpAdapter) Block(ctx context.Context, stateID string) (*spec.VersionedSignedBeaconBlock, error) {
	path := "/eth/v2/beacon/blocks/" + stateID

	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	resp, err := httpGetRaw(ctx, h.address, path, h.headers, nil)
	if err != nil {
		return nil, errors.Wrap(err, "request block")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil //nolint:nilnil // No block for slot.
	} else if resp.StatusCode != http.StatusOK {
		return nil, errors.New("request block failed", z.Int("status", resp.StatusCode))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "request block attestations body")
	}

	res := spec.VersionedSignedBeaconBlock{}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, errors.Wrap(err, "failed to parse block response")
	}

	return &res, nil
}

// BeaconStateCommittees returns the attestations included in the requested block.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators.
func (h *httpAdapter) BeaconStateCommittees(ctx context.Context, slot uint64) ([]*statecomm.StateCommittee, error) {
	r := strconv.FormatUint(slot, 10)
	path := fmt.Sprintf("/eth/v1/beacon/states/%v/committees", r)
	queryParams := map[string]string{
		"slot": strconv.FormatUint(slot, 10),
	}

	respBody, statusCode, err := httpGet(ctx, h.address, path, h.headers, queryParams, h.timeout)
	if err != nil {
		return nil, errors.Wrap(err, "request state committees for slot", z.Int("status", statusCode), z.U64("slot", slot))
	}

	if statusCode != http.StatusOK {
		return nil, errors.New("request state committees for slot failed", z.Int("status", statusCode), z.U64("slot", slot))
	}

	var res statecomm.StateCommitteesResponse

	err = json.Unmarshal(respBody, &res)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal state committees", z.Int("status", statusCode), z.U64("slot", slot))
	}

	return res.Data, nil
}

// ProposerConfig implements eth2exp.ProposerConfigProvider.
func (h *httpAdapter) ProposerConfig(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
	respBody, statusCode, err := httpGet(ctx, h.address, "/proposer_config", h.headers, nil, h.timeout)
	if err != nil {
		return nil, errors.Wrap(err, "submit sync committee selections")
	} else if statusCode != http.StatusOK {
		return nil, errors.New("request proposer config failed", z.Int("status", statusCode), z.Str("body", string(respBody)))
	}

	var resp eth2exp.ProposerConfigResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, errors.Wrap(err, "failed to parse sync committee selections response")
	}

	return &resp, nil
}

// NodePeerCount provides the peer count of the beacon node.
// See https://ethereum.github.io/beacon-APIs/#/Node/getPeerCount.
func (h *httpAdapter) NodePeerCount(ctx context.Context) (int, error) {
	const path = "/eth/v1/node/peer_count"

	respBody, statusCode, err := httpGet(ctx, h.address, path, h.headers, nil, h.timeout)
	if err != nil {
		return 0, errors.Wrap(err, "request beacon node peer count")
	} else if statusCode != http.StatusOK {
		return 0, errors.New("request beacon node peer count failed", z.Int("status", statusCode), z.Str("body", string(respBody)))
	}

	var resp peerCountJSON
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return 0, errors.Wrap(err, "failed to parse beacon node peer count response")
	}

	return resp.Data.Connected, nil
}

// Domain returns the signing domain for a given domain type.
// After EIP-7044, the VOLUNTARY_EXIT domain must always return a domain relative to the Capella hardfork.
// This method returns just that for that domain type, otherwise follows the standard go-eth2-client flow.
func (h *httpAdapter) Domain(ctx context.Context, domainType eth2p0.DomainType, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
	if domainType == (eth2p0.DomainType{0x04, 0x00, 0x00, 0x00}) { // voluntary exit domain
		domain, err := eth2util.CapellaDomain(ctx, "0x"+hex.EncodeToString(h.forkVersion[:]), h.Service, h.Service)
		if err != nil {
			return eth2p0.Domain{}, errors.Wrap(err, "get domain")
		}

		return domain, nil
	}

	return h.Service.Domain(ctx, domainType, epoch)
}

type submitBeaconCommitteeSelectionsJSON struct {
	Data []*eth2exp.BeaconCommitteeSelection `json:"data"`
}

type submitSyncCommitteeSelectionsJSON struct {
	Data []*eth2exp.SyncCommitteeSelection `json:"data"`
}

type p0AttestationsJSON struct {
	Data []*eth2p0.Attestation `json:"data"`
}

type electraAttestationsJSON struct {
	Data []*eth2e.Attestation `json:"data"`
}

type peerCountJSON struct {
	Data struct {
		Connected int `json:"connected,string"`
	} `json:"data"`
}

type responseMetadata struct {
	Version spec.DataVersion `json:"version"`
}

func httpPost(ctx context.Context, base string, endpoint string, body io.Reader, headers map[string]string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, err := url.JoinPath(base, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "invalid address")
	}

	url, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, errors.Wrap(err, "invalid endpoint")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), body)
	if err != nil {
		return nil, errors.Wrap(err, "new POST request with ctx")
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call POST endpoint")
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read POST response")
	}

	if res.StatusCode/100 != 2 {
		return nil, errors.New("post failed", z.Int("status", res.StatusCode), z.Str("body", string(data)))
	}

	return data, nil
}

// httpGetRaw performs a GET request and returns the raw http response or an error.
func httpGetRaw(ctx context.Context, base string, endpoint string, headers map[string]string, queryParams map[string]string) (*http.Response, error) {
	addr, err := url.JoinPath(base, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "invalid address")
	}

	u, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, errors.Wrap(err, "invalid endpoint")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "new GET request with ctx")
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	q := req.URL.Query()
	for key, val := range queryParams {
		q.Add(key, val)
	}

	req.URL.RawQuery = q.Encode()

	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call GET endpoint")
	}

	return res, nil
}

// httpGet performs a GET request and returns the body and status code or an error.
func httpGet(ctx context.Context, base string, endpoint string, headers map[string]string, queryParams map[string]string, timeout time.Duration) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res, err := httpGetRaw(ctx, base, endpoint, headers, queryParams)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to read GET response")
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, errors.Wrap(err, "failed to read GET response body")
	}

	return data, res.StatusCode, nil
}

// fetchConsensusVersion attempts to extract the consensus version from the beacon node http response.
func fetchConsensusVersion(resp *http.Response) (spec.DataVersion, error) {
	respConsensusVersions, exists := resp.Header["Eth-Consensus-Version"]
	if !exists {
		// No consensus version supplied in response; obtain it from the body if possible.
		var metadata responseMetadata

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return spec.DataVersionUnknown, errors.Wrap(err, "read resp body")
		}

		if err := json.Unmarshal(body, &metadata); err != nil {
			return spec.DataVersionUnknown, errors.Wrap(err, "no consensus version header and failed to parse response")
		}

		return metadata.Version, nil
	}

	if len(respConsensusVersions) != 1 {
		return spec.DataVersionUnknown, errors.New("malformed consensus version", z.Int("entries", len(respConsensusVersions)))
	}

	var dataVersion spec.DataVersion

	err := dataVersion.UnmarshalJSON([]byte(fmt.Sprintf("%q", respConsensusVersions[0])))
	if err != nil {
		return spec.DataVersionUnknown, errors.Wrap(err, "unmarshal consensus version header to data version")
	}

	return dataVersion, nil
}
