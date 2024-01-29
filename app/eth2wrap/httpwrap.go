// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// BlockAttestationsProvider is the interface for providing attestations included in blocks.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations.
type BlockAttestationsProvider interface {
	BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error)
}

// NodePeerCountProvider is the interface for providing node peer count.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Node/getPeerCount.
type NodePeerCountProvider interface {
	// NodePeerCount provides peer count of the beacon node.
	NodePeerCount(ctx context.Context) (int, error)
}

// NewHTTPAdapterForT returns a http adapter for testing non-eth2service methods as it is nil.
func NewHTTPAdapterForT(_ *testing.T, address string, timeout time.Duration) Client {
	return newHTTPAdapter(nil, address, timeout)
}

// AdaptEth2HTTP returns a Client wrapping an eth2http service by adding experimental endpoints.
// Note that the returned client doesn't wrap errors, so they are unstructured without stacktraces.
func AdaptEth2HTTP(eth2Svc *eth2http.Service, timeout time.Duration) Client {
	return newHTTPAdapter(eth2Svc, eth2Svc.Address(), timeout)
}

// newHTTPAdapter returns a new http adapter.
func newHTTPAdapter(ethSvc *eth2http.Service, address string, timeout time.Duration) *httpAdapter {
	return &httpAdapter{
		Service: ethSvc,
		address: address,
		timeout: timeout,
	}
}

// httpAdapter implements Client by wrapping and adding the following to eth2http.Service:
//   - interfaces not present in go-eth2-client
//   - experimental interfaces
type httpAdapter struct {
	*eth2http.Service
	address    string
	timeout    time.Duration
	valCacheMu sync.RWMutex
	valCache   func(context.Context) (ActiveValidators, error)
}

func (h *httpAdapter) SetValidatorCache(valCache func(context.Context) (ActiveValidators, error)) {
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

	return h.valCache(ctx)
}

// AggregateBeaconCommitteeSelections implements eth2exp.BeaconCommitteeSelectionAggregator.
func (h *httpAdapter) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	reqBody, err := json.Marshal(selections)
	if err != nil {
		return nil, errors.Wrap(err, "marshal submit beacon committee selections")
	}

	respBody, err := httpPost(ctx, h.address, "/eth/v1/validator/beacon_committee_selections", bytes.NewReader(reqBody), h.timeout)
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

	respBody, err := httpPost(ctx, h.address, "/eth/v1/validator/sync_committee_selections", bytes.NewReader(reqBody), h.timeout)
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
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations.
func (h *httpAdapter) BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
	path := fmt.Sprintf("/eth/v1/beacon/blocks/%s/attestations", stateID)
	respBody, statusCode, err := httpGet(ctx, h.address, path, h.timeout)
	if err != nil {
		return nil, errors.Wrap(err, "request block attestations")
	} else if statusCode == http.StatusNotFound {
		return nil, nil // No block for slot, so no attestations.
	} else if statusCode != http.StatusOK {
		return nil, errors.New("request block attestations failed", z.Int("status", statusCode), z.Str("body", string(respBody)))
	}

	var resp attestationsJSON
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, errors.Wrap(err, "failed to parse block attestations response")
	}

	return resp.Data, nil
}

// ProposerConfig implements eth2exp.ProposerConfigProvider.
func (h *httpAdapter) ProposerConfig(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
	respBody, statusCode, err := httpGet(ctx, h.address, "/proposer_config", h.timeout)
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
	respBody, statusCode, err := httpGet(ctx, h.address, path, h.timeout)
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

type submitBeaconCommitteeSelectionsJSON struct {
	Data []*eth2exp.BeaconCommitteeSelection `json:"data"`
}

type submitSyncCommitteeSelectionsJSON struct {
	Data []*eth2exp.SyncCommitteeSelection `json:"data"`
}

type attestationsJSON struct {
	Data []*eth2p0.Attestation `json:"data"`
}

type peerCountJSON struct {
	Data struct {
		Connected int `json:"connected,string"`
	} `json:"data"`
}

func httpPost(ctx context.Context, base string, endpoint string, body io.Reader, timeout time.Duration) ([]byte, error) {
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

// httpGet performs a GET request and returns the body and status code or an error.
func httpGet(ctx context.Context, base string, endpoint string, timeout time.Duration) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, err := url.JoinPath(base, endpoint)
	if err != nil {
		return nil, 0, errors.Wrap(err, "invalid address")
	}

	u, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, 0, errors.Wrap(err, "invalid endpoint")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, errors.Wrap(err, "new GET request with ctx")
	}

	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to call GET endpoint")
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to read GET response")
	}

	return data, res.StatusCode, nil
}
