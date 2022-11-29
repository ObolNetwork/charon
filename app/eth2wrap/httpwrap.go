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

package eth2wrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
)

// syntheticBlockGraffiti defines the graffiti to identify synthetic blocks.
const syntheticBlockGraffiti = "SYNTHETIC BLOCK: DO NOT SUBMIT"

// BlockAttestationsProvider is the interface for providing attestations included in blocks.
// It is a standard beacon API endpoint not implemented by eth2client.
// See https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations.
type BlockAttestationsProvider interface {
	BlockAttestations(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error)
}

type Option func(*httpAdapter)

// WithSyntheticDuties returns an option that enables synthetic duties.
func WithSyntheticDuties(pubkeys []eth2p0.BLSPubKey) Option {
	return func(a *httpAdapter) {
		a.syntheticDuties = true
		a.synthProposerCache = newSynthProposerCache(pubkeys)
	}
}

// NewHTTPAdapterForT returns a http adapter for testing non-eth2service methods as it is nil.
func NewHTTPAdapterForT(_ *testing.T, address string, timeout time.Duration, opts ...Option) *httpAdapter {
	return newHTTPAdapter(nil, address, timeout, opts...)
}

// AdaptEth2HTTP returns a Client wrapping an eth2http service by adding experimental endpoints.
// Note that the returned client doesn't wrap errors, so they are unstructured without stacktraces.
func AdaptEth2HTTP(eth2Svc *eth2http.Service, timeout time.Duration, opts ...Option) Client {
	return newHTTPAdapter(eth2Svc, eth2Svc.Address(), timeout, opts...)
}

// newHTTPAdapter returns a new http adapter.
func newHTTPAdapter(ethSvc *eth2http.Service, address string, timeout time.Duration, opts ...Option) *httpAdapter {
	a := &httpAdapter{
		Service: ethSvc,
		address: address,
		timeout: timeout,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// httpAdapter implements Client by wrapping and adding the following to eth2http.Service:
//   - experimental interfaces not present in go-eth2-client
//   - synthetic duties
type httpAdapter struct {
	*eth2http.Service
	address            string
	timeout            time.Duration
	syntheticDuties    bool
	synthProposerCache *synthProposerCache
}

// ProposerDuties returns upstream proposer duties for the provided validator indexes or
// upstream proposer duties and synthetic duties for all cluster validators if enabled.
func (h *httpAdapter) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, valIdxs []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	if h.syntheticDuties {
		return h.synthProposerCache.Duties(ctx, h.Service, epoch)
	}

	return h.Service.ProposerDuties(ctx, epoch, valIdxs)
}

// BeaconBlockProposal returns an unsigned beacon block, possibly marked as synthetic.
func (h *httpAdapter) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	if h.syntheticDuties {
		ok, err := h.synthProposerCache.IsSynthetic(ctx, h.Service, slot)
		if err != nil {
			return nil, err
		}

		if ok {
			graffiti = []byte(syntheticBlockGraffiti)
		}
	}

	return h.Service.BeaconBlockProposal(ctx, slot, randao, graffiti)
}

// BlindedBeaconBlockProposal returns an unsigned blinded beacon block, possibly marked as synthetic.
func (h *httpAdapter) BlindedBeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, graffiti []byte) (*api.VersionedBlindedBeaconBlock, error) {
	if h.syntheticDuties {
		ok, err := h.synthProposerCache.IsSynthetic(ctx, h.Service, slot)
		if err != nil {
			return nil, err
		}

		if ok {
			graffiti = []byte(syntheticBlockGraffiti)
		}
	}

	return h.Service.BlindedBeaconBlockProposal(ctx, slot, randao, graffiti)
}

// SubmitBlindedBeaconBlock submits a blinded beacon block or swallows it if marked as synthetic.
func (h *httpAdapter) SubmitBlindedBeaconBlock(ctx context.Context, block *api.VersionedSignedBlindedBeaconBlock) error {
	var graffiti [32]byte
	switch block.Version {
	case spec.DataVersionBellatrix:
		graffiti = block.Bellatrix.Message.Body.Graffiti
	default:
		return errors.New("unknown block version")
	}

	var synthGraffiti [32]byte
	copy(synthGraffiti[:], syntheticBlockGraffiti)
	if graffiti == synthGraffiti {
		log.Debug(ctx, "Synthetic blinded beacon block swallowed")
		return nil
	}

	return h.Service.SubmitBlindedBeaconBlock(ctx, block)
}

// SubmitBeaconBlock submits a beacon block or swallows it if marked as synthetic.
func (h *httpAdapter) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	var graffiti [32]byte
	switch block.Version {
	case spec.DataVersionPhase0:
		graffiti = block.Phase0.Message.Body.Graffiti
	case spec.DataVersionAltair:
		graffiti = block.Altair.Message.Body.Graffiti
	case spec.DataVersionBellatrix:
		graffiti = block.Bellatrix.Message.Body.Graffiti
	case spec.DataVersionCapella:
		graffiti = block.Capella.Message.Body.Graffiti
	default:
		return errors.New("unknown block version")
	}

	var synthGraffiti [32]byte
	copy(synthGraffiti[:], syntheticBlockGraffiti)
	if graffiti == synthGraffiti {
		log.Debug(ctx, "Synthetic beacon block swallowed")
		return nil
	}

	return h.Service.SubmitBeaconBlock(ctx, block)
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

type submitBeaconCommitteeSelectionsJSON struct {
	Data []*eth2exp.BeaconCommitteeSelection `json:"data"`
}

type submitSyncCommitteeSelectionsJSON struct {
	Data []*eth2exp.SyncCommitteeSelection `json:"data"`
}

type attestationsJSON struct {
	Data []*eth2p0.Attestation `json:"data"`
}

func httpPost(ctx context.Context, base string, endpoint string, body io.Reader, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, err := url.JoinPath(base, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "invalid address")
	}

	url, err := url.Parse(addr)
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

	u, err := url.Parse(addr)
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
