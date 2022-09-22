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

package beaconmock

import (
	"context"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util"
)

// newAttestationStore returns a new empty attestationStore.
func newAttestationStore(httpMock HTTPMock) *attestationStore {
	return &attestationStore{
		httpMock: httpMock,
		store:    make(map[eth2p0.Root]*eth2p0.AttestationData),
	}
}

// attestationStore generates mock attestation data and
// stores submitted attestations to support consistent aggregations.
type attestationStore struct {
	httpMock HTTPMock

	mu    sync.Mutex
	store map[eth2p0.Root]*eth2p0.AttestationData
}

func (s *attestationStore) getData(root eth2p0.Root) (*eth2p0.AttestationData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp, ok := s.store[root]

	return resp, ok
}

func (s *attestationStore) setData(data *eth2p0.AttestationData, root eth2p0.Root) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean data older than 32 slots.
	const cleanAfter = 32
	for key, old := range s.store {
		if old.Slot+cleanAfter < data.Slot {
			delete(s.store, key)
		}
	}

	s.store[root] = data
}

// AttestationDataByRoot returns a previously generates attestation data by root.
func (s *attestationStore) AttestationDataByRoot(dataRoot eth2p0.Root) (*eth2p0.AttestationData, error) {
	data, ok := s.getData(dataRoot)
	if !ok {
		return nil, errors.New("unknown aggregate attestation root")
	}

	return data, nil
}

// NewAttestationData generates and and returns an attestation data.
func (s *attestationStore) NewAttestationData(ctx context.Context, slot eth2p0.Slot, index eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	epoch, err := epochFromSlot(ctx, s.httpMock, slot)
	if err != nil {
		return nil, err
	}

	data := newAttestationData(epoch, slot, index)

	root, err := data.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "hash data")
	}

	s.setData(data, root)

	return data, nil
}

// newAttestationData returns a deterministic attestation data that should pass superficial validation.
// TODO(corver): Maybe make this non-deterministic, to be more aligned with real world.
func newAttestationData(epoch eth2p0.Epoch, slot eth2p0.Slot, index eth2p0.CommitteeIndex) *eth2p0.AttestationData {
	return &eth2p0.AttestationData{
		Slot:            slot,
		Index:           index,
		BeaconBlockRoot: mustRoot(uint64(slot)),
		Source: &eth2p0.Checkpoint{
			Epoch: epoch - 1,
			Root:  mustRoot(uint64(epoch - 1)),
		},
		Target: &eth2p0.Checkpoint{
			Epoch: epoch,
			Root:  mustRoot(uint64(epoch)),
		},
	}
}

// epochFromSlot returns the slot epoch.
func epochFromSlot(ctx context.Context, provider eth2client.SlotsPerEpochProvider, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := provider.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, err
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}

// mustRoot return the uint64 hash root.
func mustRoot(num uint64) eth2p0.Root {
	root, err := eth2util.SlotHashRoot(eth2p0.Slot(num))
	if err != nil {
		// It is fine to panic in test code, it should never panic in any-case.
		panic("slot root error: " + err.Error())
	}

	return root
}
