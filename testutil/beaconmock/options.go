// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package beaconmock

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
)

// Option defines a functional option to configure the mock beacon client.
type Option func(*Mock)

type ValidatorSet map[eth2p0.ValidatorIndex]*eth2v1.Validator

// ByPublicKey is a convenience function to return a validator by its public key.
func (s ValidatorSet) ByPublicKey(pubkey eth2p0.BLSPubKey) (*eth2v1.Validator, bool) {
	for _, validator := range s {
		if pubkey == validator.Validator.PublicKey {
			return validator, true
		}
	}

	return nil, false
}

// PublicKeys is a convenience function to extract the bls public keys from the validators.
func (s ValidatorSet) PublicKeys() ([]*bls_sig.PublicKey, error) {
	var resp []*bls_sig.PublicKey
	for _, validator := range s {
		pk := new(bls_sig.PublicKey)
		err := pk.UnmarshalBinary(validator.Validator.PublicKey[:])
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal pubkey")
		}

		resp = append(resp, pk)
	}

	return resp, nil
}

// ValidatorSetA defines a set 3 validators.
var ValidatorSetA = ValidatorSet{
	1: {
		Index:   1,
		Balance: 1,
		Status:  eth2v1.ValidatorStateActiveOngoing,
		Validator: &eth2p0.Validator{
			PublicKey:                  mustPKFromHex("0x914cff835a769156ba43ad50b931083c2dadd94e8359ce394bc7a3e06424d0214922ddf15f81640530b9c25c0bc0d490"),
			EffectiveBalance:           1,
			ActivationEligibilityEpoch: 1,
			ActivationEpoch:            2,
		},
	},
	2: {
		Index:   2,
		Balance: 2,
		Status:  eth2v1.ValidatorStateActiveOngoing,
		Validator: &eth2p0.Validator{
			PublicKey:                  mustPKFromHex("0x8dae41352b69f2b3a1c0b05330c1bf65f03730c520273028864b11fcb94d8ce8f26d64f979a0ee3025467f45fd2241ea"),
			EffectiveBalance:           2,
			ActivationEligibilityEpoch: 2,
			ActivationEpoch:            3,
		},
	},
	3: {
		Index:   3,
		Balance: 3,
		Status:  eth2v1.ValidatorStateActiveOngoing,
		Validator: &eth2p0.Validator{
			PublicKey:                  mustPKFromHex("0x8ee91545183c8c2db86633626f5074fd8ef93c4c9b7a2879ad1768f600c5b5906c3af20d47de42c3b032956fa8db1a76"),
			EffectiveBalance:           3,
			ActivationEligibilityEpoch: 3,
			ActivationEpoch:            4,
		},
	},
}

// WithValidatorSet configures the mock with the provided validator set.
func WithValidatorSet(set ValidatorSet) Option {
	return func(mock *Mock) {
		mock.ValidatorsByPubKeyFunc = func(ctx context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
			for _, pubkey := range pubkeys {
				val, ok := set.ByPublicKey(pubkey)
				if ok {
					resp[val.Index] = val
				}
			}

			return resp, nil
		}

		mock.ValidatorsFunc = func(ctx context.Context, stateID string, indexes []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
			for _, index := range indexes {
				val, ok := set[index]
				if ok {
					resp[index] = val
				}
			}

			return resp, nil
		}
	}
}

// WithGenesis configures the mock with the provided genesis time.
func WithGenesis(t0 time.Time) Option {
	return func(mock *Mock) {
		mock.GenesisTimeFunc = func(_ context.Context) (time.Time, error) {
			return t0, nil
		}
	}
}

// WithDeterministicDuties configures the mock with to provide deterministic duties based on provided arguments and config.
// Note it depends on ValidatorsFunc being populated, e.g. via WithValidatorSet.
func WithDeterministicDuties(factor int) Option {
	return func(mock *Mock) {
		mock.AttesterDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			vals, err := mock.Validators(ctx, "", indices)
			if err != nil {
				return nil, err
			}

			slotsPerEpoch, err := mock.SlotsPerEpoch(ctx)
			if err != nil {
				return nil, err
			}

			sort.Slice(indices, func(i, j int) bool {
				return indices[i] < indices[j]
			})

			var resp []*eth2v1.AttesterDuty
			for i, index := range indices {
				val, ok := vals[index]
				if !ok {
					continue
				}

				resp = append(resp, &eth2v1.AttesterDuty{
					PubKey:                  val.Validator.PublicKey,
					Slot:                    eth2p0.Slot(slotsPerEpoch*uint64(epoch) + uint64(i*factor)),
					ValidatorIndex:          index,
					CommitteeIndex:          eth2p0.CommitteeIndex(i * factor),
					CommitteeLength:         0,
					CommitteesAtSlot:        0,
					ValidatorCommitteeIndex: uint64(i * factor),
				})
			}

			return resp, nil
		}
	}
}

// defaultMock returns a minimum viable mock that doesn't panic and returns mostly empty responses.
// The default slots have 1 second duration and there are 10 slots per epoch (for simple math).
func defaultMock() Mock {
	return Mock{
		ProposerDutiesFunc: func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			return nil, nil
		},
		AttesterDutiesFunc: func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			return nil, nil
		},
		SlotDurationFunc: func(ctx context.Context) (time.Duration, error) {
			return time.Second, nil
		},
		SlotsPerEpochFunc: func(ctx context.Context) (uint64, error) {
			return 10, nil
		},
		ValidatorsFunc: func(ctx context.Context, stateID string, indices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			return nil, nil
		},
		ValidatorsByPubKeyFunc: func(ctx context.Context, stateID string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			return nil, nil
		},
		GenesisTimeFunc: func(ctx context.Context) (time.Time, error) {
			day := time.Hour * 24
			return time.Now().Truncate(day).Add(-day), nil // Start of yesterday.
		},
		NodeSyncingFunc: func(ctx context.Context) (*eth2v1.SyncState, error) {
			return &eth2v1.SyncState{
				HeadSlot:     0,
				SyncDistance: 0,
				IsSyncing:    false,
			}, nil
		},
	}
}

func mustPKFromHex(pubkeyHex string) eth2p0.BLSPubKey {
	pubkeyHex = strings.TrimPrefix(pubkeyHex, "0x")
	b, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		panic(err)
	}
	var resp eth2p0.BLSPubKey
	n := copy(resp[:], b)
	if n != 48 {
		panic("invalid pubkey hex")
	}

	return resp
}
