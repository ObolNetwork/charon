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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/testutil"
)

// Option defines a functional option to configure the mock beacon client.
type Option func(*Mock)

type ValidatorSet map[eth2p0.ValidatorIndex]*eth2v1.Validator

// Validators is a convenience function to return the validators as a slice.
func (s ValidatorSet) Validators() []*eth2v1.Validator {
	var resp []*eth2v1.Validator
	for _, validator := range s {
		resp = append(resp, validator)
	}

	return resp
}

// ByPublicKey is a convenience function to return a validator by its public key.
func (s ValidatorSet) ByPublicKey(pubkey eth2p0.BLSPubKey) (*eth2v1.Validator, bool) {
	for _, validator := range s {
		if pubkey == validator.Validator.PublicKey {
			return validator, true
		}
	}

	return nil, false
}

// CorePubKeys is a convenience function to extract the core workflow public keys from the validators.
func (s ValidatorSet) CorePubKeys() ([]core.PubKey, error) {
	var resp []core.PubKey
	for _, validator := range s {
		pk, err := core.PubKeyFromBytes(validator.Validator.PublicKey[:])
		if err != nil {
			return nil, errors.Wrap(err, "unmarshal pubkey")
		}

		resp = append(resp, pk)
	}

	return resp, nil
}

// PublicKeys is a convenience function to extract the eth2 client bls public keys from the validators.
func (s ValidatorSet) PublicKeys() []eth2p0.BLSPubKey {
	var resp []eth2p0.BLSPubKey
	for _, validator := range s {
		resp = append(resp, validator.Validator.PublicKey)
	}

	return resp
}

// Clone returns a copy of this validator set.
func (s ValidatorSet) Clone() (ValidatorSet, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, errors.Wrap(err, "marshal set")
	}

	resp := make(ValidatorSet)
	err = json.Unmarshal(b, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal set")
	}

	return resp, nil
}

// ValidatorSetA defines a set of 3 validators.
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
			WithdrawalCredentials:      []byte("12345678901234567890123456789012"),
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
			WithdrawalCredentials:      []byte("12345678901234567890123456789012"),
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
			WithdrawalCredentials:      []byte("12345678901234567890123456789012"),
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
					resp[val.Index] = cloneValidator(val)
				} else {
					log.Debug(ctx, "Pubkey not found")
				}
			}

			return resp, nil
		}

		mock.ValidatorsFunc = func(ctx context.Context, stateID string, indexes []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
			for _, index := range indexes {
				val, ok := set[index]
				if ok {
					resp[index] = cloneValidator(val)
				} else {
					log.Debug(ctx, "Index not found")
				}
			}

			return resp, nil
		}
	}
}

// cloneValidator returns a cloned value that is safe for modification.
func cloneValidator(val *eth2v1.Validator) *eth2v1.Validator {
	tempv1 := *val
	tempp0 := *tempv1.Validator
	tempv1.Validator = &tempp0

	return &tempv1
}

// WithEndpoint configures the http mock with the endpoint override.
func WithEndpoint(endpoint string, value string) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: endpoint,
			Value:    value,
		})
	}
}

// WithGenesisTime configures the http mock with the provided genesis time.
func WithGenesisTime(t0 time.Time) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/beacon/genesis",
			Key:      "genesis_time",
			Value:    fmt.Sprint(t0.Unix()),
		})
	}
}

// WithGenesisValidatorsRoot configures the http mock with the provided genesis validators root.
func WithGenesisValidatorsRoot(root [32]byte) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/beacon/genesis",
			Key:      "genesis_validators_root",
			Value:    fmt.Sprintf("%#x", root),
		})
	}
}

// WithSlotDuration configures the http mock with the provided slots duration.
func WithSlotDuration(duration time.Duration) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/config/spec",
			Key:      "SECONDS_PER_SLOT",
			Value:    fmt.Sprint(int(duration.Seconds())),
		})
	}
}

// WithSlotsPerEpoch configures the http mock with the provided slots per epoch.
func WithSlotsPerEpoch(slotsPerEpoch int) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/config/spec",
			Key:      "SLOTS_PER_EPOCH",
			Value:    fmt.Sprint(slotsPerEpoch),
		})
	}
}

// WithDeterministicAttesterDuties configures the mock to provide deterministic
// duties based on provided arguments and config.
// Note it depends on ValidatorsFunc being populated, e.g. via WithValidatorSet.
func WithDeterministicAttesterDuties(factor int) Option {
	// Aggregation duties assigned using committee_length=factor and TARGET_AGGREGATORS_PER_COMMITTEE (=16).
	// So validators are aggregators 1 out of every committee_length/TARGET_AGGREGATORS_PER_COMMITTEE or factor/16.
	// So if all validators are aggregators if factor<=16.
	commLength := uint64(factor)
	if commLength < 1 {
		commLength = 1
	}
	valCommIndex := commLength - 1 // Validator always last index in committee.

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

				slotOffset := (i * factor) % int(slotsPerEpoch)

				resp = append(resp, &eth2v1.AttesterDuty{
					PubKey:                  val.Validator.PublicKey,
					Slot:                    eth2p0.Slot(slotsPerEpoch*uint64(epoch) + uint64(slotOffset)),
					ValidatorIndex:          index,
					CommitteeIndex:          eth2p0.CommitteeIndex(slotOffset),
					CommitteeLength:         commLength,
					CommitteesAtSlot:        slotsPerEpoch,
					ValidatorCommitteeIndex: valCommIndex,
				})
			}

			return resp, nil
		}
	}
}

// WithDeterministicProposerDuties configures the mock to provide deterministic duties based on provided arguments and config.
// Note it depends on ValidatorsFunc being populated, e.g. via WithValidatorSet.
func WithDeterministicProposerDuties(factor int) Option {
	return func(mock *Mock) {
		mock.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			// if indices slice is empty then it would use 0th index or in that case first validator will be the proposer always
			// this would be the case when validator calls for block proposer and expects proposer duties from beacon node.
			if len(indices) == 0 {
				indices = []eth2p0.ValidatorIndex{0}
			}

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

			var resp []*eth2v1.ProposerDuty
			for i, index := range indices {
				val, ok := vals[index]
				if !ok {
					continue
				}

				offset := (i * factor) % int(slotsPerEpoch)

				resp = append(resp, &eth2v1.ProposerDuty{
					PubKey:         val.Validator.PublicKey,
					Slot:           eth2p0.Slot(slotsPerEpoch*uint64(epoch) + uint64(offset)),
					ValidatorIndex: index,
				})

				// there can be only one proposer per slot, in this case it would be the first validator who will propose
				if factor == 0 {
					break
				}
			}

			return resp, nil
		}
	}
}

// WithNoProposerDuties configures the mock to override ProposerDutiesFunc to return nothing.
func WithNoProposerDuties() Option {
	return func(mock *Mock) {
		mock.ProposerDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			return nil, nil
		}
	}
}

// WithNoAttesterDuties configures the mock to override AttesterDutiesFunc to return nothing.
func WithNoAttesterDuties() Option {
	return func(mock *Mock) {
		mock.AttesterDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			return nil, nil
		}
	}
}

// WithNoSyncCommitteeDuties configures the mock to override SyncCommitteeDutiesFunc to return nothing.
func WithNoSyncCommitteeDuties() Option {
	return func(mock *Mock) {
		mock.SyncCommitteeDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
			return nil, nil
		}
	}
}

// WithDeterministicSyncCommDuties configures the mock to override SyncCommitteeDutiesFunc to return sync committee
// duties for all validators for first N epochs in every K epochs. N is also used as EPOCHS_PER_SYNC_COMMITTEE_PERIOD.
func WithDeterministicSyncCommDuties(n, k int) Option {
	return func(mock *Mock) {
		mock.SyncCommitteeDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
			if int(epoch)%k >= n {
				return nil, nil
			}

			vals, err := mock.Validators(ctx, "", indices)
			if err != nil {
				return nil, err
			}

			var resp []*eth2v1.SyncCommitteeDuty
			for i, index := range indices {
				val, ok := vals[index]
				if !ok {
					continue
				}

				resp = append(resp, &eth2v1.SyncCommitteeDuty{
					PubKey:                        val.Validator.PublicKey,
					ValidatorIndex:                index,
					ValidatorSyncCommitteeIndices: []eth2p0.CommitteeIndex{eth2p0.CommitteeIndex(i)},
				})
			}

			return resp, nil
		}

		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/config/spec",
			Key:      "EPOCHS_PER_SYNC_COMMITTEE_PERIOD",
			Value:    fmt.Sprint(n),
		})
	}
}

// WithClock configures the mock with the provided clock.
func WithClock(clock clockwork.Clock) Option {
	return func(mock *Mock) {
		mock.clock = clock
	}
}

// defaultMock returns a minimum viable mock that doesn't panic and returns mostly empty responses.
func defaultMock(httpMock HTTPMock, httpServer *http.Server, clock clockwork.Clock, headProducer *headProducer) Mock {
	attStore := newAttestationStore(httpMock)

	return Mock{
		clock:        clock,
		HTTPMock:     httpMock,
		httpServer:   httpServer,
		headProducer: headProducer,
		BeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
			return &spec.VersionedBeaconBlock{
				Version: spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.BeaconBlock{
					Slot: slot,
					Body: &bellatrix.BeaconBlockBody{
						RANDAOReveal: randaoReveal,
						ETH1Data: &eth2p0.ETH1Data{
							DepositRoot:  testutil.RandomRoot(),
							DepositCount: 0,
							BlockHash:    testutil.RandomBytes32(),
						},
						Graffiti:          array32(graffiti),
						ProposerSlashings: []*eth2p0.ProposerSlashing{},
						AttesterSlashings: []*eth2p0.AttesterSlashing{},
						Attestations:      []*eth2p0.Attestation{testutil.RandomAttestation(), testutil.RandomAttestation()},
						Deposits:          []*eth2p0.Deposit{},
						VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits:      bitfield.NewBitvector512(),
							SyncCommitteeSignature: testutil.RandomEth2Signature(),
						},
						ExecutionPayload: testutil.RandomExecutionPayLoad(),
					},
				},
			}, nil
		},
		BlindedBeaconBlockProposalFunc: func(ctx context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
			return &eth2api.VersionedBlindedBeaconBlock{
				Version: spec.DataVersionBellatrix,
				Bellatrix: &eth2v1.BlindedBeaconBlock{
					Slot: slot,
					Body: &eth2v1.BlindedBeaconBlockBody{
						RANDAOReveal: randaoReveal,
						ETH1Data: &eth2p0.ETH1Data{
							DepositRoot:  testutil.RandomRoot(),
							DepositCount: 0,
							BlockHash:    testutil.RandomBytes32(),
						},
						Graffiti:          array32(graffiti),
						ProposerSlashings: []*eth2p0.ProposerSlashing{},
						AttesterSlashings: []*eth2p0.AttesterSlashing{},
						Attestations:      []*eth2p0.Attestation{testutil.RandomAttestation(), testutil.RandomAttestation()},
						Deposits:          []*eth2p0.Deposit{},
						VoluntaryExits:    []*eth2p0.SignedVoluntaryExit{},
						SyncAggregate: &altair.SyncAggregate{
							SyncCommitteeBits:      bitfield.NewBitvector512(),
							SyncCommitteeSignature: testutil.RandomEth2Signature(),
						},
						ExecutionPayloadHeader: testutil.RandomExecutionPayloadHeader(),
					},
				},
			}, nil
		},
		ProposerDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			return []*eth2v1.ProposerDuty{}, nil
		},
		BeaconCommitteesFunc: func(context.Context, string) ([]*eth2v1.BeaconCommittee, error) {
			return []*eth2v1.BeaconCommittee{}, nil
		},
		AttesterDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			return []*eth2v1.AttesterDuty{}, nil
		},
		AttestationDataFunc: func(ctx context.Context, slot eth2p0.Slot, index eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
			return attStore.NewAttestationData(ctx, slot, index)
		},
		AggregateAttestationFunc: func(ctx context.Context, slot eth2p0.Slot, root eth2p0.Root) (*eth2p0.Attestation, error) {
			attData, err := attStore.AttestationDataByRoot(root)
			if err != nil {
				return nil, err
			}

			return &eth2p0.Attestation{
				AggregationBits: bitfield.NewBitlist(0),
				Data:            attData,
			}, nil
		},
		ValidatorsFunc: func(context.Context, string, []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			return nil, nil
		},
		ValidatorsByPubKeyFunc: func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			return nil, nil
		},
		SubmitAttestationsFunc: func(context.Context, []*eth2p0.Attestation) error {
			return nil
		},
		SubmitBeaconBlockFunc: func(context.Context, *spec.VersionedSignedBeaconBlock) error {
			return nil
		},
		SubmitBlindedBeaconBlockFunc: func(context.Context, *eth2api.VersionedSignedBlindedBeaconBlock) error {
			return nil
		},
		SubmitVoluntaryExitFunc: func(context.Context, *eth2p0.SignedVoluntaryExit) error {
			return nil
		},
		GenesisTimeFunc: func(ctx context.Context) (time.Time, error) {
			return httpMock.GenesisTime(ctx)
		},
		NodeSyncingFunc: func(ctx context.Context) (*eth2v1.SyncState, error) {
			return httpMock.NodeSyncing(ctx)
		},
		SubmitValidatorRegistrationsFunc: func(context.Context, []*eth2api.VersionedSignedValidatorRegistration) error {
			return nil
		},
		AggregateBeaconCommitteeSelectionsFunc: func(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
			return selections, nil
		},
		SubmitAggregateAttestationsFunc: func(context.Context, []*eth2p0.SignedAggregateAndProof) error {
			return nil
		},
		SlotsPerEpochFunc: func(ctx context.Context) (uint64, error) {
			return httpMock.SlotsPerEpoch(ctx)
		},
		SubmitProposalPreparationsFunc: func(context.Context, []*eth2v1.ProposalPreparation) error {
			return nil
		},
		SyncCommitteeDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
			return []*eth2v1.SyncCommitteeDuty{}, nil
		},
		AggregateSyncCommitteeSelectionsFunc: func(ctx context.Context, selections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
			return selections, nil
		},
		SubmitSyncCommitteeMessagesFunc: func(context.Context, []*altair.SyncCommitteeMessage) error {
			return nil
		},
		SubmitSyncCommitteeSubscriptionsFunc: func(context.Context, []*eth2v1.SyncCommitteeSubscription) error {
			return nil
		},
		SyncCommitteeContributionFunc: func(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
			contrib := testutil.RandomSyncCommitteeContribution()
			contrib.Slot = slot
			contrib.SubcommitteeIndex = subcommitteeIndex
			contrib.BeaconBlockRoot = beaconBlockRoot

			return contrib, nil
		},
		SubmitSyncCommitteeContributionsFunc: func(context.Context, []*altair.SignedContributionAndProof) error {
			return nil
		},
	}
}

func array32(slice []byte) [32]byte {
	var resp [32]byte
	copy(resp[:], slice)

	return resp
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
