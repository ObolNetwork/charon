// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
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
			if len(pubkeys) == 0 {
				for idx, val := range set {
					resp[idx] = cloneValidator(val)
				}

				return resp, nil
			}

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

		mock.ValidatorsFunc = func(ctx context.Context, opts *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
			if len(opts.Indices) == 0 {
				for idx, val := range set {
					resp[idx] = cloneValidator(val)
				}

				return resp, nil
			}

			for _, index := range opts.Indices {
				val, ok := set[index]
				if ok {
					resp[index] = cloneValidator(val)
				} else {
					log.Debug(ctx, "Index not found")
				}
			}

			return resp, nil
		}

		activeVals := make(eth2wrap.ActiveValidators)
		for _, val := range set {
			if val.Status.IsActive() {
				activeVals[val.Index] = val.Validator.PublicKey
			}
		}

		mock.ActiveValidatorsFunc = func(ctx context.Context) (eth2wrap.ActiveValidators, error) {
			return activeVals, nil
		}

		type getValidatorsResponse struct {
			Data []*eth2v1.Validator `json:"data"`
		}

		var resp getValidatorsResponse
		for _, v := range set {
			resp.Data = append(resp.Data, v)
		}

		respJSON, err := json.Marshal(resp)
		if err != nil {
			//nolint:forbidigo // formatting an error in panic, it's okay
			panic(fmt.Errorf("could not marshal pre-generated mock validator response, %w", err))
		}

		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/beacon/states/head/validators",
			Key:      "",
			Value:    string(respJSON),
		})
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
			opts := &eth2api.ValidatorsOpts{
				State:   "",
				Indices: indices,
			}
			eth2Resp, err := mock.Validators(ctx, opts)
			if err != nil {
				return nil, err
			}
			vals := eth2Resp.Data

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
					CommitteeIndex:          eth2p0.CommitteeIndex(index),
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
		mock.ProposerDutiesFunc = func(ctx context.Context, epoch eth2p0.Epoch, _ []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			vals, err := mock.ActiveValidators(ctx)
			if err != nil {
				return nil, err
			}

			valIdxs := vals.Indices()

			sort.Slice(valIdxs, func(i, j int) bool {
				return valIdxs[i] < valIdxs[j]
			})

			slotsPerEpoch, err := mock.SlotsPerEpoch(ctx)
			if err != nil {
				return nil, err
			}

			slotsAssigned := make(map[int]bool)

			var resp []*eth2v1.ProposerDuty
			for i, valIdx := range valIdxs {
				offset := (i * factor) % int(slotsPerEpoch)
				if slotsAssigned[offset] {
					break
				}

				slotsAssigned[offset] = true

				resp = append(resp, &eth2v1.ProposerDuty{
					PubKey:         vals[valIdx],
					Slot:           eth2p0.Slot(slotsPerEpoch*uint64(epoch) + uint64(offset)),
					ValidatorIndex: valIdx,
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

			opts := &eth2api.ValidatorsOpts{
				State:   "",
				Indices: indices,
			}
			eth2Resp, err := mock.Validators(ctx, opts)
			if err != nil {
				return nil, err
			}
			vals := eth2Resp.Data

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

// WithSyncCommitteeSize configures the http mock with the provided sync committee size.
func WithSyncCommitteeSize(size int) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/config/spec",
			Key:      "SYNC_COMMITTEE_SIZE",
			Value:    fmt.Sprint(size),
		})
	}
}

// WithSyncCommitteeSubnetCount configures the http mock with the provided sync committee subnet count.
func WithSyncCommitteeSubnetCount(count int) Option {
	return func(mock *Mock) {
		mock.overrides = append(mock.overrides, staticOverride{
			Endpoint: "/eth/v1/config/spec",
			Key:      "SYNC_COMMITTEE_SUBNET_COUNT",
			Value:    fmt.Sprint(count),
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
		ProposalFunc: func(ctx context.Context, opts *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error) {
			block := &eth2api.VersionedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: testutil.RandomCapellaBeaconBlock(),
			}
			block.Capella.Slot = opts.Slot
			block.Capella.Body.RANDAOReveal = opts.RandaoReveal
			block.Capella.Body.Graffiti = opts.Graffiti

			return block, nil
		},
		BlindedProposalFunc: func(ctx context.Context, opts *eth2api.BlindedProposalOpts) (*eth2api.VersionedBlindedProposal, error) {
			block := &eth2api.VersionedBlindedProposal{
				Version: eth2spec.DataVersionCapella,
				Capella: testutil.RandomCapellaBlindedBeaconBlock(),
			}
			block.Capella.Slot = opts.Slot
			block.Capella.Body.RANDAOReveal = opts.RandaoReveal
			block.Capella.Body.Graffiti = opts.Graffiti

			return block, nil
		},
		SignedBeaconBlockFunc: func(_ context.Context, blockID string) (*eth2spec.VersionedSignedBeaconBlock, error) {
			return testutil.RandomCapellaVersionedSignedBeaconBlock(), nil // Note the slot is probably wrong.
		},
		ProposerDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			return []*eth2v1.ProposerDuty{}, nil
		},
		AttesterDutiesFunc: func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			return []*eth2v1.AttesterDuty{}, nil
		},
		BlockAttestationsFunc: func(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
			return []*eth2p0.Attestation{}, nil
		},
		NodePeerCountFunc: func(ctx context.Context) (int, error) {
			return 80, nil
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
		ActiveValidatorsFunc: func(ctx context.Context) (eth2wrap.ActiveValidators, error) {
			return nil, nil
		},
		ValidatorsFunc: func(context.Context, *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			return nil, nil
		},
		ValidatorsByPubKeyFunc: func(context.Context, string, []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			return nil, nil
		},
		SubmitAttestationsFunc: func(context.Context, []*eth2p0.Attestation) error {
			return nil
		},
		SubmitProposalFunc: func(context.Context, *eth2api.VersionedSignedProposal) error {
			return nil
		},
		SubmitBlindedProposalFunc: func(context.Context, *eth2api.VersionedSignedBlindedProposal) error {
			return nil
		},
		SubmitVoluntaryExitFunc: func(context.Context, *eth2p0.SignedVoluntaryExit) error {
			return nil
		},
		GenesisTimeFunc: func(ctx context.Context) (time.Time, error) {
			return httpMock.GenesisTime(ctx)
		},
		NodeSyncingFunc: func(ctx context.Context, opts *eth2api.NodeSyncingOpts) (*eth2v1.SyncState, error) {
			resp, err := httpMock.NodeSyncing(ctx, opts)
			if err != nil {
				return nil, err
			}

			return resp.Data, nil
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
			aggBits := bitfield.NewBitvector128()
			aggBits.SetBitAt(uint64(slot%128), true)

			return &altair.SyncCommitteeContribution{
				Slot:              slot,
				SubcommitteeIndex: subcommitteeIndex,
				BeaconBlockRoot:   beaconBlockRoot,
				AggregationBits:   aggBits,
				Signature:         testutil.RandomEth2SignatureWithSeed(int64(slot)),
			}, nil
		},
		SubmitSyncCommitteeContributionsFunc: func(context.Context, []*altair.SignedContributionAndProof) error {
			return nil
		},
		ForkScheduleFunc: func(ctx context.Context, opts *eth2api.ForkScheduleOpts) ([]*eth2p0.Fork, error) {
			eth2Resp, err := httpMock.ForkSchedule(ctx, opts)
			if err != nil {
				return nil, err
			}

			return eth2Resp.Data, nil
		},
		ProposerConfigFunc: func(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
			return nil, nil
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
