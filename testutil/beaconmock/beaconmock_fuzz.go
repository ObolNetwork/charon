// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock

import (
	"context"
	"sync"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	fuzz "github.com/google/gofuzz"
)

// WithBeaconMockFuzzer configures the beaconmock to return random responses for the all the functions consumed by charon.
func WithBeaconMockFuzzer() Option {
	var (
		valsMu     sync.Mutex
		validators map[eth2p0.ValidatorIndex]*eth2v1.Validator
	)

	setValidators := func(pubkeys []eth2p0.BLSPubKey) {
		valsMu.Lock()
		defer valsMu.Unlock()

		if len(validators) != 0 {
			return
		}

		validators = make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
		for i, pubkey := range pubkeys {
			vIdx := eth2p0.ValidatorIndex(i)

			validators[vIdx] = &eth2v1.Validator{
				Balance: eth2p0.Gwei(31300000000),
				Index:   vIdx,
				Status:  eth2v1.ValidatorStateActiveOngoing,
				Validator: &eth2p0.Validator{
					WithdrawalCredentials: []byte("12345678901234567890123456789012"),
					EffectiveBalance:      eth2p0.Gwei(31300000000),
					PublicKey:             pubkey,
					ExitEpoch:             18446744073709551615,
					WithdrawableEpoch:     18446744073709551615,
				},
			}
		}
	}

	getValidators := func() map[eth2p0.ValidatorIndex]*eth2v1.Validator {
		valsMu.Lock()
		defer valsMu.Unlock()

		return validators
	}

	return func(mock *Mock) {
		mock.AttesterDutiesFunc = func(_ context.Context, epoch eth2p0.Epoch, indices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			var duties []*eth2v1.AttesterDuty
			f := fuzz.New().Funcs(
				func(duties *[]*eth2v1.AttesterDuty, c fuzz.Continue) {
					if c.RandBool() {
						fuzz.New().Fuzz(duties)

						return
					}

					// Return expected attester duties
					vals := getValidators()
					if vals == nil {
						return
					}
					var resp []*eth2v1.AttesterDuty
					for _, vIdx := range indices {
						var duty eth2v1.AttesterDuty
						c.Fuzz(&duty)

						val, ok := vals[vIdx]
						if !ok {
							continue
						}

						duty.PubKey = val.Validator.PublicKey
						duty.ValidatorIndex = vIdx
						duty.Slot = eth2p0.Slot(int(epoch*16) + c.Intn(16))
						resp = append(resp, &duty)
					}

					*duties = resp
				},
			)
			f.Fuzz(&duties)

			return duties, nil
		}

		mock.ProposerDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
			var duties []*eth2v1.ProposerDuty
			fuzz.New().Fuzz(&duties)

			return duties, nil
		}

		mock.AttestationDataFunc = func(context.Context, eth2p0.Slot, eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
			var attData *eth2p0.AttestationData
			fuzz.New().Fuzz(&attData)

			return attData, nil
		}

		mock.ProposalFunc = func(context.Context, *eth2api.ProposalOpts) (*eth2api.VersionedProposal, error) {
			var block *eth2api.VersionedProposal
			fuzz.New().Fuzz(&block)

			return block, nil
		}

		mock.AggregateAttestationFunc = func(context.Context, eth2p0.Slot, eth2p0.Root) (*eth2p0.Attestation, error) {
			var att *eth2p0.Attestation
			fuzz.New().Fuzz(&att)

			return att, nil
		}

		mock.ValidatorsFunc = func(context.Context, *eth2api.ValidatorsOpts) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			var vals map[eth2p0.ValidatorIndex]*eth2v1.Validator
			fuzz.New().Fuzz(&vals)

			return vals, nil
		}

		mock.NodePeerCountFunc = func(context.Context) (int, error) {
			var count int
			fuzz.New().Fuzz(&count)

			return count, nil
		}

		mock.ValidatorsByPubKeyFunc = func(_ context.Context, _ string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			f := fuzz.New().Funcs(
				func(vals *map[eth2p0.ValidatorIndex]*eth2v1.Validator, c fuzz.Continue) {
					if c.RandBool() {
						fuzz.New().Funcs(
							func(state *eth2v1.ValidatorState, c fuzz.Continue) {
								*state = eth2v1.ValidatorState(c.Intn(10))
							},
						).Fuzz(vals)

						return
					}

					// Return validators with expected keys 50% of the time.
					setValidators(pubkeys)
					*vals = getValidators()
				},
			)

			var vals map[eth2p0.ValidatorIndex]*eth2v1.Validator
			f.Fuzz(&vals)

			return vals, nil
		}

		mock.SyncCommitteeDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
			var duties []*eth2v1.SyncCommitteeDuty
			fuzz.New().Fuzz(&duties)

			return duties, nil
		}

		mock.SyncCommitteeContributionFunc = func(context.Context, eth2p0.Slot, uint64, eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
			var contribution *altair.SyncCommitteeContribution
			fuzz.New().Fuzz(&contribution)

			return contribution, nil
		}

		mock.BlockAttestationsFunc = func(context.Context, string) ([]*eth2p0.Attestation, error) {
			var atts []*eth2p0.Attestation
			fuzz.New().Fuzz(&atts)

			return atts, nil
		}

		mock.BlockAttestationsV2Func = func(context.Context, string) ([]*eth2spec.VersionedAttestation, error) {
			var atts []*eth2spec.VersionedAttestation
			fuzz.New().Fuzz(&atts)

			return atts, nil
		}
	}
}
