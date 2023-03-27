// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package beaconmock

import (
	"context"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	fuzz "github.com/google/gofuzz"
)

// WithBeaconMockFuzzer configures the beaconmock to return random responses for the all the functions consumed by charon.
func WithBeaconMockFuzzer() Option {
	return func(mock *Mock) {
		mock.AttesterDutiesFunc = func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
			var duties []*eth2v1.AttesterDuty
			fuzz.New().Fuzz(&duties)

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

		mock.BeaconBlockProposalFunc = func(context.Context, eth2p0.Slot, eth2p0.BLSSignature, []byte) (*eth2spec.VersionedBeaconBlock, error) {
			var block *eth2spec.VersionedBeaconBlock
			fuzz.New().Fuzz(&block)

			return block, nil
		}

		mock.AggregateAttestationFunc = func(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error) {
			var att *eth2p0.Attestation
			fuzz.New().Fuzz(&att)

			return att, nil
		}

		mock.ValidatorsFunc = func(context.Context, string, []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			var vals map[eth2p0.ValidatorIndex]*eth2v1.Validator
			fuzz.New().Fuzz(&vals)

			return vals, nil
		}

		mock.BlindedBeaconBlockProposalFunc = func(context.Context, eth2p0.Slot, eth2p0.BLSSignature, []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
			var block *eth2api.VersionedBlindedBeaconBlock
			fuzz.New().Fuzz(&block)

			return block, nil
		}

		mock.NodePeerCountFunc = func(context.Context) (int, error) {
			var count int
			fuzz.New().Fuzz(&count)

			return count, nil
		}

		mock.ValidatorsByPubKeyFunc = func(_ context.Context, _ string, pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
			var vals map[eth2p0.ValidatorIndex]*eth2v1.Validator
			fuzz.New().Fuzz(&vals)

			return vals, nil
		}

		mock.SlotsPerEpochFunc = func(context.Context) (uint64, error) {
			var slots uint64
			fuzz.New().Fuzz(&slots)

			return slots, nil
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
	}
}
