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

// Code generated by genwrap.go. DO NOT EDIT.

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/errors"
)

// Client defines all go-eth2-client interfaces used in charon.
type Client interface {
	eth2client.Service

	eth2client.AttestationDataProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.BeaconBlockProposalProvider
	eth2client.BeaconBlockSubmitter
	eth2client.BeaconCommitteesProvider
	eth2client.BlindedBeaconBlockProposalProvider
	eth2client.BlindedBeaconBlockSubmitter
	eth2client.DepositContractProvider
	eth2client.DomainProvider
	eth2client.EventsProvider
	eth2client.ForkProvider
	eth2client.ForkScheduleProvider
	eth2client.GenesisProvider
	eth2client.GenesisTimeProvider
	eth2client.NodeSyncingProvider
	eth2client.NodeVersionProvider
	eth2client.ProposerDutiesProvider
	eth2client.SlotDurationProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.ValidatorRegistrationsSubmitter
	eth2client.ValidatorsProvider
	eth2client.VoluntaryExitSubmitter
}

// NodeVersion returns a free-text string with the node version.
// Note this endpoint is cached in go-eth2-client.
func (m multi) NodeVersion(ctx context.Context) (string, error) {
	const label = "node_version"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (string, error) {
			return cl.NodeVersion(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// SlotDuration provides the duration of a slot of the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) SlotDuration(ctx context.Context) (time.Duration, error) {
	const label = "slot_duration"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (time.Duration, error) {
			return cl.SlotDuration(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// SlotsPerEpoch provides the slots per epoch of the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) SlotsPerEpoch(ctx context.Context) (uint64, error) {
	const label = "slots_per_epoch"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (uint64, error) {
			return cl.SlotsPerEpoch(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// DepositContract provides details of the Ethereum 1 deposit contract for the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) DepositContract(ctx context.Context) (*apiv1.DepositContract, error) {
	const label = "deposit_contract"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*apiv1.DepositContract, error) {
			return cl.DepositContract(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// BeaconCommittees fetches all beacon committees for the epoch at the given state.
func (m multi) BeaconCommittees(ctx context.Context, stateID string) ([]*apiv1.BeaconCommittee, error) {
	const label = "beacon_committees"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*apiv1.BeaconCommittee, error) {
			return cl.BeaconCommittees(ctx, stateID)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// BeaconCommitteesAtEpoch fetches all beacon committees for the given epoch at the given state.
func (m multi) BeaconCommitteesAtEpoch(ctx context.Context, stateID string, epoch phase0.Epoch) ([]*apiv1.BeaconCommittee, error) {
	const label = "beacon_committees_at_epoch"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*apiv1.BeaconCommittee, error) {
			return cl.BeaconCommitteesAtEpoch(ctx, stateID, epoch)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// AttestationData fetches the attestation data for the given slot and committee index.
func (m multi) AttestationData(ctx context.Context, slot phase0.Slot, committeeIndex phase0.CommitteeIndex) (*phase0.AttestationData, error) {
	const label = "attestation_data"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*phase0.AttestationData, error) {
			return cl.AttestationData(ctx, slot, committeeIndex)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// SubmitAttestations submits attestations.
func (m multi) SubmitAttestations(ctx context.Context, attestations []*phase0.Attestation) error {
	const label = "submit_attestations"
	defer latency(label)()

	err := submit(ctx, m.clients,
		func(ctx context.Context, cl Client) error {
			return cl.SubmitAttestations(ctx, attestations)
		},
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return err
}

// AttesterDuties obtains attester duties.
// If validatorIndicess is nil it will return all duties for the given epoch.
func (m multi) AttesterDuties(ctx context.Context, epoch phase0.Epoch, validatorIndices []phase0.ValidatorIndex) ([]*apiv1.AttesterDuty, error) {
	const label = "attester_duties"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*apiv1.AttesterDuty, error) {
			return cl.AttesterDuties(ctx, epoch, validatorIndices)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// BeaconBlockProposal fetches a proposed beacon block for signing.
func (m multi) BeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*spec.VersionedBeaconBlock, error) {
	const label = "beacon_block_proposal"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*spec.VersionedBeaconBlock, error) {
			return cl.BeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// SubmitBeaconBlock submits a beacon block.
func (m multi) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	const label = "submit_beacon_block"
	defer latency(label)()

	err := submit(ctx, m.clients,
		func(ctx context.Context, cl Client) error {
			return cl.SubmitBeaconBlock(ctx, block)
		},
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return err
}

// BlindedBeaconBlockProposal fetches a blinded proposed beacon block for signing.
func (m multi) BlindedBeaconBlockProposal(ctx context.Context, slot phase0.Slot, randaoReveal phase0.BLSSignature, graffiti []byte) (*api.VersionedBlindedBeaconBlock, error) {
	const label = "blinded_beacon_block_proposal"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*api.VersionedBlindedBeaconBlock, error) {
			return cl.BlindedBeaconBlockProposal(ctx, slot, randaoReveal, graffiti)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// SubmitBlindedBeaconBlock submits a beacon block.
func (m multi) SubmitBlindedBeaconBlock(ctx context.Context, block *api.VersionedSignedBlindedBeaconBlock) error {
	const label = "submit_blinded_beacon_block"
	defer latency(label)()

	err := submit(ctx, m.clients,
		func(ctx context.Context, cl Client) error {
			return cl.SubmitBlindedBeaconBlock(ctx, block)
		},
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return err
}

// SubmitValidatorRegistrations submits a validator registration.
func (m multi) SubmitValidatorRegistrations(ctx context.Context, registrations []*api.VersionedSignedValidatorRegistration) error {
	const label = "submit_validator_registrations"
	defer latency(label)()

	err := submit(ctx, m.clients,
		func(ctx context.Context, cl Client) error {
			return cl.SubmitValidatorRegistrations(ctx, registrations)
		},
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return err
}

// Events feeds requested events with the given topics to the supplied handler.
func (m multi) Events(ctx context.Context, topics []string, handler eth2client.EventHandlerFunc) error {
	const label = "events"
	defer latency(label)()

	err := submit(ctx, m.clients,
		func(ctx context.Context, cl Client) error {
			return cl.Events(ctx, topics, handler)
		},
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return err
}

// Fork fetches fork information for the given state.
func (m multi) Fork(ctx context.Context, stateID string) (*phase0.Fork, error) {
	const label = "fork"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*phase0.Fork, error) {
			return cl.Fork(ctx, stateID)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// ForkSchedule provides details of past and future changes in the chain's fork version.
func (m multi) ForkSchedule(ctx context.Context) ([]*phase0.Fork, error) {
	const label = "fork_schedule"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*phase0.Fork, error) {
			return cl.ForkSchedule(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// Genesis fetches genesis information for the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) Genesis(ctx context.Context) (*apiv1.Genesis, error) {
	const label = "genesis"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*apiv1.Genesis, error) {
			return cl.Genesis(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// NodeSyncing provides the state of the node's synchronization with the chain.
func (m multi) NodeSyncing(ctx context.Context) (*apiv1.SyncState, error) {
	const label = "node_syncing"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (*apiv1.SyncState, error) {
			return cl.NodeSyncing(ctx)
		},
		isSyncStateOk,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// ProposerDuties obtains proposer duties for the given epoch.
// If validatorIndices is empty all duties are returned, otherwise only matching duties are returned.
func (m multi) ProposerDuties(ctx context.Context, epoch phase0.Epoch, validatorIndices []phase0.ValidatorIndex) ([]*apiv1.ProposerDuty, error) {
	const label = "proposer_duties"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) ([]*apiv1.ProposerDuty, error) {
			return cl.ProposerDuties(ctx, epoch, validatorIndices)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// Spec provides the spec information of the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) Spec(ctx context.Context) (map[string]interface{}, error) {
	const label = "spec"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (map[string]interface{}, error) {
			return cl.Spec(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// Validators provides the validators, with their balance and status, for a given state.
// stateID can be a slot number or state root, or one of the special values "genesis", "head", "justified" or "finalized".
// validatorIndices is a list of validator indices to restrict the returned values.  If no validators IDs are supplied no filter
// will be applied.
func (m multi) Validators(ctx context.Context, stateID string, validatorIndices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	const label = "validators"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
			return cl.Validators(ctx, stateID, validatorIndices)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// ValidatorsByPubKey provides the validators, with their balance and status, for a given state.
// stateID can be a slot number or state root, or one of the special values "genesis", "head", "justified" or "finalized".
// validatorPubKeys is a list of validator public keys to restrict the returned values.  If no validators public keys are
// supplied no filter will be applied.
func (m multi) ValidatorsByPubKey(ctx context.Context, stateID string, validatorPubKeys []phase0.BLSPubKey) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	const label = "validators_by_pub_key"
	defer latency(label)()

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
			return cl.ValidatorsByPubKey(ctx, stateID, validatorPubKeys)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// SubmitVoluntaryExit submits a voluntary exit.
func (m multi) SubmitVoluntaryExit(ctx context.Context, voluntaryExit *phase0.SignedVoluntaryExit) error {
	const label = "submit_voluntary_exit"
	defer latency(label)()

	err := submit(ctx, m.clients,
		func(ctx context.Context, cl Client) error {
			return cl.SubmitVoluntaryExit(ctx, voluntaryExit)
		},
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return err
}

// Domain provides a domain for a given domain type at a given epoch.
// Note this endpoint is cached in go-eth2-client.
func (m multi) Domain(ctx context.Context, domainType phase0.DomainType, epoch phase0.Epoch) (phase0.Domain, error) {
	const label = "domain"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (phase0.Domain, error) {
			return cl.Domain(ctx, domainType, epoch)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}

// GenesisTime provides the genesis time of the chain.
// Note this endpoint is cached in go-eth2-client.
func (m multi) GenesisTime(ctx context.Context) (time.Time, error) {
	const label = "genesis_time"

	res0, err := provide(ctx, m.clients,
		func(ctx context.Context, cl Client) (time.Time, error) {
			return cl.GenesisTime(ctx)
		},
		nil,
	)

	if err != nil {
		incError(label)
		err = errors.Wrap(err, "eth2wrap")
	}

	return res0, err
}
