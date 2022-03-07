// Package validatormock provides mock validator client functionality.
package validatormock

import (
	"context"
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
)

// Eth2AttProvider defines the eth2 beacon api providers required to perform attestations.
type Eth2AttProvider interface {
	eth2client.AttestationDataProvider
	eth2client.AttesterDutiesProvider
	eth2client.AttestationsSubmitter
	eth2client.SlotsPerEpochProvider
	eth2client.ValidatorsProvider
	eth2client.SpecProvider
	eth2client.DomainProvider
}

// SignFunc abstract signing done by the validator client.
type SignFunc func(context.Context, eth2p0.BLSPubKey, eth2p0.SigningData) (eth2p0.BLSSignature, error)

// Attest performs attestation duties for the provided slot and pubkeys (validators).
func Attest(ctx context.Context, eth2Cl Eth2AttProvider, signFunc SignFunc,
	slot eth2p0.Slot, pubkeys []eth2p0.BLSPubKey,
) error {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	domain, err := getDomain(ctx, eth2Cl, "DOMAIN_BEACON_ATTESTER", epoch)
	if err != nil {
		return err
	}

	valMap, err := eth2Cl.ValidatorsByPubKey(ctx, fmt.Sprint(slot), pubkeys)
	if err != nil {
		return err
	}

	var indexes []eth2p0.ValidatorIndex
	for index, val := range valMap {
		if !val.Status.IsActive() {
			continue
		}
		indexes = append(indexes, index)
	}

	duties, err := eth2Cl.AttesterDuties(ctx, epoch, indexes)
	if err != nil {
		return err
	}

	var atts []*eth2p0.Attestation
	for _, duty := range duties {
		if duty.Slot != slot {
			continue
		}

		data, err := eth2Cl.AttestationData(ctx, duty.Slot, duty.CommitteeIndex)
		if err != nil {
			return err
		}

		root, err := data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		sig, err := signFunc(ctx, duty.PubKey, eth2p0.SigningData{
			ObjectRoot: root,
			Domain:     domain,
		})
		if err != nil {
			return err
		}

		aggBits := bitfield.NewBitlist(duty.CommitteeLength)
		aggBits.SetBitAt(duty.ValidatorCommitteeIndex, true)

		atts = append(atts, &eth2p0.Attestation{
			AggregationBits: aggBits,
			Data:            data,
			Signature:       sig,
		})
	}

	return eth2Cl.SubmitAttestations(ctx, atts)
}

// eth2DomainProvider is the subset of eth2 beacon api provider required to get a signing domain.
type eth2DomainProvider interface {
	eth2client.SpecProvider
	eth2client.DomainProvider
}

// getDomain returns the beacon domain for the provided type.
// Types are defined in eth2 spec, see "specs/[phase0|altair]/beacon-chain.md#domain-types"
// at https://github.com/ethereum/consensus-specs.
func getDomain(ctx context.Context, eth2Cl eth2DomainProvider, typ string, epoch eth2p0.Epoch) (eth2p0.Domain, error) {
	spec, err := eth2Cl.Spec(ctx)
	if err != nil {
		return eth2p0.Domain{}, err
	}

	domainType, ok := spec[typ]
	if !ok {
		return eth2p0.Domain{}, errors.New("domain type not found")
	}

	domainTyped, ok := domainType.(eth2p0.DomainType)
	if !ok {
		return eth2p0.Domain{}, errors.New("invalid domain type")
	}

	return eth2Cl.Domain(ctx, domainTyped, epoch)
}
