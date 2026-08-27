// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util/signing"
)

// PayloadAttest performs the payload timeliness committee duty for the provided slot.
// It is stateless and does nothing if no active validator is a payload timeliness
// committee member for the slot.
func PayloadAttest(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc, slot eth2p0.Slot) error {
	valMap, err := eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	_, slotsPerEpoch, err := eth2wrap.FetchSlotsConfig(ctx, eth2Cl)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	var indexes []eth2p0.ValidatorIndex
	for index := range valMap {
		indexes = append(indexes, index)
	}

	eth2Resp, err := eth2Cl.PTCDuties(ctx, &eth2api.PTCDutiesOpts{
		Epoch:   epoch,
		Indices: indexes,
	})
	if err != nil {
		return err
	}

	var duties []*eth2v1.PTCDuty

	for _, duty := range eth2Resp.Data {
		if duty.Slot == slot {
			duties = append(duties, duty)
		}
	}

	if len(duties) == 0 {
		return nil
	}

	// The payload attestation data is per-slot, all committee members attest to the same data.
	dataResp, err := eth2Cl.PayloadAttestationData(ctx, &eth2api.PayloadAttestationDataOpts{Slot: slot})
	if errors.Is(err, eth2client.ErrNoPayloadAttestationData) {
		// The beacon node has seen no block for the slot, so there is nothing to attest.
		return nil
	} else if err != nil {
		return err
	}

	versioned := dataResp.Data
	if versioned == nil {
		return errors.New("versioned payload attestation data is nil")
	}

	var data *gloas.PayloadAttestationData

	switch versioned.Version {
	case eth2spec.DataVersionGloas:
		data = versioned.Gloas
	default:
		return errors.New("unknown payload attestation data version")
	}

	if data == nil {
		return errors.New("no gloas payload attestation data")
	}

	root, err := data.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "hash payload attestation data")
	}

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainPTCAttester, epoch, root)
	if err != nil {
		return err
	}

	var msgs []*eth2spec.VersionedPayloadAttestationMessage

	for _, duty := range duties {
		sig, err := signFunc(duty.PubKey, sigData[:])
		if err != nil {
			return err
		}

		msgs = append(msgs, &eth2spec.VersionedPayloadAttestationMessage{
			Version: versioned.Version,
			Gloas: &gloas.PayloadAttestationMessage{
				ValidatorIndex: duty.ValidatorIndex,
				Data:           data,
				Signature:      sig,
			},
		})
	}

	return eth2Cl.SubmitPayloadAttestationMessages(ctx, &eth2api.SubmitPayloadAttestationMessagesOpts{Messages: msgs})
}
