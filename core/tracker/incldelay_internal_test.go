// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestInclDelay(t *testing.T) {
	const (
		blockSlot     = 10
		slotsPerEpoch = 16
		slot          = blockSlot + inclDelayLag
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	expect := []int64{1, 2, 4, 8}

	var atts []att
	for i, e := range expect {
		atts = append(atts, makeAtt(blockSlot-e, int64(i), int64(i)))
	}

	bmock.BlockAttestationsFunc = func(ctx context.Context, stateID string) ([]*eth2p0.Attestation, error) {
		require.Equal(t, fmt.Sprint(blockSlot), stateID)
		var res []*eth2p0.Attestation
		for _, att := range atts {
			res = append(res, att.Att)
		}

		return res, nil
	}

	dutiesFunc := func(_ context.Context, duty core.Duty) (core.DutyDefinitionSet, error) {
		res := make(core.DutyDefinitionSet)
		for i, att := range atts {
			if int64(att.Att.Data.Slot) != duty.Slot {
				continue
			}
			res[core.PubKey(fmt.Sprint(i))] = core.NewAttesterDefinition(att.Duty)
		}

		return res, nil
	}

	done := make(chan struct{})
	fn := newInclDelayFunc(bmock, dutiesFunc, func(delays []int64) {
		require.EqualValues(t, expect, delays)
		close(done)
	})

	err = fn(context.Background(), core.Slot{
		Slot: 1,
	})
	require.NoError(t, err)

	err = fn(context.Background(), core.Slot{
		Slot:          slot,
		SlotsPerEpoch: slotsPerEpoch,
	})
	require.NoError(t, err)

	<-done
}

type att struct {
	Att  *eth2p0.Attestation
	Duty *eth2v1.AttesterDuty
}

func makeAtt(slot int64, commIdx int64, valCommIdx int64) att {
	aggBits := bitfield.NewBitlist(1024)
	aggBits.SetBitAt(uint64(valCommIdx), true)

	return att{
		Att: &eth2p0.Attestation{
			AggregationBits: aggBits,
			Data: &eth2p0.AttestationData{
				Slot:  eth2p0.Slot(slot),
				Index: eth2p0.CommitteeIndex(commIdx),
			},
		},
		Duty: &eth2v1.AttesterDuty{
			CommitteeIndex:          eth2p0.CommitteeIndex(commIdx),
			ValidatorCommitteeIndex: uint64(valCommIdx),
		},
	}
}
