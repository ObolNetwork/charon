// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tracker

import (
	"context"
	"fmt"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestInclDelay(t *testing.T) {
	const (
		blockSlot     = 10
		slotsPerEpoch = 16
		slotDuration  = time.Second
		slot          = blockSlot + inclDelayLag
	)
	ctx := context.Background()
	clock := clockwork.NewFakeClockAt(time.Now().Truncate(time.Hour))

	bmock, err := beaconmock.New(
		beaconmock.WithSlotDuration(slotDuration),
		beaconmock.WithSlotsPerEpoch(slotsPerEpoch),
		beaconmock.WithGenesisTime(clock.Now()),
	)
	require.NoError(t, err)

	clock.Advance(blockSlot * slotDuration)

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

	inclDelay, err := NewInclusionDelay(ctx, bmock, dutiesFunc)
	require.NoError(t, err)
	inclDelay.clock = clock

	done := make(chan struct{})
	inclDelay.instrumentFunc = func(delays []int64) {
		require.EqualValues(t, expect, delays)
		close(done)
	}

	for _, att := range atts {
		inclDelay.Broadcasted(int64(att.Att.Data.Slot), core.NewAttestation(att.Att))
	}

	inclDelay.logMappingFunc = func(ctx context.Context, slot int64, bcastDelay time.Duration, inclDelay int64) {
		require.Equal(t, time.Duration(blockSlot-slot)*slotDuration, bcastDelay)
	}

	err = inclDelay.Instrument(ctx, core.Slot{
		Slot: 1,
	})
	require.NoError(t, err)

	err = inclDelay.Instrument(ctx, core.Slot{
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
