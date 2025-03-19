// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"encoding/hex"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

func TestBackwardsCompatability(t *testing.T) {
	require.EqualValues(t, 0, core.DutyUnknown)
	require.EqualValues(t, 1, core.DutyProposer)
	require.EqualValues(t, 2, core.DutyAttester)
	require.EqualValues(t, 3, core.DutySignature)
	require.EqualValues(t, 4, core.DutyExit)
	require.EqualValues(t, 5, core.DutyBuilderProposer)
	require.EqualValues(t, 6, core.DutyBuilderRegistration)
	require.EqualValues(t, 7, core.DutyRandao)
	require.EqualValues(t, 8, core.DutyPrepareAggregator)
	require.EqualValues(t, 9, core.DutyAggregator)
	require.EqualValues(t, 10, core.DutySyncMessage)
	require.EqualValues(t, 11, core.DutyPrepareSyncContribution)
	require.EqualValues(t, 12, core.DutySyncContribution)
	require.EqualValues(t, 13, core.DutyInfoSync)
	// Add more types here.

	const sentinel = core.DutyType(14)
	for i := core.DutyUnknown; i <= sentinel; i++ {
		if i == core.DutyUnknown {
			require.False(t, i.Valid())
			require.Equal(t, "unknown", i.String())
		} else if i == sentinel {
			require.False(t, i.Valid())
			require.Equal(t, "", i.String())
		} else {
			require.True(t, i.Valid())
			require.NotEmpty(t, i.String())
		}
	}
}

func TestWithDutySpanCtx(t *testing.T) {
	ctx := context.Background()
	stop, err := tracer.Init(tracer.WithStdOut(io.Discard))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stop(ctx))
	}()

	_, span1 := core.StartDutyTrace(ctx, core.Duty{}, "span1")
	_, span2 := core.StartDutyTrace(ctx, core.Duty{}, "span2")

	require.Equal(t, "7d0b160d5b04eac85dd1eaf0585c5b82", span1.SpanContext().TraceID().String())
	require.Equal(t, span1.SpanContext().TraceID(), span2.SpanContext().TraceID())
	require.NotEqual(t, span1.SpanContext().SpanID(), span2.SpanContext().SpanID())

	require.True(t, span1.SpanContext().IsValid())
	require.True(t, span1.SpanContext().IsSampled())

	require.True(t, span2.SpanContext().IsValid())
	require.True(t, span2.SpanContext().IsSampled())
}

func TestAllDutyTypes(t *testing.T) {
	adt := core.AllDutyTypes()

	require.Len(t, adt, 13)
	for i, dt := range adt {
		require.Equal(t, i, slices.Index(adt, dt))
	}
}

func TestNewBuilderRegistrationDuty(t *testing.T) {
	d := core.NewBuilderRegistrationDuty(1)

	require.EqualValues(t, core.DutyBuilderRegistration, d.Type)
	require.Equal(t, "1/builder_registration", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewSignatureDuty(t *testing.T) {
	d := core.NewSignatureDuty(1)

	require.EqualValues(t, core.DutySignature, d.Type)
	require.Equal(t, "1/signature", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewPrepareAggregatorDuty(t *testing.T) {
	d := core.NewPrepareAggregatorDuty(1)

	require.EqualValues(t, core.DutyPrepareAggregator, d.Type)
	require.Equal(t, "1/prepare_aggregator", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewAggregatorDuty(t *testing.T) {
	d := core.NewAggregatorDuty(1)

	require.EqualValues(t, core.DutyAggregator, d.Type)
	require.Equal(t, "1/aggregator", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewSyncMessageDuty(t *testing.T) {
	d := core.NewSyncMessageDuty(1)

	require.EqualValues(t, core.DutySyncMessage, d.Type)
	require.Equal(t, "1/sync_message", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewPrepareSyncContributionDuty(t *testing.T) {
	d := core.NewPrepareSyncContributionDuty(1)

	require.EqualValues(t, core.DutyPrepareSyncContribution, d.Type)
	require.Equal(t, "1/prepare_sync_contribution", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewSyncContributionDuty(t *testing.T) {
	d := core.NewSyncContributionDuty(1)

	require.EqualValues(t, core.DutySyncContribution, d.Type)
	require.Equal(t, "1/sync_contribution", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestNewInfoSyncDuty(t *testing.T) {
	d := core.NewInfoSyncDuty(1)

	require.EqualValues(t, core.DutyInfoSync, d.Type)
	require.Equal(t, "1/info_sync", d.String())
	require.EqualValues(t, 1, d.Slot)
}

func TestPubKeyFrom48Bytes(t *testing.T) {
	k := testutil.RandomEth2PubKey(t)
	pk := core.PubKeyFrom48Bytes(k)

	k2, err := pk.ToETH2()
	require.NoError(t, err)
	require.Equal(t, k, k2)
}

func TestPubKey(t *testing.T) {
	k := "0xc70a999b6754717c0886a1c744168f1ff5457b342c4e3abbc5a139ade2a0d20247c98531fe51ae271d570badd704ca31"
	pk := core.PubKey(k)

	require.Equal(t, "c70_ca3", pk.String())

	b, err := hex.DecodeString(k[2:])
	require.NoError(t, err)
	b2, err := pk.Bytes()
	require.NoError(t, err)
	require.Equal(t, b, b2)

	e2k, err := pk.ToETH2()
	require.NoError(t, err)
	require.Equal(t, k, e2k.String())
}

func TestSlot(t *testing.T) {
	s := core.Slot{
		Slot:          123,
		Time:          time.Unix(100, 100),
		SlotDuration:  4 * time.Second,
		SlotsPerEpoch: 32,
	}

	require.Equal(t, uint64(0x7b), s.Slot)
	require.EqualValues(t, 3, s.Epoch())
	require.False(t, s.LastInEpoch())
	require.False(t, s.FirstInEpoch())
	require.Equal(t, core.Slot{
		Slot:          124,
		Time:          time.Unix(104, 100),
		SlotDuration:  4 * time.Second,
		SlotsPerEpoch: 32,
	}, s.Next())
}
