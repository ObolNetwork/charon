// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
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

func TestVerifyDutyDefinition(t *testing.T) {
	pubkey := testutil.RandomCorePubKey(t)
	eth2Pk, err := pubkey.ToETH2()
	require.NoError(t, err)

	otherPubkey := testutil.RandomCorePubKey(t)

	tests := []struct {
		name           string
		dutyDefinition core.DutyDefinition
		slot           eth2p0.Slot
		rawPubkey      core.PubKey
		errCheck       func(t *testing.T, err error)
	}{
		{
			"sync committee has wrong public key",
			core.SyncCommitteeDefinition{
				SyncCommitteeDuty: eth2v1.SyncCommitteeDuty{
					PubKey: eth2Pk,
				},
			},
			eth2p0.Slot(42),
			otherPubkey,
			func(t *testing.T, err error) {
				t.Helper()
				require.ErrorContains(t, err, "duty definition does not match expected public key")
			},
		},
		{
			"sync committee has correct public key",
			core.SyncCommitteeDefinition{
				SyncCommitteeDuty: eth2v1.SyncCommitteeDuty{
					PubKey: eth2Pk,
				},
			},
			eth2p0.Slot(42),
			pubkey,
			func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			"attester definition has wrong pubkey",
			core.AttesterDefinition{
				AttesterDuty: eth2v1.AttesterDuty{
					PubKey: eth2Pk,
				},
			},
			eth2p0.Slot(0),
			otherPubkey,
			func(t *testing.T, err error) {
				t.Helper()
				require.ErrorContains(t, err, "duty definition does not match expected public key")
			},
		},
		{
			"attester definition has wrong slot",
			core.AttesterDefinition{
				AttesterDuty: eth2v1.AttesterDuty{
					PubKey: eth2Pk,
					Slot:   eth2p0.Slot(42),
				},
			},
			eth2p0.Slot(0),
			pubkey,
			func(t *testing.T, err error) {
				t.Helper()
				require.ErrorContains(t, err, "mismatched slot")
			},
		},
		{
			"attester definition is correct",
			core.AttesterDefinition{
				AttesterDuty: eth2v1.AttesterDuty{
					PubKey: eth2Pk,
					Slot:   eth2p0.Slot(42),
				},
			},
			eth2p0.Slot(42),
			pubkey,
			func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			"bogus definition",
			bogusDefinition{},
			eth2p0.Slot(42),
			pubkey,
			func(t *testing.T, err error) {
				t.Helper()
				require.ErrorContains(t, err, "unknown duty definition interface type")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.errCheck(t, core.VerifyDutyDefinition(tt.dutyDefinition, tt.slot, tt.rawPubkey))
		})
	}
}

type bogusDefinition struct{}

func (bogusDefinition) Clone() (core.DutyDefinition, error) {
	return bogusDefinition{}, nil
}

func (bogusDefinition) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // interface method, never actually used
	return json.Marshal(bogusDefinition{})
}
