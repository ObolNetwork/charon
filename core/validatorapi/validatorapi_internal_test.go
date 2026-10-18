// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"context"
	"fmt"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestMismatchKeysFunc(t *testing.T) {
	const shareIdx = 1

	// Create keys (just use normal keys, not split tbls)
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pubkey, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	corePubKey, err := core.PubKeyFromBytes(pubkey[:])
	require.NoError(t, err)

	eth2Pubkey := eth2p0.BLSPubKey(pubkey)

	t.Run("no mismatch", func(t *testing.T) {
		allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}} // Maps self to self since not tbls

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, false, defaultGasLimit)
		require.NoError(t, err)
		pk, err := vapi.getPubKeyFunc(eth2Pubkey)
		require.NoError(t, err)
		require.Equal(t, eth2Pubkey, pk)
	})

	t.Run("mismatch", func(t *testing.T) {
		// Create a mismatching key
		pkraw := testutil.RandomCorePubKey(t)
		pkb, err := pkraw.Bytes()
		require.NoError(t, err)

		pubshare := *(*tbls.PublicKey)(pkb)
		allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey, shareIdx + 1: pubshare}}

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, false, defaultGasLimit)
		require.NoError(t, err)

		resp, err := vapi.getPubKeyFunc(eth2p0.BLSPubKey(pubshare)) // Ask for a mismatching key
		require.Error(t, err)
		require.Equal(t, resp, eth2p0.BLSPubKey{})
		require.ErrorContains(t, err, "mismatching validator client key share index, Mth key share submitted to Nth charon peer")
	})

	t.Run("unknown public key", func(t *testing.T) {
		// Create a mismatching key
		pkb, err := testutil.RandomCorePubKey(t).Bytes()
		require.NoError(t, err)
		pk, err := tblsconv.PubkeyFromBytes(pkb)
		require.NoError(t, err)

		pubshare := eth2p0.BLSPubKey(pk)
		allPubSharesByKey := map[core.PubKey]map[int]tbls.PublicKey{corePubKey: {shareIdx: pubkey}}

		vapi, err := NewComponent(nil, allPubSharesByKey, shareIdx, nil, false, defaultGasLimit)
		require.NoError(t, err)

		_, err = vapi.getPubKeyFunc(pubshare) // Ask for a mismatching key
		require.Error(t, err)
		require.ErrorContains(t, err, "unknown public key")
	})
}

func TestWrapResponse(t *testing.T) {
	resp := wrapResponse(123)

	require.NotNil(t, resp)
	require.Equal(t, 123, resp.Data)
	require.Nil(t, resp.Metadata)
}

func TestWrapResponseWithMetadata(t *testing.T) {
	metadata := map[string]any{
		"foo": 123,
	}

	resp := wrapResponseWithMetadata(123, metadata)

	require.NotNil(t, resp)
	require.Equal(t, 123, resp.Data)
	require.Equal(t, metadata, resp.Metadata)
}

func TestWarnProposerPreferencesMismatch(t *testing.T) {
	ctx := context.Background()
	pubkey := testutil.RandomCorePubKey(t)

	addr := bellatrix.ExecutionAddress{0x01, 0x02, 0x03}
	feeRecipient := fmt.Sprintf("%#x", addr)

	const gasLimit = 30000000

	c := Component{
		feeRecipientFunc: func(core.PubKey) string { return feeRecipient },
		targetGasLimit:   gasLimit,
	}

	feeCount := func() float64 { return promtestutil.ToFloat64(proposerPrefMismatch.WithLabelValues("fee_recipient")) }
	gasCount := func() float64 { return promtestutil.ToFloat64(proposerPrefMismatch.WithLabelValues("gas_limit")) }

	fee0, gas0 := feeCount(), gasCount()

	// Matching fee recipient and gas limit: no increment.
	c.warnProposerPreferencesMismatch(ctx, pubkey, &gloas.ProposerPreferences{FeeRecipient: addr, TargetGasLimit: gasLimit})
	require.InDelta(t, fee0, feeCount(), 0)
	require.InDelta(t, gas0, gasCount(), 0)

	// Mismatching fee recipient and gas limit: both increment.
	otherAddr := bellatrix.ExecutionAddress{0xff}
	c.warnProposerPreferencesMismatch(ctx, pubkey, &gloas.ProposerPreferences{FeeRecipient: otherAddr, TargetGasLimit: gasLimit + 1})
	require.InDelta(t, fee0+1, feeCount(), 0)
	require.InDelta(t, gas0+1, gasCount(), 0)

	// Nil feeRecipientFunc: no panic, no increment.
	empty := Component{}
	empty.warnProposerPreferencesMismatch(ctx, pubkey, &gloas.ProposerPreferences{FeeRecipient: otherAddr})
}

func TestEPBSProposalFormGauge(t *testing.T) {
	ctx := t.Context()

	bmock, err := beaconmock.New(ctx)
	require.NoError(t, err)

	const slot = 123

	component, err := NewComponentInsecure(t, bmock, 1)
	require.NoError(t, err)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pk, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	pubkey, err := core.PubKeyFromBytes(pk[:])
	require.NoError(t, err)

	component.RegisterGetDutyDefinition(func(context.Context, core.Duty) (core.DutyDefinitionSet, error) {
		return core.DutyDefinitionSet{pubkey: nil}, nil
	})

	contents := testutil.RandomGloasBlockContents()
	contents.Block.Slot = slot

	component.RegisterAwaitVersionedProposal(func(context.Context, uint64) (core.VersionedProposal, error) {
		return core.VersionedProposal{
			Version: eth2spec.DataVersionGloas,
			EPBS:    &eth2api.VersionedEPBSProposal{Version: eth2spec.DataVersionGloas, Gloas: contents.Block},
		}, nil
	})
	component.RegisterAwaitPayloadContents(func(context.Context, uint64, eth2p0.Root) (*eth2api.VersionedEPBSProposal, error) {
		return &eth2api.VersionedEPBSProposal{
			Version:                  eth2spec.DataVersionGloas,
			ExecutionPayloadIncluded: true,
			GloasContents:            contents,
		}, nil
	})

	sig, err := tbls.Sign(secret, []byte("randao reveal"))
	require.NoError(t, err)

	propose := func(includePayload *bool) {
		_, err := component.EPBSProposal(ctx, &eth2api.EPBSProposalOpts{
			Slot:           slot,
			RandaoReveal:   eth2p0.BLSSignature(sig),
			IncludePayload: includePayload,
		})
		require.NoError(t, err)
	}

	form := func() int { return int(promtestutil.ToFloat64(proposalFormGauge)) }

	// Until a gloas proposal is requested the gauge is at its default, distinct from either form.
	proposalFormGauge.Set(proposalFormUnknown)
	require.Equal(t, proposalFormUnknown, form())

	stateful, stateless := false, true

	propose(&stateful)
	require.Equal(t, proposalFormStateful, form())

	propose(&stateless)
	require.Equal(t, proposalFormStateless, form())

	propose(nil)
	require.Equal(t, proposalFormStateful, form())
}

func TestWarnBuilderPreferencesMismatch(t *testing.T) {
	const (
		builderA = "builder-a.example.com"
		builderB = "builder-b.example.com"
		builderC = "builder-c.example.com"
		removed  = "removed.example.com"
	)

	ctx := t.Context()
	pubkey := testutil.RandomCorePubKey(t)
	c := Component{builderHosts: []string{builderA, builderB, builderC}}

	auths := func(hosts ...string) []*gloas.SignedBuilderRequestAuth {
		var resp []*gloas.SignedBuilderRequestAuth
		for _, host := range hosts {
			resp = append(resp, &gloas.SignedBuilderRequestAuth{Message: &gloas.BuilderRequestAuth{Data: []byte(host), Slot: 1}})
		}

		return resp
	}

	count := func(builder, reason string) float64 {
		return promtestutil.ToFloat64(builderPrefMismatch.WithLabelValues(builder, reason))
	}

	missingC, unknownRemoved := count(builderC, "missing"), count(removed, "unknown")

	// All configured builders: no increment.
	c.warnBuilderPreferencesMismatch(ctx, 1, pubkey, auths(builderA, builderB, builderC))
	require.InDelta(t, missingC, count(builderC, "missing"), 0)

	// A validator client that doesn't know builder C.
	c.warnBuilderPreferencesMismatch(ctx, 1, pubkey, auths(builderA, builderB))
	require.InDelta(t, missingC+1, count(builderC, "missing"), 0)

	// A validator client still signing for a removed builder, counted once per submission.
	c.warnBuilderPreferencesMismatch(ctx, 1, pubkey, auths(builderA, builderB, builderC, removed, removed))
	require.InDelta(t, missingC+1, count(builderC, "missing"), 0)
	require.InDelta(t, unknownRemoved+1, count(removed, "unknown"), 0)
}
