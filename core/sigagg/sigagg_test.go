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

package sigagg_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/sigagg"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestSigAgg_DutyAttester(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	att := testutil.RandomAttestation()

	// Sign the attestation directly (spec domain not required for test)
	msg, err := att.MarshalSSZ()
	require.NoError(t, err)

	// Generate private shares
	tss, secrets, err := tbls.GenerateTSS(threshold, peers, rand.Reader)
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   []*bls_sig.PartialSignature
	)
	for _, secret := range secrets {
		psig, err := tbls.PartialSign(secret, msg)
		require.NoError(t, err)

		att.Signature = tblsconv.SigToETH2(tblsconv.SigFromPartial(psig))

		parsig, err := core.EncodeAttestationParSignedData(att, int(psig.Identifier))
		require.NoError(t, err)

		psigs = append(psigs, psig)
		parsigs = append(parsigs, parsig)
	}

	// Create expected aggregated signature
	aggSig, err := tbls.Aggregate(psigs)
	require.NoError(t, err)
	expect := tblsconv.SigToCore(aggSig)

	agg := sigagg.New(threshold)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.AggSignedData) error {
		require.Equal(t, expect, aggData.Signature)
		sig, err := tblsconv.SigFromCore(aggData.Signature)
		require.NoError(t, err)

		ok, err := tbls.Verify(tss.PublicKey(), msg, sig)
		require.NoError(t, err)
		require.True(t, ok)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyAttester}, "", parsigs)
	require.NoError(t, err)
}

func TestSigAgg_DutyRandao(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	msg := []byte("RANDAO reveal")

	// Generate private shares
	tss, secrets, err := tbls.GenerateTSS(threshold, peers, rand.Reader)
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   []*bls_sig.PartialSignature
	)
	for _, secret := range secrets {
		psig, err := tbls.PartialSign(secret, msg)
		require.NoError(t, err)

		sig := tblsconv.SigToETH2(tblsconv.SigFromPartial(psig))

		parsig := core.EncodeRandaoParSignedData(sig, int(psig.Identifier))

		psigs = append(psigs, psig)
		parsigs = append(parsigs, parsig)
	}

	// Create expected aggregated signature
	aggSig, err := tbls.Aggregate(psigs)
	require.NoError(t, err)
	expect := tblsconv.SigToCore(aggSig)

	agg := sigagg.New(threshold)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.AggSignedData) error {
		require.Equal(t, expect, aggData.Signature)
		sig, err := tblsconv.SigFromCore(aggData.Signature)
		require.NoError(t, err)

		ok, err := tbls.Verify(tss.PublicKey(), msg, sig)
		require.NoError(t, err)
		require.True(t, ok)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyRandao}, "", parsigs)
	require.NoError(t, err)
}

func TestSigAgg_DutyExit(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	// Generate private shares
	tss, secrets, err := tbls.GenerateTSS(threshold, peers, rand.Reader)
	require.NoError(t, err)

	uve := testutil.RandomExit()

	msg, err := uve.MarshalSSZ()
	require.NoError(t, err)

	// Create partial signatures (in two formats)
	var (
		parsigs []core.ParSignedData
		psigs   []*bls_sig.PartialSignature
	)
	for _, secret := range secrets {
		psig, err := tbls.PartialSign(secret, msg)
		require.NoError(t, err)

		sig := tblsconv.SigToETH2(tblsconv.SigFromPartial(psig))
		ve := &eth2p0.SignedVoluntaryExit{
			Message:   uve,
			Signature: sig,
		}

		data, err := json.Marshal(ve)
		require.NoError(t, err)

		parsig := core.ParSignedData{
			Data:      data,
			Signature: core.SigFromETH2(ve.Signature),
			ShareIdx:  int(psig.Identifier),
		}

		psigs = append(psigs, psig)
		parsigs = append(parsigs, parsig)
	}

	aggSig, err := tbls.Aggregate(psigs)
	require.NoError(t, err)
	expect := tblsconv.SigToCore(aggSig)

	agg := sigagg.New(threshold)

	// Assert output
	agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.AggSignedData) error {
		require.Equal(t, expect, aggData.Signature)
		sig, err := tblsconv.SigFromCore(aggData.Signature)
		require.NoError(t, err)

		ok, err := tbls.Verify(tss.PublicKey(), msg, sig)
		require.NoError(t, err)
		require.True(t, ok)

		return nil
	})

	// Run aggregation
	err = agg.Aggregate(ctx, core.Duty{Type: core.DutyExit}, "", parsigs)
	require.NoError(t, err)
}

func TestSigAgg_DutyProposer(t *testing.T) {
	ctx := context.Background()

	const (
		threshold = 3
		peers     = 4
	)

	// Generate private shares
	tss, secrets, err := tbls.GenerateTSS(threshold, peers, rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name  string
		block *spec.VersionedSignedBeaconBlock
	}{
		{
			name: "phase0 block",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionPhase0,
				Phase0: &eth2p0.SignedBeaconBlock{
					Message:   testutil.RandomPhase0BeaconBlock(),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "altair block",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionAltair,
				Altair: &altair.SignedBeaconBlock{
					Message:   testutil.RandomAltairBeaconBlock(t),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
		{
			name: "bellatrix block",
			block: &spec.VersionedSignedBeaconBlock{
				Version: spec.DataVersionBellatrix,
				Bellatrix: &bellatrix.SignedBeaconBlock{
					Message:   testutil.RandomBellatrixBeaconBlock(t),
					Signature: testutil.RandomEth2Signature(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ignoring Domain for this test
			msg, err := test.block.Root()
			require.NoError(t, err)

			// Create partial signatures (in two formats)
			var (
				parsigs []core.ParSignedData
				psigs   []*bls_sig.PartialSignature
			)
			for _, secret := range secrets {
				psig, err := tbls.PartialSign(secret, msg[:])
				require.NoError(t, err)

				setSigToSignedBlock(test.block, tblsconv.SigToETH2(tblsconv.SigFromPartial(psig)))

				parsig, err := core.EncodeBlockParSignedData(test.block, int(psig.Identifier))
				require.NoError(t, err)

				psigs = append(psigs, psig)
				parsigs = append(parsigs, parsig)
			}

			// Create expected aggregated signature
			aggSig, err := tbls.Aggregate(psigs)
			require.NoError(t, err)
			expect := tblsconv.SigToCore(aggSig)

			agg := sigagg.New(threshold)

			// Assert output
			agg.Subscribe(func(_ context.Context, _ core.Duty, _ core.PubKey, aggData core.AggSignedData) error {
				require.Equal(t, expect, aggData.Signature)
				sig, err := tblsconv.SigFromCore(aggData.Signature)
				require.NoError(t, err)

				ok, err := tbls.Verify(tss.PublicKey(), msg[:], sig)
				require.NoError(t, err)
				require.True(t, ok)

				return nil
			})

			// Run aggregation
			err = agg.Aggregate(ctx, core.Duty{Type: core.DutyProposer}, "", parsigs)
			require.NoError(t, err)
		})
	}
}

func setSigToSignedBlock(block *spec.VersionedSignedBeaconBlock, sig eth2p0.BLSSignature) {
	switch block.Version {
	case spec.DataVersionPhase0:
		block.Phase0.Signature = sig
	case spec.DataVersionAltair:
		block.Altair.Signature = sig
	case spec.DataVersionBellatrix:
		block.Bellatrix.Signature = sig
	}
}
