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
	"testing"

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
